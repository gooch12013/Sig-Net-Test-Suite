import Foundation
#if canImport(Darwin)
import Darwin
#elseif os(Windows)
import WinSDK
#elseif canImport(Glibc)
import Glibc
#endif

#if os(Windows)
private typealias Handle = SOCKET
private let invalidHandle = ~SOCKET(0) // INVALID_SOCKET (a cast macro Swift cannot import)
private let ipproto = Int32(IPPROTO_IP.rawValue), udp = Int32(IPPROTO_UDP.rawValue), dgram = SOCK_DGRAM
private func lastError() -> String { "WSA error \(WSAGetLastError())" }
private func closeHandle(_ h: Handle) { closesocket(h) }
private let wsaStarted: Bool = { var d = WSADATA(); return WSAStartup(0x0202, &d) == 0 }()
#else
private typealias Handle = Int32
private let invalidHandle: Int32 = -1
#if canImport(Darwin)
private let ipproto = IPPROTO_IP, udp = IPPROTO_UDP, dgram = SOCK_DGRAM
#else
private let ipproto = Int32(IPPROTO_IP), udp = Int32(IPPROTO_UDP), dgram = Int32(SOCK_DGRAM.rawValue)
#endif
private func lastError() -> String { String(cString: strerror(errno)) }
private func closeHandle(_ h: Handle) { _ = close(h) }
#endif

private func ipv4(_ s: String) -> in_addr? {
    var a = in_addr()
    return inet_pton(AF_INET, s, &a) == 1 ? a : nil
}

private func text(_ a: in_addr) -> String {
    var a = a
    var buf = [CChar](repeating: 0, count: 16)
    return inet_ntop(AF_INET, &a, &buf, 16) == nil ? "?" : String(cString: buf)
}

private func sockaddrIn(_ a: in_addr, _ port: UInt16) -> sockaddr_in {
    var s = sockaddr_in()
    #if canImport(Darwin)
    s.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    #endif
    s.sin_family = .init(AF_INET)
    s.sin_port = port.bigEndian
    s.sin_addr = a
    return s
}

/// IPv4 UDP socket for Sig-Net (port 5683): address/port reuse so every part of the app (and other
/// apps) can share the port, multicast loopback on so they hear each other, TTL 32, multicast out of
/// `interface` (an IPv4 address; empty = OS default). Receive runs on its own thread and delivers
/// (bytes, source IPv4) on `queue`; nothing is delivered after `close()` returns on that queue.
public final class UDPSocket {
    public static let port: UInt16 = 5683
    private let fd: Handle
    private let nic: in_addr
    private let lock = NSLock()
    private var closed = false, started = false

    public init(interface: String = "", port: UInt16 = UDPSocket.port, ttl: UInt8 = 32) throws {
        #if os(Windows)
        guard wsaStarted else { throw SigNetError("WSAStartup failed") }
        #endif
        if interface.isEmpty { nic = in_addr() } // INADDR_ANY
        else if let a = ipv4(interface) { nic = a }
        else { throw SigNetError("Interface must be an IPv4 address") }
        fd = socket(AF_INET, dgram, udp)
        guard fd != invalidHandle else { throw SigNetError("socket: \(lastError())") }
        _ = option(SOL_SOCKET, SO_REUSEADDR, Int32(1))
        #if !os(Windows)
        _ = option(SOL_SOCKET, SO_REUSEPORT, Int32(1))
        #endif
        #if canImport(Darwin)
        _ = option(ipproto, IP_MULTICAST_TTL, ttl)
        _ = option(ipproto, IP_MULTICAST_LOOP, UInt8(1))
        #else
        _ = option(ipproto, IP_MULTICAST_TTL, Int32(ttl))
        _ = option(ipproto, IP_MULTICAST_LOOP, Int32(1))
        #endif
        // A blocked recvfrom wakes at least this often to notice close().
        #if os(Windows)
        _ = option(SOL_SOCKET, SO_RCVTIMEO, DWORD(200))
        #else
        _ = option(SOL_SOCKET, SO_RCVTIMEO, timeval(tv_sec: 0, tv_usec: 200_000))
        #endif
        if !interface.isEmpty { _ = option(ipproto, IP_MULTICAST_IF, nic) }
        var addr = sockaddrIn(in_addr(), port)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, .init(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else {
            let why = lastError()
            closeHandle(fd)
            throw SigNetError("bind \(port): \(why)")
        }
    }

    deinit { close() }

    private func option<T>(_ level: Int32, _ name: Int32, _ value: T) -> Bool {
        var v = value
        return withUnsafeBytes(of: &v) { b in
            #if os(Windows)
            setsockopt(fd, level, name, b.baseAddress!.assumingMemoryBound(to: CChar.self), Int32(b.count)) == 0
            #else
            setsockopt(fd, level, name, b.baseAddress, socklen_t(b.count)) == 0
            #endif
        }
    }

    private func membership(_ group: String, _ op: Int32) throws {
        guard let g = ipv4(group) else { throw SigNetError("bad group \(group)") }
        guard option(ipproto, op, ip_mreq(imr_multiaddr: g, imr_interface: nic)) else {
            throw SigNetError("\(op == IP_ADD_MEMBERSHIP ? "join" : "leave") \(group): \(lastError())")
        }
    }

    /// Joins `group` on the chosen interface.
    public func join(_ group: String) throws { try membership(group, IP_ADD_MEMBERSHIP) }
    public func leave(_ group: String) throws { try membership(group, IP_DROP_MEMBERSHIP) }

    /// One datagram to a multicast group or unicast host.
    public func send(_ bytes: [UInt8], to host: String, port: UInt16 = UDPSocket.port) throws {
        guard let a = ipv4(host) else { throw SigNetError("sendto \(host): not an IPv4 address") }
        var addr = sockaddrIn(a, port)
        let n = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bytes.withUnsafeBufferPointer { b in
                    #if os(Windows)
                    Int(sendto(fd, UnsafeRawPointer(b.baseAddress)?.assumingMemoryBound(to: CChar.self), Int32(b.count), 0, sa, Int32(MemoryLayout<sockaddr_in>.size)))
                    #else
                    sendto(fd, b.baseAddress, b.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                    #endif
                }
            }
        }
        if n < 0 { throw SigNetError("sendto \(host): \(lastError())") }
    }

    /// Starts the receive thread. Call once, and call `close()` when done: the thread holds the socket.
    public func receive(on queue: DispatchQueue, _ handler: @escaping (_ bytes: [UInt8], _ from: String) -> Void) {
        lock.lock()
        started = true
        lock.unlock()
        Thread.detachNewThread { [self] in
            var buf = [UInt8](repeating: 0, count: 2048)
            while !isClosed {
                var from = sockaddr_in()
                #if os(Windows)
                var len = Int32(MemoryLayout<sockaddr_in>.size)
                #else
                var len = socklen_t(MemoryLayout<sockaddr_in>.size)
                #endif
                let n = withUnsafeMutablePointer(to: &from) { p in
                    p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        buf.withUnsafeMutableBufferPointer { b in
                            #if os(Windows)
                            Int(recvfrom(fd, UnsafeMutableRawPointer(b.baseAddress)?.assumingMemoryBound(to: CChar.self), Int32(b.count), 0, sa, &len))
                            #else
                            recvfrom(fd, b.baseAddress, b.count, 0, sa, &len)
                            #endif
                        }
                    }
                }
                guard n > 0 else { continue } // timeout, or an error we can't act on
                let bytes = Array(buf[0..<n]), ip = text(from.sin_addr)
                queue.async { [weak self] in
                    guard let self, !self.isClosed else { return }
                    handler(bytes, ip)
                }
            }
            closeHandle(fd)
        }
    }

    private var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }

    /// Stops delivery at once; the receive thread closes the socket within 200 ms.
    public func close() {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        if !started { closeHandle(fd) }
    }

    /// Non-loopback IPv4 interfaces, for an interface picker.
    public static func interfaces() -> [(name: String, ip: String)] {
        var out: [(String, String)] = []
        #if os(Windows)
        // ponytail: addresses of the host name, no adapter names; GetAdaptersAddresses if the picker needs them.
        guard wsaStarted else { return [] }
        var name = [CChar](repeating: 0, count: 256)
        guard gethostname(&name, 256) == 0 else { return [] }
        var hints = addrinfo()
        hints.ai_family = AF_INET
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(name, nil, &hints, &res) == 0 else { return [] }
        defer { freeaddrinfo(res) }
        var p = res
        while let i = p?.pointee {
            defer { p = i.ai_next }
            guard let sa = i.ai_addr else { continue }
            let ip = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { text($0.pointee.sin_addr) }
            if !ip.hasPrefix("127."), !out.contains(where: { $0.1 == ip }) { out.append((ip, ip)) }
        }
        #else
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return [] }
        defer { freeifaddrs(head) }
        var p = head
        while let i = p?.pointee {
            defer { p = i.ifa_next }
            guard let sa = i.ifa_addr, sa.pointee.sa_family == .init(AF_INET) else { continue }
            let ip = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { text($0.pointee.sin_addr) }
            if !ip.hasPrefix("127.") { out.append((String(cString: i.ifa_name), ip)) }
        }
        #endif
        return out
    }
}
