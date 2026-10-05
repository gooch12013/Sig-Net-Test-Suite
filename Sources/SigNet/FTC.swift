/// ANSI E1.37-4-2026 (RDM File Transfer Control) constants, CRC and the INITIATE declarations. Names follow the
/// standard's terms (FTC_RS_STATUS_OK → `FTC.RS.statusOK`); section numbers cite the standard.
public enum FTC {
    /// FTCVersion 1.00 (§11.3).
    public static let version: UInt16 = 0x0100

    /// [RDM] command classes and response types used here.
    public static let getCommand: UInt8 = 0x20, setCommand: UInt8 = 0x30
    public static let ack: Int32 = 0, ackTimer: Int32 = 1, nack: Int32 = 2, ackOverflow: Int32 = 3

    /// Parameter IDs (Table A-2).
    public enum PID {
        public static let initiate: UInt16 = 0x1200, transferUpload: UInt16 = 0x1201, commit: UInt16 = 0x1202
        public static let cancel: UInt16 = 0x1203, fileList: UInt16 = 0x1204, transferDownload: UInt16 = 0x1205
    }

    /// General defines (Table A-1).
    public enum DEF {
        public static let noFileIDOffered: UInt8 = 0x00, multipleFileID: UInt8 = 0xFF
        public static let noSessionIDOffered: UInt8 = 0x00, sessionIDAll: UInt8 = 0xFF
    }

    /// ResponseStatus (Table A-3).
    public enum RS {
        public static let statusOK: UInt8 = 0x00, initOKUL: UInt8 = 0x01, initOKDL: UInt8 = 0x02, statusInProgress: UInt8 = 0x03
        public static let transferComplete: UInt8 = 0x04, modalError: UInt8 = 0x05, switchToBootloader: UInt8 = 0x06
        public static let sessionIDMismatch: UInt8 = 0x07, unsupportedFileID: UInt8 = 0x08, fileNotCompatible: UInt8 = 0x09
        public static let fileNotAvailable: UInt8 = 0x0A, packetCRCError: UInt8 = 0x0B, fileCRCError: UInt8 = 0x0C
        public static let validationError: UInt8 = 0x0D, e137LockActive: UInt8 = 0x10, otherLockActive: UInt8 = 0x11
        public static let writeProtect: UInt8 = 0x12, invalidDirection: UInt8 = 0x13, offsetError: UInt8 = 0x14
        public static let fileSizeError: UInt8 = 0x15, ftcVersionError: UInt8 = 0x16, fileCRCNotSupported: UInt8 = 0x17
        public static let downloadKeyRequired: UInt8 = 0x18, downloadFileCRC: UInt8 = 0x19, downloadCommandError: UInt8 = 0x1A
        public static let unresolvedError: UInt8 = 0x7F
    }

    /// TransferFlags / CommitFlags (Table A-5).
    public enum TF { public static let testMode: UInt16 = 0x0001, download: UInt16 = 0x0002 }

    /// Transfer Download commands (Table A-6).
    public enum TD { public static let getNextPacket: UInt8 = 0x01, resendLastPacket: UInt8 = 0x02, getFileCRC: UInt8 = 0x03 }

    /// Responder Capabilities bits (Table A-7).
    public enum Cap {
        public static let acceptUpload: UInt32 = 0x1, acceptDownload: UInt32 = 0x2, processFileCRC: UInt32 = 0x4
        public static let processPacketCRC: UInt32 = 0x8, generateFileCRC: UInt32 = 0x10, generatePacketCRC: UInt32 = 0x20
        public static let downloadKey: UInt32 = 0x40, bootloaderSwitch: UInt32 = 0x80, nscNoInterleave: UInt32 = 0x100
        public static let nscIgnore: UInt32 = 0x200, functionalLimit: UInt32 = 0x400, e137Lock: UInt32 = 0x1000
        public static let otherLock: UInt32 = 0x2000, acceptBroadcasts: UInt32 = 0x8000, failMayBrick: UInt32 = 0x10000
        public static let alternateErrorRecovery: UInt32 = 0x20000, testModeSupported: UInt32 = 0x800000
    }

    /// Limits: TransferBlock Size (§8.6.1), and the longest Initial Delay / IN_PROGRESS / bootloader / Commit Time (§8.6.2, §12.1.4).
    public static let maxUploadBlock: UInt8 = 224, maxDownloadBlock: UInt8 = 223, maxDelay: UInt32 = 0x0040_0000

    /// FileCRC / PacketCRC (§10, Appendix D): CRC-16/MODBUS, as the standard prints it (register low byte first),
    /// so sent big-endian it goes out as Appendix D shows (FileCRC 0xB3DD → B3 DD).
    public static func crc<C: Collection>(_ bytes: C) -> UInt16 where C.Element == UInt8 {
        var r: UInt16 = 0xFFFF
        for b in bytes {
            r ^= UInt16(b)
            for _ in 0..<8 { r = r & 1 == 1 ? r >> 1 ^ 0xA001 : r >> 1 }
        }
        return r.byteSwapped
    }

    /// GET/SET:FTC_INITIATE response (§13.1.2, §13.1.4, §13.1.5), 38 bytes as the field table adds up.
    public struct Declarations {
        public var status: UInt8 = 0, data: UInt32 = 0, session: UInt8 = 0, fileID: UInt8 = 0, version: UInt16 = 0
        public var fileSize: UInt32 = 0, capabilities: UInt32 = 0, offset: UInt32 = 0, blockSize: UInt8 = 0
        public var initialDelay: UInt32 = 0, interPacketDelay: UInt16 = 0, accumulatedByteCount: UInt32 = 0
        public var accumulatedByteDelay: UInt16 = 0, validationDelay: UInt16 = 0, maxInterPacketDelay: UInt16 = 0

        public init() {}
        public init?(_ pd: [UInt8]) {
            guard pd.count >= 38 else { return nil }
            status = pd[0]; data = mgrU32(pd[1...]); session = pd[5]; fileID = pd[6]; version = mgrU16(pd[7...])
            fileSize = mgrU32(pd[9...]); capabilities = mgrU32(pd[13...]); offset = mgrU32(pd[17...]); blockSize = pd[21]
            initialDelay = mgrU32(pd[22...]); interPacketDelay = mgrU16(pd[26...]); accumulatedByteCount = mgrU32(pd[28...])
            accumulatedByteDelay = mgrU16(pd[32...]); validationDelay = mgrU16(pd[34...]); maxInterPacketDelay = mgrU16(pd[36...])
        }
    }
}
