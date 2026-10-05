extension FirmwareUpdate {
    /// Placeholder until the Responder emulator lands: the CRC and SET:FTC_INITIATE bytes against Appendix D.
    static func selfTestFTC() -> Bool {
        let file: [UInt8] = [0xEC, 0xEF, 0x7B, 0xF0, 0x00, 0x00, 0x00, 0x03, 0x04, 0x6E, 0xD8, 0xCF, 0x05, 0xF0, 0xE0, 0xCF]
        let initiate: [UInt8] = [0x7D, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10] + file + [0xB3, 0xDD, 0xCA, 0xB0]
        return FTC.crc(Array("123456789".utf8)) == 0x374B // CRC-16/MODBUS check value 0x4B37, low byte first
            && FTC.crc(file) == 0xB3DD
            && initiatePD(session: 0x7D, fileID: 1, flags: 0, size: 16, head: file, fileCRC: FTC.crc(file)) == initiate
    }
}
