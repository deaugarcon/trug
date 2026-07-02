import Foundation
import Climobiledevice
import Cplist
import CWrappers

/// The ported `mb2_handle_*` IO bodies from `idevicebackup2.c`. Each handler ends by sending a
/// status response on ALL paths (the device blocks until it gets one — Odb C4), confines every
/// device-supplied path to `backupRoot` before any filesystem op (Odb 3b/C5), and converts IO
/// errors into status codes rather than throwing mid-conversation. Only `receiveFiles` reports
/// a count (and observes cancellation per byte-block — Odb C6).
final class MB2Handlers {
    private let client: mobilebackup2_client_t
    private let backupRoot: URL
    private let fm = FileManager.default

    init(client: mobilebackup2_client_t, backupRoot: URL) {
        self.client = client
        self.backupRoot = backupRoot
    }

    // MARK: - status response (C4)

    /// Sends a DLMessageStatusResponse. `status2` is an optional plist payload (caller owns freeing).
    private func sendStatus(_ code: Int32, _ message: String?, _ payload: plist_t? = nil) {
        let empty = payload == nil ? plist_new_dict() : nil
        defer { if let empty { plist_free(empty) } }
        _ = mobilebackup2_send_status_response(client, Int32(code), message, payload ?? empty)
    }

    // MARK: - message decoding

    /// Converts the incoming DL* message plist to a Foundation array (DL* messages are arrays).
    private func messageArray(_ message: plist_t?) -> [Any]? {
        guard let message else { return nil }
        return PlistBridge.foundationObject(from: message) as? [Any]
    }

    /// C2 terminal-signal parse, delegating to the unit-tested pure parser.
    func processMessageOutcome(_ message: plist_t?) -> MB2ProcessMessage {
        guard let arr = messageArray(message), arr.count >= 2,
              let dict = arr[1] as? [String: Any] else {
            return .failure(code: -1, description: nil)
        }
        return MB2ProcessMessage.outcome(fromMessageDict: dict)
    }

    /// Diagnostics: a readable dump of a DL* message's Foundation form, for surfacing exactly what
    /// the device sent before a terminal throw. Returns "<unparseable>" if the bridge yields nil.
    func describe(_ message: plist_t?) -> String {
        guard let obj = message.flatMap({ PlistBridge.foundationObject(from: $0) }) else {
            return "<unparseable or nil message>"
        }
        return String(describing: obj)
    }

    // MARK: - receive files (device → host); the core transfer

    /// Ports `mb2_handle_receive_files`. Writes received files into the staging clone, each at a
    /// path confined to `backupRoot`. Checks cancellation per block. Returns files written.
    /// `deadline` bounds a mid-file device wedge (G1): progress is recorded per received chunk and
    /// a stalled read past the no-progress window throws `deviceDisconnectedMidBackup`.
    ///
    /// G2 (intentional): the only throws here are terminal aborts — `backupCancelled` (user
    /// cancelled) and `deviceDisconnectedMidBackup` (dead transport / mid-file stall). These
    /// deliberately skip the per-message status response: there is no live conversation to keep
    /// alive, the whole backup is being torn down. Recoverable per-file IO errors do NOT throw —
    /// they set `errcode`/`break` and still send a status response below (honoring C4).
    func receiveFiles(message: plist_t?, deadline: MB2Deadline) throws -> Int {
        var fileCount = 0
        var errcode: Int32 = 0
        var errdesc: String? = nil

        while true {
            if Task.isCancelled { throw BackupError.backupCancelled }

            // Device sends a pair of names: the device-display name, then the host backup path.
            guard let _ = try receiveFilename() else { break }       // dname (display); end on zero-length
            guard let fname = try receiveFilename() else { break }   // fname (host-relative backup path)

            // 3b/C5: confine the host path before any write.
            guard let dest = MB2PathGuard.confinedPath(backupRoot: backupRoot, deviceRelativePath: fname) else {
                // Refuse a path that escapes the staging root; keep the conversation alive.
                errcode = MB2.deviceError(forErrno: EPERM)
                errdesc = "path escapes backup root"
                break
            }

            // 4-byte big-endian length + 1-byte code framing.
            guard let firstLen = try receiveUInt32BE() else { break }
            var nlen = firstLen
            var code = try receiveByte()

            try fm.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
            // In-place overwrite into the staging clone (the C does remove_file + fopen "wb").
            try? fm.removeItem(at: dest)
            guard let handle = createAndOpen(dest) else {
                errcode = MB2.deviceError(forErrno: errno)
                errdesc = "could not open \(dest.lastPathComponent) for writing"
                break
            }
            defer { try? handle.close() }

            while code == MB2Handlers.codeFileData {
                let blockSize = Int(nlen) - 1
                var done = 0
                while done < blockSize {
                    if Task.isCancelled { throw BackupError.backupCancelled }   // C6: per-block cancel
                    let want = min(blockSize - done, 32768)
                    let chunk = try receiveRaw(count: want)
                    if chunk.isEmpty {
                        // G1: an empty read mid-block means the device stalled. If the stall
                        // exceeds the no-progress window, fail with a diagnostic rather than
                        // spinning on empty reads; otherwise end this block and move on.
                        try deadline.checkAlive()
                        break
                    }
                    try handle.write(contentsOf: chunk)
                    done += chunk.count
                    deadline.recordProgress()
                }
                guard let nextLen = try receiveUInt32BE() else { nlen = 0; break }
                nlen = nextLen
                if nlen > 0 { code = try receiveByte() } else { break }
            }
            fileCount += 1

            // CODE_ERROR_REMOTE after data carries a device-side error string; drain it.
            if code == MB2Handlers.codeErrorRemote, nlen > 1 {
                _ = try receiveRaw(count: Int(nlen) - 1)
            }
            if nlen == 0 { break }
        }

        let payload = plist_new_dict()
        defer { plist_free(payload) }
        sendStatus(errcode, errdesc, payload)
        return fileCount
    }

    // MARK: - send files (host → device); rarely used in a pure backup

    /// Ports `mb2_handle_send_files`. For each requested path, sends it (or skips missing),
    /// then a terminating zero dword and a status response.
    func sendFiles(message: plist_t?) throws {
        var hadError = false
        if let arr = messageArray(message), arr.count >= 2, let files = arr[1] as? [Any] {
            for case let path as String in files {
                if Task.isCancelled { throw BackupError.backupCancelled }
                if !sendOneFile(deviceRelativePath: path) { hadError = true; break }
            }
        }
        // Terminating zero dword (no more files).
        var zero: UInt32 = 0
        withUnsafeBytes(of: &zero) { _ = sendRaw($0) }
        if hadError {
            sendStatus(-13, "Multi status")
        } else {
            sendStatus(0, nil)
        }
    }

    // MARK: - directory listing / creation

    /// Ports `mb2_handle_list_directory` — builds a plist dict of the directory contents.
    func listDirectory(message: plist_t?) {
        guard let arr = messageArray(message), arr.count >= 2, let rel = arr[1] as? String,
              let dir = MB2PathGuard.confinedPath(backupRoot: backupRoot, deviceRelativePath: rel) else {
            sendStatus(0, nil, plist_new_dict())
            return
        }
        let dirlist = plist_new_dict()
        defer { plist_free(dirlist) }
        if let entries = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey, .isDirectoryKey, .contentModificationDateKey]) {
            for entry in entries {
                let values = try? entry.resourceValues(forKeys: [.fileSizeKey, .isDirectoryKey, .contentModificationDateKey])
                let isDir = values?.isDirectory ?? false
                let fdict = plist_new_dict()
                let ftype = isDir ? "DLFileTypeDirectory" : "DLFileTypeRegular"
                plist_dict_set_item(fdict, "DLFileType", plist_new_string(ftype))
                plist_dict_set_item(fdict, "DLFileSize", plist_new_uint(UInt64(values?.fileSize ?? 0)))
                plist_dict_set_item(dirlist, entry.lastPathComponent, fdict)
            }
        }
        sendStatus(0, nil, dirlist)
    }

    /// Ports `mb2_handle_make_directory` — mkdir -p, mapping errno to a device error.
    func makeDirectory(message: plist_t?) {
        guard let arr = messageArray(message), arr.count >= 2, let rel = arr[1] as? String,
              let dir = MB2PathGuard.confinedPath(backupRoot: backupRoot, deviceRelativePath: rel) else {
            sendStatus(MB2.deviceError(forErrno: EPERM), "path escapes backup root")
            return
        }
        do {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
            sendStatus(0, nil)
        } catch {
            sendStatus(MB2.deviceError(forError: error), error.localizedDescription)
        }
    }

    // MARK: - move / remove / copy (inline in the C main loop)

    /// Ports the `DLMessageMove*` case: rename each key→value, both confined to backupRoot.
    func moveItems(message: plist_t?) {
        var errcode: Int32 = 0
        var errdesc: String? = nil
        if let arr = messageArray(message), arr.count >= 2, let moves = arr[1] as? [String: Any] {
            for (key, value) in moves {
                guard let to = value as? String,
                      let oldURL = MB2PathGuard.confinedPath(backupRoot: backupRoot, deviceRelativePath: key),
                      let newURL = MB2PathGuard.confinedPath(backupRoot: backupRoot, deviceRelativePath: to) else {
                    errcode = MB2.deviceError(forErrno: EPERM); errdesc = "path escapes backup root"; break
                }
                try? fm.removeItem(at: newURL)
                do {
                    try fm.moveItem(at: oldURL, to: newURL)
                } catch {
                    errcode = MB2.deviceError(forError: error)
                    errdesc = error.localizedDescription
                    break
                }
            }
        }
        sendStatus(errcode, errdesc, plist_new_dict())
    }

    /// Ports the `DLMessageRemove*` case: remove each listed path, confined to backupRoot.
    func removeItems(message: plist_t?) {
        var errcode: Int32 = 0
        var errdesc: String? = nil
        if let arr = messageArray(message), arr.count >= 2, let removes = arr[1] as? [Any] {
            for case let rel as String in removes {
                guard let target = MB2PathGuard.confinedPath(backupRoot: backupRoot, deviceRelativePath: rel) else {
                    errcode = MB2.deviceError(forErrno: EPERM); errdesc = "path escapes backup root"; continue
                }
                if fm.fileExists(atPath: target.path) {
                    do { try fm.removeItem(at: target) }
                    catch {
                        errcode = MB2.deviceError(forError: error)
                        errdesc = error.localizedDescription
                    }
                }
            }
        }
        sendStatus(errcode, errdesc, plist_new_dict())
    }

    /// Ports the `DLMessageCopyItem` case: copy src→dst, both confined to backupRoot.
    func copyItem(message: plist_t?) {
        var errcode: Int32 = 0
        var errdesc: String? = nil
        if let arr = messageArray(message), arr.count >= 3,
           let src = arr[1] as? String, let dst = arr[2] as? String {
            if let from = MB2PathGuard.confinedPath(backupRoot: backupRoot, deviceRelativePath: src),
               let to = MB2PathGuard.confinedPath(backupRoot: backupRoot, deviceRelativePath: dst),
               fm.fileExists(atPath: from.path) {
                do { try fm.copyItem(at: from, to: to) }
                catch {
                    errcode = MB2.deviceError(forError: error)
                    errdesc = error.localizedDescription
                }
            } else {
                errcode = MB2.deviceError(forErrno: EPERM); errdesc = "path escapes backup root"
            }
        }
        sendStatus(errcode, errdesc, plist_new_dict())
    }

    // MARK: - disk space

    /// Ports the `DLMessageGetFreeDiskSpace` case: report free bytes on the backup volume.
    func freeDiskSpace() {
        let free = (try? fm.attributesOfFileSystem(forPath: backupRoot.path)[.systemFreeSize] as? NSNumber)?.uint64Value ?? 0
        let item = plist_new_uint(free)
        defer { plist_free(item) }
        sendStatus(0, nil, item)
    }

    /// Ports the `DLMessagePurgeDiskSpace` case: unsupported, ack with an error status.
    func purgeDiskSpace() {
        sendStatus(-1, "Operation not supported", plist_new_dict())
    }

    // MARK: - raw transfer primitives (bridge mobilebackup2_send_raw / receive_raw)

    private static let codeSuccess: UInt8 = 0x00
    private static let codeErrorLocal: UInt8 = 0x06
    private static let codeErrorRemote: UInt8 = 0x0b
    private static let codeFileData: UInt8 = 0x0c

    @discardableResult
    private func sendRaw(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard let base = bytes.baseAddress else { return true }
        var sent: UInt32 = 0
        let err = base.withMemoryRebound(to: CChar.self, capacity: bytes.count) {
            mobilebackup2_send_raw(client, $0, UInt32(bytes.count), &sent)
        }
        return err == MOBILEBACKUP2_E_SUCCESS && sent == UInt32(bytes.count)
    }

    /// Receives exactly `count` bytes (best-effort; returns what arrived, like the C).
    private func receiveRaw(count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var buffer = [UInt8](repeating: 0, count: count)
        var received: UInt32 = 0
        let err = buffer.withUnsafeMutableBytes { raw -> mobilebackup2_error_t in
            raw.baseAddress!.withMemoryRebound(to: CChar.self, capacity: count) {
                mobilebackup2_receive_raw(client, $0, UInt32(count), &received)
            }
        }
        if err == MOBILEBACKUP2_E_MUX_ERROR {
            throw BackupError.deviceDisconnectedMidBackup(lastResultCode: err.rawValue)
        }
        return Data(buffer.prefix(Int(received)))
    }

    /// Reads a 4-byte big-endian length. Returns nil on a clean zero-length end-of-stream marker.
    private func receiveUInt32BE() throws -> UInt32? {
        let data = try receiveRaw(count: 4)
        guard data.count == 4 else { return nil }
        let value = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        return UInt32(bigEndian: value)
    }

    private func receiveByte() throws -> UInt8 {
        let data = try receiveRaw(count: 1)
        return data.first ?? 0
    }

    /// Ports `mb2_receive_filename`: 4-byte length then that many name bytes. nil = no more files.
    private func receiveFilename() throws -> String? {
        guard let nlen = try receiveUInt32BE() else { return nil }
        if nlen == 0 { return nil }           // zero length = no more files
        if nlen > 4096 { return nil }         // matches the C's sanity cap
        let data = try receiveRaw(count: Int(nlen))
        guard data.count == Int(nlen) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: - file helpers

    private func createAndOpen(_ url: URL) -> FileHandle? {
        fm.createFile(atPath: url.path, contents: nil)
        return try? FileHandle(forWritingTo: url)
    }

    /// Sends one local file's path + contents to the device (host → device). Returns false on failure.
    ///
    /// Ports `mb2_handle_send_file`'s three outcomes EXACTLY — getting the absent-file case wrong is
    /// what made the device refuse a first backup with MBErrorDomain/205:
    ///  - file ABSENT  → CODE_ERROR_LOCAL + the error description. The device reads this as "not
    ///    present" and treats the backup as fresh/full. (On a first backup Status.plist /
    ///    Manifest.plist legitimately don't exist; they MUST be reported absent, never as empty data.)
    ///  - file present but EMPTY → CODE_SUCCESS terminator, no data block.
    ///  - file present with data  → CODE_FILE_DATA block(s) then a CODE_SUCCESS terminator.
    private func sendOneFile(deviceRelativePath path: String) -> Bool {
        guard let local = MB2PathGuard.confinedPath(backupRoot: backupRoot, deviceRelativePath: path) else {
            return false
        }
        // Send path length (big-endian) + path bytes (always, like the C, before stat).
        let pathBytes = Array(path.utf8)
        var plen = UInt32(pathBytes.count).bigEndian
        guard withUnsafeBytes(of: &plen, { sendRaw($0) }) else { return false }
        guard pathBytes.withUnsafeBytes({ sendRaw($0) }) else { return false }

        // Absent file → CODE_ERROR_LOCAL + errno description (the reference's stat-failure path).
        guard fm.fileExists(atPath: local.path) else {
            sendErrorLocal(description: String(cString: strerror(ENOENT)))
            return true   // not a transport failure — the device handles "absent" gracefully
        }
        guard let data = try? Data(contentsOf: local) else {
            sendErrorLocal(description: String(cString: strerror(EIO)))
            return true
        }
        if data.isEmpty {
            // Present but empty (total == 0 in the C) → CODE_SUCCESS terminator, no data block.
            sendTerminator(MB2Handlers.codeSuccess)
            return true
        }
        // Present with data → a single FILE_DATA block (length = data + 1 for the code byte).
        // The reference chunks at 32KB; we send one block because host→device transfers here are
        // only the tiny backup control files the device requests back (Status.plist / Manifest.plist
        // / Info.plist) — never bulk data, which always flows device→host. If a large host→device
        // file ever became possible, this would need the C's 32KB chunking loop.
        var header = Data()
        var blockLen = UInt32(data.count + 1).bigEndian
        withUnsafeBytes(of: &blockLen) { header.append(contentsOf: $0) }
        header.append(MB2Handlers.codeFileData)
        let ok = header.withUnsafeBytes { sendRaw($0) } && data.withUnsafeBytes { sendRaw($0) }
        sendTerminator(MB2Handlers.codeSuccess)
        return ok
    }

    /// Sends a CODE_ERROR_LOCAL frame for an absent/unreadable file (the device's "not present"
    /// signal). Frame bytes are built by the pure, unit-tested MB2.absentFileFrame.
    private func sendErrorLocal(description: String) {
        let frame = MB2.absentFileFrame(description: description)
        frame.withUnsafeBytes { _ = sendRaw($0) }
    }

    private func sendTerminator(_ code: UInt8) {
        let frame = MB2.terminatorFrame(code: code)
        frame.withUnsafeBytes { _ = sendRaw($0) }
    }
}
