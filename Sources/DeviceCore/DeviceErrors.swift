import Foundation

public enum ConnectionError: Error, LocalizedError, Equatable {
    case muxdUnreachable
    case deviceNotFound(udid: String)
    case noDeviceConnected
    case ambiguousDevice(count: Int)
    case notPaired(udid: String)
    case connectionFailed(code: Int32)

    public var errorDescription: String? {
        switch self {
        case .muxdUnreachable: "Could not reach usbmuxd (the macOS USB device daemon)."
        case .deviceNotFound(let udid): "No connected device with UDID \(udid)."
        case .noDeviceConnected: "No device is connected."
        case .ambiguousDevice(let count): "\(count) devices are connected; target is ambiguous."
        case .notPaired(let udid): "Device \(udid) is not paired with this Mac."
        case .connectionFailed(let code): "Device connection failed (libimobiledevice code \(code))."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .muxdUnreachable: "Reconnect the device; usbmuxd starts automatically on macOS."
        case .deviceNotFound: "Run `trug devices list` to see connected devices."
        case .noDeviceConnected: "Connect an iPhone or iPad over USB and try again."
        case .ambiguousDevice: "Pass --udid to choose a device (see `trug devices list`)."
        case .notPaired: "Run `trug devices pair` and tap Trust on the device."
        case .connectionFailed: "Unplug and reconnect the device, then retry."
        }
    }
}

public enum PairingError: Error, LocalizedError, Equatable {
    case passwordProtected
    case userDenied
    case trustDialogPending
    case failed(code: Int32)

    public var errorDescription: String? {
        switch self {
        case .passwordProtected: "The device is locked with a passcode."
        case .userDenied: "Pairing was declined on the device."
        case .trustDialogPending: "The device is showing the Trust dialog."
        case .failed(let code): "Pairing failed (lockdownd code \(code))."
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .passwordProtected: "Unlock the device, then run `trug devices pair` again."
        case .userDenied: "Run `trug devices pair` again and tap Trust."
        case .trustDialogPending: "Tap Trust on the device, then re-run the command."
        case .failed: "Reconnect the device and retry; if it persists, re-pair."
        }
    }
}
