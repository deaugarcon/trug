import Foundation
import Cplist

/// The only crossing point between plist_t (C) and Foundation values.
public enum PlistBridge {
    /// Converts a C plist node to a Foundation property-list object.
    /// Crossing via XML is slower than node-walking but is one obviously
    /// correct function — revisit only if profiling says so.
    /// A nil return means the C bridge failed or the node was nil — never an empty plist.
    public static func foundationObject(from node: plist_t) -> Any? {
        var xml: UnsafeMutablePointer<CChar>? = nil
        var length: UInt32 = 0
        let err = plist_to_xml(node, &xml, &length)
        guard err == PLIST_ERR_SUCCESS, let xml else { return nil }
        defer { plist_mem_free(xml) }
        return foundationObject(fromXML: Data(bytes: xml, count: Int(length)))
    }

    public static func foundationObject(fromXML data: Data) -> Any? {
        try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    }
}
