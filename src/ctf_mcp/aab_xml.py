"""AAPT2 XML field projection decoded by Google's protobuf runtime.

Field numbers follow AOSP tools/aapt2/Resources.proto (see sources.lock.json).
Unknown fields are preserved by protobuf but are not interpreted here. This is
an original descriptor projection, not a full resource-table implementation.
"""
from xml.etree.ElementTree import Element
from .config import Rejected


def xml_type():
    from google.protobuf import descriptor_pb2 as d, descriptor_pool, message_factory
    f = d.FileDescriptorProto(name="finder_aapt_xml.proto", package="finder_aapt", syntax="proto3")
    definitions = {
        "String": [("value", 1, 9, None, False)],
        "Reference": [("id", 2, 13, None, False), ("name", 3, 9, None, False)],
        "Primitive": [("int_decimal_value", 6, 5, None, False), ("int_hexadecimal_value", 7, 13, None, False), ("boolean_value", 8, 8, None, False)],
        "Item": [("ref", 1, 11, "Reference", False), ("str", 2, 11, "String", False), ("raw_str", 3, 11, "String", False), ("prim", 7, 11, "Primitive", False)],
        "XmlAttribute": [("namespace_uri", 1, 9, None, False), ("name", 2, 9, None, False), ("value", 3, 9, None, False), ("compiled_item", 6, 11, "Item", False)],
        "XmlElement": [("namespace_uri", 2, 9, None, False), ("name", 3, 9, None, False), ("attribute", 4, 11, "XmlAttribute", True), ("child", 5, 11, "XmlNode", True)],
        "XmlNode": [("element", 1, 11, "XmlElement", False), ("text", 2, 9, None, False)],
    }
    for name, fs in definitions.items():
        msg = f.message_type.add(name=name)
        if name == "Primitive":msg.oneof_decl.add(name="value")
        for field, number, typ, ref, repeated in fs:
            fd = msg.field.add(name=field, number=number, type=typ, label=3 if repeated else 1)
            if ref:fd.type_name = ".finder_aapt." + ref
            if name == "Primitive":fd.oneof_index = 0
    pool = descriptor_pool.DescriptorPool()
    pool.Add(f)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName("finder_aapt.XmlNode"))


def decode(data):
    from google.protobuf.message import DecodeError
    node = xml_type()()
    try:
        node.ParseFromString(data)
    except DecodeError:
        raise Rejected("invalid_aab_protobuf_xml") from None
    count = [0]
    def convert(n, depth=0):
        count[0] += 1
        if depth > 32 or count[0] > 10000:raise Rejected("xml_tree_limit")
        if not n.HasField("element") or not n.element.name:raise Rejected("invalid_aab_xml_element")
        e = Element(n.element.name)
        for a in n.element.attribute:
            value = a.value
            if not value and a.HasField("compiled_item"):
                c = a.compiled_item
                if c.HasField("prim"):
                    kind = c.prim.WhichOneof("value")
                    if kind:
                        v = getattr(c.prim, kind)
                        value = str(v).lower() if isinstance(v, bool) else str(v)
                    else:value = "[unsupported compiled primitive]"
                elif c.HasField("ref"):
                    value = "@" + (c.ref.name or hex(c.ref.id))
                elif c.HasField("str"):value = c.str.value
                elif c.HasField("raw_str"):value = c.raw_str.value
                else:value = "[unsupported compiled value]"
            key = "{" + a.namespace_uri + "}" + a.name if a.namespace_uri else a.name
            e.set(key, value)
        for child in n.element.child:
            if child.HasField("element"):e.append(convert(child, depth + 1))
        return e
    return convert(node)
