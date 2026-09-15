import io
import plistlib
from defusedxml import ElementTree as XML
from .artifacts import concern
from .config import Rejected
from .records import digest
from .safety import SafeZip, bounded_tree

ANDROID = "{http://schemas.android.com/apk/res/android}"


def xml(data, protobuf=False):
    if data.lstrip().startswith(b"<"):
        tree = XML.fromstring(data, forbid_dtd=True)
    elif protobuf:
        from .aab_xml import decode
        tree = decode(data)
    else:
        from loguru import logger
        logger.disable("androguard")
        from androguard.core.axml import AXMLPrinter
        ax = AXMLPrinter(data)
        if not ax.is_valid():raise Rejected("invalid_binary_android_xml")
        tree = ax.get_xml_obj()
        if tree is None:raise Rejected("invalid_binary_android_xml")
    budget = [0]
    def visit(el, depth):
        budget[0] += 1
        if depth > 32 or budget[0] > 10000:raise Rejected("xml_tree_limit")
        for child in el:visit(child, depth + 1)
    visit(tree, 0)
    return tree


def manifest(tree, path):
    if tree.tag != "manifest":raise Rejected("expected_android_manifest")
    app, sdk = tree.find("application"), tree.find("uses-sdk")
    findings, components = [], []
    flags = {}
    if app is not None:
        flags = {k: app.get(ANDROID + k, "unspecified") for k in
                 ("debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig", "permission")}
        for k in ("debuggable", "usesCleartextTraffic"):
            if flags[k] == "true":
                findings.append(concern("android." + k, {"member": path, "element": "application"},
                    k + " is enabled in this manifest.", "Review release configuration and platform defaults.",
                    "Development variants or an explicit transport exception can be intentional."))
        for c in app:
            if c.tag in {"activity", "activity-alias", "service", "receiver", "provider"}:
                components.append({"type": c.tag, "name": c.get(ANDROID + "name"),
                    "exported": c.get(ANDROID + "exported", "unspecified; defaults depend on component/SDK"),
                    "permission": c.get(ANDROID + "permission", app.get(ANDROID + "permission", "unspecified")),
                    "intent_filter_count": len(c.findall("intent-filter"))})
                if c.get(ANDROID + "exported") == "true" and not c.get(ANDROID + "permission", app.get(ANDROID + "permission")):
                    findings.append(concern("android.exported-no-permission", {"member": path, "element": c.tag, "name": c.get(ANDROID + "name")},
                        "An explicitly exported component has no manifest-level permission declaration.",
                        "Review intended public entrypoints and code-level caller checks before restricting access.",
                        "Launchers and public app links are often intentionally exported; runtime checks may apply."))
    return {"member": path, "package": tree.get("package"),
            "version_name": tree.get(ANDROID + "versionName"), "version_code": tree.get(ANDROID + "versionCode"),
            "sdk": {} if sdk is None else {k: sdk.get(ANDROID + k) for k in ("minSdkVersion", "targetSdkVersion")},
            "permissions": [c.get(ANDROID + "name") for c in tree if c.tag.startswith("uses-permission")],
            "application_flags": flags, "components": components, "concerns": findings}


def certificates(data):
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.hazmat.primitives import hashes
    from cryptography import x509
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            certs = [x509.load_pem_x509_certificate(data)]
        else:
            try:certs = pkcs7.load_der_pkcs7_certificates(data)
            except ValueError:certs = [x509.load_der_x509_certificate(data)]
        return [{"sha256": c.fingerprint(hashes.SHA256()).hex(),
                 "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(),
                 "key_type": type(c.public_key()).__name__} for c in certs]
    except ValueError:
        raise Rejected("invalid_certificate") from None


def android(data, limits):
    z = SafeZip(data, limits)
    is_aab = "BundleConfig.pb" in z.names or any(n.endswith("/manifest/AndroidManifest.xml") for n in z.names)
    paths = [n for n in z.names if n == "AndroidManifest.xml" or n.endswith("/manifest/AndroidManifest.xml")]
    if not paths:raise Rejected("missing_android_manifest")
    manifests = [manifest(xml(z.read(p), protobuf=is_aab), p) for p in paths]
    network = []
    for n in z.names:
        if "/xml/" in n and n.endswith(".xml"):
            root = xml(z.read(n), protobuf=is_aab)
            if root.tag == "network-security-config":
                network.append({"member": n, "configs": [
                    {"element": c.tag, "cleartext_permitted": c.get("cleartextTrafficPermitted", "unspecified"),
                     "trust_anchor_sources": [x.get("src") for x in c.findall(".//certificates")],
                     "pin_count": len(c.findall(".//pin")), "domain_count": len(c.findall(".//domain"))}
                    for c in root]})
    certs = []
    for n in z.names:
        if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC")):
            certs.append({"member": n, "certificates": certificates(z.read(n))})
    return {"observations": {"format": "AAB" if is_aab else "APK", "manifests": manifests,
            "network_security_configs": network, "certificates": certs,
            "native_libraries": [n for n in z.names if n.endswith(".so")],
            "dex_files": [n for n in z.names if n.endswith(".dex")],
            "resource_count": sum("res/" in n for n in z.names), "member_count": len(z.names)},
            "limitations": ["No installation, execution, decompilation or signature verification.",
            "APK AXML uses Androguard; AAB XML uses a field projection with Google protobuf.",
            "Resource-ID references, split configuration and merged manifests may require source context.",
            "Only archive v1 certificate blocks are parsed; APK v2/v3/v4 signing blocks are not validated.",
            "Exported components and permissions are declarations, not proof of an exploitable boundary."]}


def plist(data):
    if not data.startswith(b"bplist"):
        XML.fromstring(data, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    obj = bounded_tree(plistlib.loads(data))
    if not isinstance(obj, dict):raise Rejected("expected_plist_dictionary")
    return obj


def ios(data, limits):
    z = SafeZip(data, limits)
    paths = [n for n in z.names if n.startswith("Payload/") and n.endswith("/Info.plist")]
    if not paths:raise Rejected("missing_ipa_info_plist")
    bundles, findings = [], []
    for path in paths:
        p = plist(z.read(path))
        ats = p.get("NSAppTransportSecurity", {})
        if not isinstance(ats, dict):raise Rejected("invalid_ats_dictionary")
        bundles.append({"member": path, "identifier": p.get("CFBundleIdentifier"),
            "version": p.get("CFBundleShortVersionString"), "minimum_os": p.get("MinimumOSVersion"),
            "ats_flags": {k: v for k, v in ats.items() if isinstance(v, bool)},
            "ats_exception_count": len(ats.get("NSExceptionDomains", {})),
            "ats_exceptions": [{"domain": name, "flags": {k: v for k, v in value.items() if isinstance(v, bool)},
                "minimum_tls": value.get("NSExceptionMinimumTLSVersion", "unspecified")}
                for name, value in ats.get("NSExceptionDomains", {}).items() if isinstance(value, dict)],
            "url_schemes": [s for t in p.get("CFBundleURLTypes", []) for s in t.get("CFBundleURLSchemes", [])],
            "usage_description_keys": [k for k in p if k.startswith("NS") and k.endswith("UsageDescription")]})
        if ats.get("NSAllowsArbitraryLoads") is True:
            findings.append(concern("ios.ats-arbitrary", {"member": path}, "ATS arbitrary loads are permitted.",
                "Remove broad exceptions; scope necessary exceptions and document them.", "Platform version and narrower ATS keys may override this flag."))
    entitlements = []
    for path in z.names:
        if path.endswith((".entitlements", "entitlements.plist")):
            entitlements.append({"member": path, "analysis": entitlement(z.read(path), limits)})
    return {"observations": {"bundles": bundles, "entitlements": entitlements,
            "frameworks": sorted({n.split(".framework/")[0] + ".framework" for n in z.names if ".framework/" in n}),
            "signature_resources_present": any("_CodeSignature/" in n for n in z.names)}, "concerns": findings,
            "limitations": ["Entitlements must be supplied as plist; CMS provisioning profiles and embedded signatures are not verified.",
            "Encrypted executable contents are unavailable; use binary_metadata on a supplied executable to inspect encryption flags.",
            "Device behavior, signing validation, keychain access and runtime instrumentation require macOS/device tooling."]}


def entitlement(data, _limits):
    p = plist(data)
    return {"keys": sorted(p), "debugging_entitlement": p.get("get-task-allow"),
            "app_sandbox": p.get("com.apple.security.app-sandbox"),
            "keychain_group_count": len(p.get("keychain-access-groups", [])),
            "associated_domain_count": len(p.get("com.apple.developer.associated-domains", [])),
            "limitations": ["Provided declarations only; actual signed entitlements are not independently verified."]}


def binary(data, limits):
    import lief
    lief.logging.disable()
    if len(data) < 32:raise Rejected("truncated_binary")
    recognized = data[:4] == b"\x7fELF" or data[:2] == b"MZ" or data[:4] in {
        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
    if not recognized:raise Rejected("unsupported_binary_format")
    if data[:4] in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        fat = lief.MachO.parse(data)
        bins = [] if fat is None else list(fat)
    else:
        b = lief.parse(data)
        bins = [] if b is None else [b]
    if not bins:raise Rejected("invalid_binary")
    out = []
    for b in bins:
        fmt = type(b).__module__.split(".")[-1]
        sec = list(b.sections)
        if len(sec) > limits.archive_entries:raise Rejected("binary_section_limit")
        entry = {"format": fmt, "sections": [{"name": s.name, "size": s.size, "offset": s.offset} for s in sec],
                 "nx_flag": bool(b.has_nx), "pie_flag": bool(b.is_pie)}
        if isinstance(b, lief.ELF.Binary):
            entry.update(format="ELF", architecture=str(b.header.machine_type), libraries=list(b.libraries),
                         segment_types=[str(s.type) for s in b.segments])
        elif isinstance(b, lief.PE.Binary):
            entry.update(format="PE", architecture=str(b.header.machine), libraries=list(b.libraries),
                         dll_characteristics=int(b.optional_header.dll_characteristics))
        elif isinstance(b, lief.MachO.Binary):
            entry.update(format="Mach-O", architecture=str(b.header.cpu_type), libraries=[x.name for x in b.libraries],
                         header_flags=int(b.header.flags),
                         encryption_id=b.encryption_info.crypt_id if b.has_encryption_info else None)
        for s in sec:
            # Zero-fill/BSS sections can exceed file size without file backing.
            if s.offset > len(data):raise Rejected("binary_section_outside_file")
        out.append(entry)
    return {"observations": out, "limitations": ["LIEF header/section/import metadata only; target never executed.",
            "A header flag does not establish exploitation, runtime protections or code reachability.",
            "No disassembly, signature validation, automatic unpacking or decryption."]}


PLATFORM_ANALYZERS = {"android": android, "ios": ios, "entitlement": entitlement,
                      "binary": binary, "certificate": lambda b, _: {"observations": certificates(b)}}
