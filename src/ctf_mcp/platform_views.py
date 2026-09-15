"""Focused static views built on the existing APK/IPA/LIEF parsers."""
import re
from . import platforms
from .config import Rejected
from .redaction import redact_text
from .safety import SafeZip


ANDROID_VIEWS = {"android_package_info", "android_manifest", "android_permissions", "android_exported_components",
                 "android_network_security", "android_certificate_info", "android_find_deeplinks"}
IOS_VIEWS = {"ios_package_info", "ios_info_plist", "ios_entitlements", "ios_url_schemes", "ios_ats_config", "ios_frameworks", "ios_macho_info"}
BINARY_VIEWS = {"binary_identify", "binary_imports", "binary_exports", "binary_strings"}


def android_view(data, limits, view):
    result = platforms.android(data, limits)
    obs = result["observations"]
    if view == "android_manifest":selected = obs["manifests"]
    elif view == "android_permissions":selected = [{"member": m["member"], "permissions": m["permissions"]} for m in obs["manifests"]]
    elif view == "android_exported_components":selected = [{"member": m["member"], "components": m["components"]} for m in obs["manifests"]]
    elif view == "android_network_security":selected = {"configs": obs["network_security_configs"], "application_flags": [m["application_flags"] for m in obs["manifests"]]}
    elif view == "android_certificate_info":selected = obs["certificates"]
    elif view == "android_find_deeplinks":
        z = SafeZip(data, limits);selected = []
        for m in obs["manifests"]:
            tree = platforms.xml(z.read(m["member"]), protobuf=obs["format"] == "AAB")
            for component in tree.findall("./application/*"):
                for intent in component.findall("intent-filter"):
                    for item in intent.findall("data"):
                        selected.append({"member": m["member"], "component": component.get(platforms.ANDROID + "name"),
                            "declaration": {key: item.get(platforms.ANDROID + key) for key in
                                ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType") if item.get(platforms.ANDROID + key) is not None},
                            "auto_verify": intent.get(platforms.ANDROID + "autoVerify", "unspecified")})
    else:selected = {k: v for k, v in obs.items() if k not in {"network_security_configs", "certificates"}}
    return {"observations": selected, "limitations": result["limitations"]}


def ios_view(data, limits, view):
    if view == "ios_entitlements" and not data.startswith(b"PK"):
        return {"observations": platforms.entitlement(data, limits)}
    result = platforms.ios(data, limits);obs = result["observations"]
    if view == "ios_frameworks":selected = obs["frameworks"]
    elif view == "ios_entitlements":selected = obs["entitlements"]
    elif view == "ios_url_schemes":selected = [{"member": b["member"], "url_schemes": b["url_schemes"]} for b in obs["bundles"]]
    elif view == "ios_ats_config":selected = [{key: value for key, value in b.items() if key == "member" or key.startswith("ats_")} for b in obs["bundles"]]
    elif view == "ios_macho_info":
        z = SafeZip(data, limits);selected = []
        for bundle in obs["bundles"]:
            info = platforms.plist(z.read(bundle["member"]))
            executable = info.get("CFBundleExecutable")
            if not isinstance(executable, str) or not executable or "/" in executable or "\\" in executable:continue
            member = bundle["member"].rsplit("/", 1)[0] + "/" + executable
            if member not in z.names:
                selected.append({"member": member, "status": "EXECUTABLE_NOT_PROVIDED"});continue
            parsed = platforms.binary(z.read(member), limits)
            if any(b["format"] != "Mach-O" for b in parsed["observations"]):raise Rejected("ipa_executable_not_macho")
            selected.append({"member": member, "analysis": parsed})
    elif view == "ios_info_plist":
        z = SafeZip(data, limits);selected = []
        approved = {"CFBundleIdentifier", "CFBundleExecutable", "CFBundleName", "CFBundleVersion", "CFBundleShortVersionString", "MinimumOSVersion", "UIDeviceFamily", "LSRequiresIPhoneOS"}
        for b in obs["bundles"]:
            info = platforms.plist(z.read(b["member"]))
            selected.append({"member": b["member"], "key_names": sorted(info), "selected_metadata": {k: v for k, v in info.items() if k in approved}})
    else:selected = obs
    return {"observations": selected, "limitations": result["limitations"]}


def binary_view(data, limits, view):
    result = platforms.binary(data, limits)
    if view == "binary_identify":
        selected = [{"format": b["format"], "architecture": b["architecture"]} for b in result["observations"]]
    elif view == "binary_strings":
        selected = []
        for match in re.finditer(rb"[\x20-\x7e]{5,256}", data):
            if len(selected) >= 500:break
            value = match.group().decode("ascii")
            # Strings can contain credentials; omit the whole value when redaction changes it.
            redacted = redact_text(value)
            selected.append({"offset": match.start(), "length": len(value),
                "value": "[WITHHELD]" if redacted != value else redacted})
        result["limitations"].append("Only first 500 ASCII runs, maximum 256 bytes each; no complete Unicode string extraction.")
    else:
        import lief
        if data[:4] in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:bins = list(lief.MachO.parse(data))
        else:bins = [lief.parse(data)]
        selected = []
        for binary in bins:
            functions = binary.imported_functions if view == "binary_imports" else binary.exported_functions
            entries = []
            for fn in functions:
                if len(entries) >= 2000:raise Rejected("binary_symbol_limit")
                entries.append({"name": fn.name, "address": fn.address})
            selected.append({"functions": entries})
    return {"observations": selected, "limitations": result["limitations"]}
