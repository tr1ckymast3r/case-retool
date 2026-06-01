"""
Local static analysis engine — runs in the app container.
Fast, no external tools needed. Handles file type detection,
hash calculation, string extraction, and basic dependency analysis.
"""

import os
import re
import hashlib
import struct
import zipfile
import json
import magic  # python-magic
from datetime import datetime

from app.models import Analysis


def detect_file_type(filepath: str) -> dict:
    """Detect file type, platform, and architecture."""
    result = {"type": "Unknown", "platform": "Unknown", "arch": "Unknown", "details": ""}

    try:
        with open(filepath, "rb") as f:
            header = f.read(512)
    except Exception:
        return result

    if len(header) < 2:
        return result

    # PE (Windows executable)
    if header[:2] == b"MZ":
        result["type"] = "PE"
        result["platform"] = "Windows"
        try:
            with open(filepath, "rb") as f:
                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_offset + 4)
                machine = struct.unpack("<H", f.read(2))[0]
                if machine == 0x14C:
                    result["arch"] = "x86"
                elif machine == 0x8664:
                    result["arch"] = "x64"
                elif machine == 0x1C0:
                    result["arch"] = "ARM"
                elif machine == 0xAA64:
                    result["arch"] = "ARM64"
        except Exception:
            result["arch"] = "Unknown"
        result["details"] = f"Windows PE {result['arch']} executable"
        return result

    # ELF (Linux executable)
    if header[:4] == b"\x7fELF":
        ei_class = header[4]
        ei_data = header[5]
        e_machine = struct.unpack("<H" if ei_data == 1 else ">H", header[18:20])[0]
        result["type"] = "ELF"
        result["platform"] = "Linux"
        if ei_class == 1:
            result["arch"] = "x86"
        elif ei_class == 2:
            result["arch"] = "x64"
        machine_map = {0x28: "ARM", 0xB7: "ARM64", 0x03: "x86", 0x3E: "x64", 0x08: "MIPS", 0x14: "PPC"}
        if e_machine in machine_map:
            result["arch"] = machine_map[e_machine]
        result["details"] = f"Linux ELF {result['arch']} executable"
        return result

    # Mach-O (macOS executable)
    if header[:4] in (b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF", b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE"):
        result["type"] = "Mach-O"
        result["platform"] = "macOS"
        if header[:4] in (b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE"):
            result["arch"] = "x86"
        else:
            result["arch"] = "x64"
        result["details"] = f"macOS Mach-O {result['arch']} executable"
        return result

    # Mach-O Universal/Fat binary
    if header[:4] == b"\xCA\xFE\xBA\xBE":
        result["type"] = "Mach-O"
        result["platform"] = "macOS"
        result["arch"] = "Universal"
        result["details"] = "macOS Universal (Fat) binary"
        return result

    # DEB (Debian package) — `!<arch>` magic
    if header[:8] == b"!<arch>\n":
        # Check for debian-binary inside
        try:
            with open(filepath, "rb") as f:
                content = f.read(4096)
                if b"debian-binary" in content:
                    result["type"] = "DEB"
                    result["platform"] = "Linux"
                    result["details"] = "Debian package (.deb)"
                    return result
        except Exception:
            pass
        result["type"] = "AR Archive"
        result["details"] = "AR archive (ar format)"
        return result

    # RPM — 0xEDABEEDB magic
    if len(header) >= 4 and header[:4] == b"\xED\xAB\xEE\xDB":
        result["type"] = "RPM"
        result["platform"] = "Linux"
        result["details"] = "RPM package (.rpm)"
        return result

    # MSI — D0CF11E0 (COM Structured Storage / OLE2)
    if header[:4] == b"\xD0\xCF\x11\xE0":
        # Could be MSI or old Office doc — check for MSI signature
        try:
            with open(filepath, "rb") as f:
                data = f.read(8192)
                if b"\x05SummaryInformation" in data or b"MSI" in data:
                    result["type"] = "MSI"
                    result["platform"] = "Windows"
                    result["details"] = "Windows Installer package (.msi)"
                    return result
                result["type"] = "OLE2"
                result["platform"] = "Windows"
                result["details"] = "OLE2 Compound Document"
                return result
        except Exception:
            result["type"] = "OLE2"
            result["platform"] = "Windows"
            result["details"] = "OLE2 Compound Document"
            return result

    # APK / ZIP-based
    if header[:2] == b"PK":
        # Check if it's an APK, JAR, or plain ZIP
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                names = zf.namelist()
                # APK
                if "AndroidManifest.xml" in names:
                    result["type"] = "APK"
                    result["platform"] = "Android"
                    result["details"] = "Android application package (.apk)"
                    return result
                # JAR
                if "META-INF/MANIFEST.MF" in names:
                    result["type"] = "JAR"
                    result["platform"] = "Java"
                    result["details"] = "Java archive (.jar)"
                    return result
                # IPA (iOS)
                for n in names:
                    if n.startswith("Payload/") and n.endswith(".app/Info.plist"):
                        result["type"] = "IPA"
                        result["platform"] = "iOS"
                        result["details"] = "iOS application archive (.ipa)"
                        return result
        except zipfile.BadZipFile:
            pass
        result["type"] = "ZIP"
        result["details"] = "ZIP archive"
        return result

    # RAR
    if header[:4] == b"Rar!\x1a\x07" or header[:3] == b"Rar":
        result["type"] = "RAR"
        result["details"] = "RAR archive"
        return result

    # 7z
    if header[:6] == b"\x37\x7a\xbc\xaf\x27\x1c":
        result["type"] = "7z"
        result["details"] = "7-Zip archive"
        return result

    # TAR (ustar magic at offset 257)
    if len(header) >= 263 and header[257:263] == b"ustar\x00":
        result["type"] = "TAR"
        result["details"] = "TAR archive"
        return result

    # GZ (single file or tar.gz)
    if header[:2] == b"\x1f\x8b":
        fname_lower = os.path.basename(filepath).lower()
        if fname_lower.endswith(".tar.gz") or fname_lower.endswith(".tgz"):
            result["type"] = "TGZ"
            result["details"] = "Gzipped TAR archive"
        else:
            result["type"] = "GZ"
            result["details"] = "Gzip compressed file"
        return result

    # BZ2
    if header[:3] == b"BZh":
        fname_lower = os.path.basename(filepath).lower()
        if fname_lower.endswith(".tar.bz2"):
            result["type"] = "TBZ2"
            result["details"] = "Bzip2 compressed TAR"
        else:
            result["type"] = "BZ2"
            result["details"] = "Bzip2 compressed file"
        return result

    # XZ
    if header[:6] == b"\xfd7zXZ\x00":
        fname_lower = os.path.basename(filepath).lower()
        if fname_lower.endswith(".tar.xz"):
            result["type"] = "TXZ"
            result["details"] = "XZ compressed TAR"
        else:
            result["type"] = "XZ"
            result["details"] = "XZ compressed file"
        return result

    # SO (shared object) — typically ELF but check extension
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".so":
        result["type"] = "SO"
        result["platform"] = "Linux"
        result["details"] = "Shared library (.so)"
        return result
    if ext == ".dll":
        result["type"] = "DLL"
        result["platform"] = "Windows"
        result["details"] = "Dynamic Link Library (.dll)"
        return result

    # .NET assembly check
    try:
        with open(filepath, "rb") as f:
            data = f.read(4096)
            if b"mscoree.dll" in data or b"_CorExeMain" in data:
                result["type"] = ".NET"
                result["platform"] = "Windows"
                result["arch"] = "AnyCPU"
                result["details"] = ".NET assembly"
                return result
    except Exception:
        pass

    # Script detection
    try:
        text_preview = header.decode("utf-8", errors="ignore").strip()
        script_shebangs = {
            "#!/bin/bash": ("Script", "Linux", "Bash"),
            "#!/bin/sh": ("Script", "Linux", "Shell"),
            "#!/usr/bin/env python": ("Script", "Cross-platform", "Python"),
            "#!/usr/bin/env node": ("Script", "Cross-platform", "JavaScript/Node"),
            "#!/usr/bin/env ruby": ("Script", "Cross-platform", "Ruby"),
            "#!/usr/bin/env perl": ("Script", "Cross-platform", "Perl"),
        }
        for shebang, (stype, splatform, slang) in script_shebangs.items():
            if text_preview.startswith(shebang):
                result["type"] = stype
                result["platform"] = splatform
                result["details"] = f"{slang} script"
                return result
    except Exception:
        pass

    # MIME type fallback
    try:
        mime = magic.from_file(filepath, mime=True)
        mime_map = {
            "application/x-executable": ("ELF", "Linux"),
            "application/x-dosexec": ("PE", "Windows"),
            "application/x-mach-binary": ("Mach-O", "macOS"),
            "application/x-sharedlib": ("SO", "Linux"),
            "application/x-debian-package": ("DEB", "Linux"),
            "application/x-rpm": ("RPM", "Linux"),
        }
        if mime in mime_map:
            mtype, mplatform = mime_map[mime]
            result["type"] = mtype
            result["platform"] = mplatform
            result["details"] = f"Detected via MIME: {mime}"
            return result
        if mime and mime.startswith("text/"):
            result["type"] = "Text"
            result["details"] = f"Text file ({mime})"
            return result
    except Exception:
        pass

    result["details"] = "Binary or unknown format"
    return result


def calculate_hashes(filepath: str) -> dict:
    """Calculate MD5, SHA1, SHA256 hashes for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except Exception:
        return {"md5": "", "sha1": "", "sha256": ""}


def extract_strings(filepath: str, min_length: int = 6) -> dict:
    """Extract and categorize strings from a binary file."""
    result = {
        "urls": [],
        "ips": [],
        "emails": [],
        "paths": [],
        "registry": [],
        "commands": [],
        "api_keys": [],
        "suspicious": [],
        "total_count": 0,
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read(10 * 1024 * 1024)  # Read up to 10MB
    except Exception:
        return result

    # Extract printable strings
    strings = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode("ascii", errors="ignore"))
            current = bytearray()
    if len(current) >= min_length:
        strings.append(current.decode("ascii", errors="ignore"))

    result["total_count"] = len(strings)

    seen_urls = set()
    seen_ips = set()
    seen_emails = set()

    url_re = re.compile(r"https?://[^\s\"'<>]{5,}", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    email_re = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    path_re = re.compile(r"(?:/[a-zA-Z0-9_.-]+){2,}")
    registry_re = re.compile(r"HKEY_[A-Z_]+\\[^\s]+", re.IGNORECASE)
    command_re = re.compile(
        r"(?:curl|wget|powershell|cmd\.exe|/bin/bash|/bin/sh|chmod|chown|sudo|apt-get|yum|pip install)\s+[^\s]*",
        re.IGNORECASE,
    )
    api_key_re = re.compile(
        r"(?:api[_-]?key|secret[_-]?key|token|password|bearer)\s*[:=]\s*\S+",
        re.IGNORECASE,
    )

    suspicious_keywords = [
        "exploit", "payload", "shellcode", "keylogger", "trojan", "backdoor",
        "rootkit", "ransomware", "botnet", "cryptominer", "inject", "hook",
        "bypass", "privilege", "escalation", "exfiltrate", "credential",
        "dump", "steal", "persistence", "obfuscat", "encode", "decode",
        "reverse_shell", "bind_shell", "meterpreter", "mimikatz",
    ]

    for s in strings:
        # URLs
        for m in url_re.finditer(s):
            url = m.group()
            if url not in seen_urls:
                seen_urls.add(url)
                result["urls"].append(url)

        # IPs (excluding common localhost/broadcast)
        for m in ip_re.finditer(s):
            ip = m.group()
            if ip not in seen_ips and not ip.startswith("0.") and ip not in ("127.0.0.1", "255.255.255.255", "0.0.0.0"):
                seen_ips.add(ip)
                result["ips"].append(ip)

        # Emails
        for m in email_re.finditer(s):
            email = m.group()
            if email not in seen_emails:
                seen_emails.add(email)
                result["emails"].append(email)

        # Paths
        for m in path_re.finditer(s):
            p = m.group()
            if len(p) < 100:
                result["paths"].append(p)

        # Registry keys
        for m in registry_re.finditer(s):
            result["registry"].append(m.group())

        # Commands
        for m in command_re.finditer(s):
            cmd = m.group()
            if cmd not in result["commands"]:
                result["commands"].append(cmd)

        # API keys
        for m in api_key_re.finditer(s):
            key = m.group()
            if key not in result["api_keys"]:
                result["api_keys"].append(key)

        # Suspicious keywords
        s_lower = s.lower()
        for kw in suspicious_keywords:
            if kw in s_lower:
                if s not in result["suspicious"]:
                    result["suspicious"].append(s[:200])
                break

    # Limit results to avoid huge JSON
    for key in ["urls", "ips", "emails", "paths", "registry", "commands", "api_keys", "suspicious"]:
        result[key] = result[key][:100]

    return result


def detect_dependencies_basic(filepath: str) -> list:
    """Basic dependency detection from file content."""
    deps = []

    try:
        with open(filepath, "rb") as f:
            data = f.read(2 * 1024 * 1024)  # 2MB
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return deps

    # .NET references
    dotnet_refs = re.findall(r"(?:System\.\w+(?:\.\w+)*|Microsoft\.\w+(?:\.\w+)*)", text)
    seen = set()
    for ref in dotnet_refs:
        if ref not in seen:
            seen.add(ref)
            deps.append({"name": ref, "type": "dotnet_reference"})

    # DLL imports
    dll_imports = re.findall(r"(\w+\.dll)", text, re.IGNORECASE)
    seen_dlls = set()
    for dll in dll_imports:
        dll_lower = dll.lower()
        if dll_lower not in seen_dlls:
            seen_dlls.add(dll_lower)
            deps.append({"name": dll, "type": "dll_import"})

    # Java imports (for JAR/APK)
    java_imports = re.findall(r"import\s+([\w.]+);", text[:50000])
    seen_java = set()
    for imp in java_imports:
        pkg = imp.rsplit(".", 1)[0] if "." in imp else imp
        if pkg not in seen_java and not imp.startswith("java.") and not imp.startswith("android."):
            seen_java.add(pkg)
            deps.append({"name": imp, "type": "java_import"})

    # Python imports
    python_imports = re.findall(r"(?:from|import)\s+([\w.]+)", text[:50000])
    seen_py = set()
    for imp in python_imports:
        top = imp.split(".")[0]
        if top not in seen_py and top not in ("os", "sys", "re", "json", "time", "datetime"):
            seen_py.add(top)
            deps.append({"name": imp, "type": "python_import"})

    # Shared library dependencies (from ELF .dynamic section strings)
    so_refs = re.findall(r"lib([\w.-]+)\.so[\d.]*", text)
    seen_so = set()
    for so in so_refs:
        if so not in seen_so:
            seen_so.add(so)
            deps.append({"name": f"lib{so}", "type": "shared_library"})

    return deps[:200]


def run_local_analysis(analysis: Analysis, db) -> None:
    """Run all local analysis steps and update the database record."""
    filepath = analysis.filepath

    try:
        # File type detection
        type_info = detect_file_type(filepath)
        analysis.file_type = type_info.get("type", "Unknown")
        analysis.platform = type_info.get("platform", "Unknown")

        # Hashes
        hashes = calculate_hashes(filepath)
        analysis.md5 = hashes.get("md5", "")
        analysis.sha1 = hashes.get("sha1", "")
        analysis.sha256 = hashes.get("sha256", "")

        # File size
        analysis.file_size = os.path.getsize(filepath)

        # Strings analysis
        strings_result = extract_strings(filepath)

        # Basic dependencies
        deps = detect_dependencies_basic(filepath)
        analysis.dependencies = json.dumps(deps)

        # Build tech stack from what we know
        tech_stack = {
            "language": type_info.get("details", "Unknown"),
            "type": type_info.get("type", "Unknown"),
            "platform": type_info.get("platform", "Unknown"),
            "arch": type_info.get("arch", "Unknown"),
        }

        # Infer language from deps
        dep_types = {d["type"] for d in deps}
        if "dotnet_reference" in dep_types:
            tech_stack["language"] = "C#/.NET"
            tech_stack["framework"] = ".NET"
        elif "java_import" in dep_types:
            tech_stack["language"] = "Java"
        elif "python_import" in dep_types:
            tech_stack["language"] = "Python"

        analysis.tech_stack = json.dumps(tech_stack)
        analysis.architecture = json.dumps({
            "type": type_info.get("type", "Unknown"),
            "arch": type_info.get("arch", "Unknown"),
            "details": type_info.get("details", ""),
        })

        # Store string analysis results
        analysis.features = json.dumps({
            "strings_analysis": strings_result,
            "total_strings": strings_result.get("total_count", 0),
            "suspicious_strings_count": len(strings_result.get("suspicious", [])),
        })

        analysis.status = "analyzing"  # Local done, waiting for worker
        db.commit()

    except Exception as e:
        analysis.status = "failed"
        analysis.error_message = f"Local analysis failed: {str(e)}"
        db.commit()


def merge_worker_results(analysis_id: str, worker_result: dict, db) -> None:
    """Merge worker deep analysis results into the analysis record."""
    from app.database import SessionLocal

    # Open a new session since we're in a background thread
    session = SessionLocal()
    try:
        analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            return

        # Worker returns: {id, results: {binary/package/apk/ghidra/dynamic}, status}
        results = worker_result.get("results", {})

        # --- Merge ELF/PE binary analysis ---
        binary = results.get("binary", {})
        if binary:
            # Update tech stack with language/framework detected by worker
            existing_ts = json.loads(analysis.tech_stack or "{}")
            if binary.get("language") and binary["language"] != "unknown":
                existing_ts["language"] = binary["language"]
            if binary.get("framework") and binary["framework"] != "unknown":
                existing_ts["framework"] = binary["framework"]
            analysis.tech_stack = json.dumps(existing_ts)

            # Store shared libraries as dependencies
            existing_deps = json.loads(analysis.dependencies or "[]")
            shared_libs = binary.get("shared_libs", "")
            if shared_libs:
                for line in shared_libs.strip().split("\n"):
                    line = line.strip()
                    if "=>" in line:
                        lib_name = line.split("=>")[0].strip()
                        if lib_name:
                            existing_deps.append({"name": lib_name, "type": "shared_library"})
            analysis.dependencies = json.dumps(existing_deps)

            # Store categorized strings in features
            existing_features = json.loads(analysis.features or "{}")
            if binary.get("strings_categorized"):
                existing_features["worker_strings"] = binary["strings_categorized"]
            if binary.get("crypto_detected"):
                existing_features["crypto_detected"] = binary["crypto_detected"]
            if binary.get("network_libs"):
                existing_features["network_libs"] = binary["network_libs"]
            if binary.get("persistence_mechanisms"):
                existing_features["persistence_mechanisms"] = binary["persistence_mechanisms"]
            analysis.features = json.dumps(existing_features)

            # Store disassembly in decompiled_code
            decompiled = {}
            if binary.get("disassembly_sample"):
                decompiled["disassembly"] = binary["disassembly_sample"][:10000]
            if binary.get("header"):
                decompiled["elf_header"] = binary["header"]
            if binary.get("sections_raw"):
                decompiled["sections"] = binary["sections_raw"][:5000]
            if binary.get("dynamic_symbols"):
                decompiled["dynamic_symbols"] = binary["dynamic_symbols"][:5000]
            if decompiled:
                analysis.decompiled_code = json.dumps(decompiled)

            # Store architecture info
            existing_arch = json.loads(analysis.architecture or "{}")
            if binary.get("header"):
                # Extract entry point and other info from ELF header
                for line in binary["header"].split("\n"):
                    if "Entry point" in line:
                        existing_arch["entry_point"] = line.split(":")[-1].strip()
            analysis.architecture = json.dumps(existing_arch)

        # --- Merge DEB package analysis ---
        package = results.get("package", {})
        if package:
            existing_ts = json.loads(analysis.tech_stack or "{}")
            if package.get("package_info"):
                pi = package["package_info"]
                existing_ts["package_name"] = pi.get("Package", "")
                existing_ts["package_version"] = pi.get("Version", "")
                existing_ts["package_arch"] = pi.get("Architecture", "")
                existing_ts["package_maintainer"] = pi.get("Maintainer", "")
            analysis.tech_stack = json.dumps(existing_ts)

            if package.get("dependencies"):
                existing_deps = json.loads(analysis.dependencies or "[]")
                for dep in package["dependencies"]:
                    existing_deps.append({"name": dep, "type": "deb_dependency"})
                analysis.dependencies = json.dumps(existing_deps)

            # Store scripts (preinst, postinst, etc.)
            if package.get("scripts"):
                existing_features = json.loads(analysis.features or "{}")
                existing_features["install_scripts"] = package["scripts"]
                analysis.features = json.dumps(existing_features)

            # Store file list
            if package.get("files"):
                existing_features = json.loads(analysis.features or "{}")
                existing_features["package_files"] = [
                    {"path": f.get("path", ""), "size": f.get("size", 0), "type": f.get("type", "")}
                    for f in package["files"][:200]
                ]
                existing_features["binary_files"] = [
                    {"path": f.get("path", ""), "file_info": f.get("file_info", "")}
                    for f in package.get("binaries", [])
                ]
                existing_features["config_files"] = [
                    {"path": f.get("path", ""), "content_preview": f.get("content_preview", "")[:500]}
                    for f in package.get("configs", [])
                ]
                existing_features["service_files"] = [
                    {"path": f.get("path", ""), "content": f.get("content", "")[:500]}
                    for f in package.get("services", [])
                ]
                analysis.features = json.dumps(existing_features)

            # Store decompiled code from binaries in package
            if package.get("binaries"):
                decompiled = json.loads(analysis.decompiled_code or "{}")
                decompiled["package_binaries"] = [
                    {"path": b.get("path", ""), "file_info": b.get("file_info", ""), "strings_sample": b.get("strings_sample", "")[:2000]}
                    for b in package["binaries"][:20]
                ]
                analysis.decompiled_code = json.dumps(decompiled)

        # --- Merge APK analysis ---
        apk = results.get("apk", {})
        if apk:
            existing_features = json.loads(analysis.features or "{}")
            if apk.get("permissions"):
                existing_features["permissions"] = apk["permissions"]
            if apk.get("activities"):
                existing_features["activities"] = apk["activities"]
            if apk.get("services"):
                existing_features["android_services"] = apk["services"]
            if apk.get("receivers"):
                existing_features["receivers"] = apk["receivers"]
            analysis.features = json.dumps(existing_features)

            if apk.get("source_code", {}).get("key_files"):
                decompiled = json.loads(analysis.decompiled_code or "{}")
                decompiled["java_classes"] = [
                    {"name": f.get("path", ""), "code": f.get("content", "")[:5000]}
                    for f in apk["source_code"]["key_files"][:30]
                ]
                decompiled["total_java_files"] = apk["source_code"].get("total_java_files", 0)
                analysis.decompiled_code = json.dumps(decompiled)

        # --- Merge Ghidra results ---
        ghidra = results.get("ghidra", {})
        if ghidra and not ghidra.get("error"):
            decompiled = json.loads(analysis.decompiled_code or "{}")
            if ghidra.get("decompiled"):
                decompiled["ghidra_functions"] = [
                    {"name": f.get("name", ""), "address": f.get("address", ""), "size": f.get("size", 0), "code": f.get("code", "")[:3000]}
                    for f in ghidra["decompiled"][:20]
                ]
            if ghidra.get("functions"):
                decompiled["total_functions"] = len(ghidra["functions"])
            analysis.decompiled_code = json.dumps(decompiled)

        # --- Merge Dynamic analysis ---
        dynamic = results.get("dynamic", {})
        if dynamic:
            network = json.loads(analysis.network_activity or "{}")
            if dynamic.get("syscalls"):
                network["syscalls"] = dynamic["syscalls"]
            if dynamic.get("network_ops"):
                network["network_operations"] = dynamic["network_ops"]
            if dynamic.get("file_ops"):
                network["file_operations"] = dynamic["file_ops"]
            if dynamic.get("stdout"):
                network["stdout"] = dynamic["stdout"][:2000]
            if dynamic.get("stderr"):
                network["stderr"] = dynamic["stderr"][:2000]
            analysis.network_activity = json.dumps(network)

        # Store raw worker results
        analysis.worker_results = json.dumps(worker_result)
        analysis.status = "completed"
        analysis.completed_at = datetime.utcnow()

        # Generate report
        try:
            from app.engines.report_engine import generate_report
            generate_report(analysis, session)
        except Exception as e:
            analysis.error_message = f"Report generation warning: {str(e)}"

        session.commit()
    except Exception as e:
        session.rollback()
        analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
        if analysis:
            analysis.status = "failed"
            analysis.error_message = f"Worker result merge failed: {str(e)}"
            session.commit()
    finally:
        session.close()


def mark_completed(analysis_id: str, db) -> None:
    """Mark analysis as completed with local results only (worker timeout)."""
    from app.database import SessionLocal

    session = SessionLocal()
    try:
        analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            return

        analysis.status = "completed"
        analysis.completed_at = datetime.utcnow()

        # Generate report from local results
        try:
            from app.engines.report_engine import generate_report
            generate_report(analysis, session)
        except Exception:
            pass

        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()