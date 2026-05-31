#!/usr/bin/env python3
"""ReTool Auto-Extractor — detects and unpacks installers, packers, and embedded payloads."""

import os
import re
import shutil
import subprocess
import tempfile
import json
from pathlib import Path


def run_cmd(cmd, timeout=120, cwd=None):
    """Run shell command, return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1


def detect_file_type(filepath):
    """Deep file type detection — returns dict with type, sub_type, confidence."""
    result = {"type": "unknown", "sub_type": None, "confidence": 0, "details": {}}

    # file command
    file_out, _, _ = run_cmd(f"file '{filepath}'")
    file_lower = file_out.lower()

    # Read first 4KB for magic bytes
    with open(filepath, "rb") as f:
        header = f.read(4096)
    header_hex = header[:256].hex()

    # Read strings for detection
    strings_out, _, _ = run_cmd(f"strings -n 5 '{filepath}' | head -500")
    strings_lower = strings_out.lower()

    # === PE Executable Detection ===
    if header[:2] == b"MZ":
        result["type"] = "PE"
        result["confidence"] = 100

        # Detect specific installer/packer types
        import pefile
        try:
            pe = pefile.PE(filepath)

            # Check .NET
            for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if entry.name == "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR" and entry.VirtualAddress:
                    result["sub_type"] = "dotnet"
                    result["details"]["is_dotnet"] = True
                    pe.close()
                    return result

            # Check sections for packer signatures
            sections = []
            for sec in pe.sections:
                name = sec.Name.decode(errors='ignore').strip('\x00')
                sections.append({
                    "name": name,
                    "size": sec.SizeOfRawData,
                    "entropy": sec.get_entropy()
                })

            result["details"]["sections"] = sections
            result["details"]["imports_count"] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0

            # Only KERNEL32 + SHELL32 = likely stub/loader
            import_dlls = set()
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    import_dlls.add(entry.dll.decode(errors='ignore').lower())

            result["details"]["import_dlls"] = list(import_dlls)

            # Check for installer signatures
            # NSIS
            if any(s["name"].startswith(".ndata") or "nsis" in s["name"].lower() for s in sections):
                result["sub_type"] = "nsis"
                result["confidence"] = 95
                pe.close()
                return result

            if "nsis" in strings_lower or "nullsoft" in strings_lower:
                result["sub_type"] = "nsis"
                result["confidence"] = 90
                pe.close()
                return result

            # Inno Setup
            if "inno" in strings_lower and ("setup" in strings_lower or "install" in strings_lower):
                result["sub_type"] = "inno"
                result["confidence"] = 90
                pe.close()
                return result

            # InstallShield
            if "installshield" in strings_lower:
                result["sub_type"] = "installshield"
                result["confidence"] = 85
                pe.close()
                return result

            # 7z SFX
            if "7z" in strings_lower and ("sfx" in strings_lower or "self-extract" in strings_lower):
                result["sub_type"] = "7z_sfx"
                result["confidence"] = 85
                pe.close()
                return result

            # UPX packed
            if any("upx" in s["name"].lower() for s in sections):
                result["sub_type"] = "upx"
                result["confidence"] = 95
                pe.close()
                return result
            if "upx" in strings_lower[:2000]:
                result["sub_type"] = "upx"
                result["confidence"] = 80
                pe.close()
                return result

            # Resource-heavy (embedded payload)
            rsrc_sections = [s for s in sections if s["name"] == ".rsrc"]
            if rsrc_sections and rsrc_sections[0]["size"] > 5_000_000:
                result["sub_type"] = "resource_heavy"
                result["confidence"] = 85
                result["details"]["rsrc_size"] = rsrc_sections[0]["size"]
                result["details"]["rsrc_entropy"] = rsrc_sections[0]["entropy"]
                pe.close()
                return result

            # High entropy = packed
            for s in sections:
                if s["entropy"] > 7.5 and s["size"] > 100_000:
                    result["sub_type"] = "packed"
                    result["confidence"] = 70
                    result["details"]["packed_section"] = s["name"]
                    pe.close()
                    return result

            # Minimal imports (stub)
            if len(import_dlls) <= 3 and len(pe.DIRECTORY_ENTRY_IMPORT) <= 5:
                result["sub_type"] = "stub"
                result["confidence"] = 60
                pe.close()
                return result

            # Regular PE — detect language
            pe.close()

        except Exception as e:
            result["details"]["pe_error"] = str(e)

        # Default PE analysis
        result["sub_type"] = "native"
        return result

    # === Other types ===
    if header[:4] == b"\x7fELF":
        result["type"] = "ELF"
        result["sub_type"] = "native"
        result["confidence"] = 100
    elif header[:4] == b"PK\x03\x04":
        if filepath.endswith(".apk") or "android" in strings_lower:
            result["type"] = "APK"
        elif filepath.endswith(".ipa"):
            result["type"] = "IPA"
        else:
            result["type"] = "ZIP"
        result["confidence"] = 100
    elif header[:8] == b"!<arch>\n":
        result["type"] = "DEB"
        result["confidence"] = 100
    elif header[:4] == b"\rPid":
        result["type"] = "RAR"
        result["confidence"] = 100
    elif header[:6] == b"7z\xbc\xaf\x27\x1c":
        result["type"] = "7z"
        result["confidence"] = 100

    return result


def extract_nsis(filepath, output_dir):
    """Extract NSIS installer."""
    print("  [extract] NSIS installer detected", flush=True)
    extracted = []

    # Method 1: 7z extract
    out, err, rc = run_cmd(f"7z x -y -o'{output_dir}' '{filepath}'", timeout=120)
    if rc == 0:
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                extracted.append(os.path.join(root, f))
        if extracted:
            print(f"  [extract] 7z extracted {len(extracted)} files", flush=True)
            return extracted

    # Method 2: binwalk
    out, err, rc = run_cmd(f"binwalk -e -C '{output_dir}' '{filepath}'", timeout=120)
    if rc == 0:
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                extracted.append(os.path.join(root, f))
        if extracted:
            print(f"  [extract] binwalk extracted {len(extracted)} files", flush=True)
            return extracted

    return extracted


def extract_inno(filepath, output_dir):
    """Extract Inno Setup installer."""
    print("  [extract] Inno Setup installer detected", flush=True)
    extracted = []

    # Try innoextract
    out, err, rc = run_cmd(f"innoextract -d '{output_dir}' '{filepath}'", timeout=120)
    if rc == 0:
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                extracted.append(os.path.join(root, f))
        print(f"  [extract] innoextract extracted {len(extracted)} files", flush=True)
        return extracted

    # Fallback: 7z
    out, err, rc = run_cmd(f"7z x -y -o'{output_dir}' '{filepath}'", timeout=120)
    if rc == 0:
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                extracted.append(os.path.join(root, f))
        if extracted:
            print(f"  [extract] 7z extracted {len(extracted)} files", flush=True)
            return extracted

    return extracted


def extract_upx(filepath, output_dir):
    """Unpack UPX packed executable."""
    print("  [extract] UPX packed binary detected", flush=True)
    out_name = os.path.join(output_dir, os.path.basename(filepath) + ".unpacked")
    out, err, rc = run_cmd(f"upx -d -o '{out_name}' '{filepath}'", timeout=60)
    if rc == 0 and os.path.exists(out_name):
        print(f"  [extract] UPX unpacked successfully", flush=True)
        return [out_name]
    print(f"  [extract] UPX unpack failed: {err[:200]}", flush=True)
    return []


def extract_resource_heavy(filepath, output_dir):
    """Extract embedded resources from PE with large .rsrc section."""
    print("  [extract] Resource-heavy PE detected, extracting resources...", flush=True)
    extracted = []

    # Method 1: wrestool (for NE/PE resources)
    out, err, rc = run_cmd(f"wrestool -x --type=14 '{filepath}' > '{output_dir}/manifest.xml' 2>/dev/null")

    # Method 2: 7z to extract embedded archives
    out, err, rc = run_cmd(f"7z x -y -o'{output_dir}' '{filepath}'", timeout=120)
    if rc == 0:
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                fpath = os.path.join(root, f)
                if os.path.getsize(fpath) > 0:
                    extracted.append(fpath)

    # Method 3: binwalk for embedded files
    if not extracted:
        out, err, rc = run_cmd(f"binwalk -e -C '{output_dir}' '{filepath}'", timeout=120)
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                extracted.append(os.path.join(root, f))

    # Method 4: Search for embedded PE/MZ in the file
    if not extracted:
        print("  [extract] Scanning for embedded executables...", flush=True)
        with open(filepath, "rb") as f:
            data = f.read()

        # Find MZ headers (embedded PE files)
        offset = 0
        pe_count = 0
        while True:
            pos = data.find(b"MZ", offset)
            if pos == -1:
                break
            # Check if it's a valid PE
            try:
                import pefile
                pe_data = data[pos:]
                if len(pe_data) > 512:
                    pe = pefile.PE(data=pe_data[:min(len(pe_data), 64*1024*1024)], fast_load=True)
                    if pe.is_exe() or pe.is_dll():
                        pe_path = os.path.join(output_dir, f"embedded_pe_{pe_count}.exe")
                        with open(pe_path, "wb") as pf:
                            # Write until end of PE
                            pe_size = pe.OPTIONAL_HEADER.SizeOfHeaders
                            for sec in pe.sections:
                                end = sec.PointerToRawData + sec.SizeOfRawData
                                if end > pe_size:
                                    pe_size = end
                            pf.write(pe_data[:pe_size])
                        extracted.append(pe_path)
                        pe_count += 1
                        print(f"  [extract] Found embedded PE at offset 0x{pos:x} ({pe_size} bytes)", flush=True)
                    pe.close()
            except:
                pass
            offset = pos + 2
            if offset > len(data) - 2:
                break

    if extracted:
        print(f"  [extract] Resource extraction found {len(extracted)} files", flush=True)
    else:
        print(f"  [extract] No extractable resources found", flush=True)

    return extracted


def extract_7z_sfx(filepath, output_dir):
    """Extract 7z self-extracting archive."""
    print("  [extract] 7z SFX detected", flush=True)
    extracted = []
    out, err, rc = run_cmd(f"7z x -y -o'{output_dir}' '{filepath}'", timeout=120)
    if rc == 0:
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                extracted.append(os.path.join(root, f))
        print(f"  [extract] 7z SFX extracted {len(extracted)} files", flush=True)
    return extracted


def extract_stub(filepath, output_dir):
    """Try multiple methods to extract payload from a stub/loader."""
    print("  [extract] Stub/loader detected, trying extraction methods...", flush=True)
    extracted = []

    # Try 7z first
    out, err, rc = run_cmd(f"7z x -y -o'{output_dir}/7z' '{filepath}'", timeout=120)
    if rc == 0:
        for root, dirs, files in os.walk(f"{output_dir}/7z"):
            for f in files:
                fpath = os.path.join(root, f)
                if os.path.getsize(fpath) > 100:  # Skip tiny files
                    extracted.append(fpath)

    # Try binwalk
    if not extracted:
        out, err, rc = run_cmd(f"binwalk -e -C '{output_dir}/binwalk' '{filepath}'", timeout=120)
        for root, dirs, files in os.walk(f"{output_dir}/binwalk"):
            for f in files:
                extracted.append(os.path.join(root, f))

    # Try strings to find embedded paths/URLs
    if not extracted:
        out, _, _ = run_cmd(f"strings -n 10 '{filepath}' | head -200")
        print(f"  [extract] Key strings found:\n{out[:1000]}", flush=True)

    return extracted


def extract_generic(filepath, output_dir):
    """Generic extraction — try everything."""
    print("  [extract] Trying generic extraction...", flush=True)
    extracted = []

    # 7z
    out, err, rc = run_cmd(f"7z x -y -o'{output_dir}/7z' '{filepath}'", timeout=60)
    if rc == 0:
        for root, dirs, files in os.walk(f"{output_dir}/7z"):
            for f in files:
                extracted.append(os.path.join(root, f))

    # binwalk
    if not extracted:
        out, err, rc = run_cmd(f"binwalk -e -C '{output_dir}/binwalk' '{filepath}'", timeout=120)
        for root, dirs, files in os.walk(f"{output_dir}/binwalk"):
            for f in files:
                extracted.append(os.path.join(root, f))

    return extracted


def auto_extract(filepath, output_dir):
    """Main entry point — detect type and extract automatically.

    Returns: dict with detection info and list of extracted files.
    """
    result = {
        "detection": detect_file_type(filepath),
        "extracted_files": [],
        "extraction_method": None,
        "error": None
    }

    detection = result["detection"]
    print(f"  [detect] Type={detection['type']} SubType={detection['sub_type']} Confidence={detection['confidence']}", flush=True)

    extract_dir = os.path.join(output_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    sub_type = detection.get("sub_type")
    file_type = detection.get("type")

    # Route to appropriate extractor
    if sub_type == "nsis":
        result["extracted_files"] = extract_nsis(filepath, extract_dir)
        result["extraction_method"] = "nsis"
    elif sub_type == "inno":
        result["extracted_files"] = extract_inno(filepath, extract_dir)
        result["extraction_method"] = "inno"
    elif sub_type == "upx":
        result["extracted_files"] = extract_upx(filepath, extract_dir)
        result["extraction_method"] = "upx"
    elif sub_type == "7z_sfx":
        result["extracted_files"] = extract_7z_sfx(filepath, extract_dir)
        result["extraction_method"] = "7z_sfx"
    elif sub_type == "resource_heavy":
        result["extracted_files"] = extract_resource_heavy(filepath, extract_dir)
        result["extraction_method"] = "resource_extraction"
    elif sub_type == "stub":
        result["extracted_files"] = extract_stub(filepath, extract_dir)
        result["extraction_method"] = "stub_extraction"
    elif sub_type == "packed":
        # Try UPX first, then generic
        result["extracted_files"] = extract_upx(filepath, extract_dir)
        if not result["extracted_files"]:
            result["extracted_files"] = extract_generic(filepath, extract_dir)
        result["extraction_method"] = "unpack"
    elif file_type == "DEB":
        # Already handled by analyze_deb
        result["extraction_method"] = "deb"
    elif file_type == "APK":
        # Already handled by analyze_apk
        result["extraction_method"] = "apk"
    else:
        # Generic extraction attempt
        result["extracted_files"] = extract_generic(filepath, extract_dir)
        result["extraction_method"] = "generic"

    # Filter out non-interesting files
    interesting_extensions = {
        '.exe', '.dll', '.sys', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.jar', '.class', '.py', '.rb', '.sh',
        '.apk', '.ipa', '.deb', '.rpm',
        '.so', '.dylib', '.elf',
        '.config', '.xml', '.json', '.ini', '.cfg',
        '.dat', '.bin', '.pak',
    }

    filtered = []
    for fpath in result["extracted_files"]:
        ext = os.path.splitext(fpath)[1].lower()
        size = os.path.getsize(fpath) if os.path.exists(fpath) else 0
        if ext in interesting_extensions or size > 100_000:  # Keep large files
            filtered.append(fpath)
        elif ext in ('.txt', '.log', '.md') and size < 100_000:
            filtered.append(fpath)  # Keep small text files

    result["interesting_files"] = filtered
    result["total_extracted"] = len(result["extracted_files"])
    result["total_interesting"] = len(filtered)

    print(f"  [extract] Total: {result['total_extracted']} files, {result['total_interesting']} interesting", flush=True)

    return result
