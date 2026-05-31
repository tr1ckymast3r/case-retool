#!/usr/bin/env python3
"""ReTool Analysis Worker — listens for tasks on shared volume, runs RE tools, returns results."""

import os
import sys
import json
import time
import shutil
import subprocess
import tempfile
import traceback
from pathlib import Path

DATA_DIR = Path("/data")
INPUT_DIR = DATA_DIR / "input"
OUTPUT_DIR = DATA_DIR / "output"
SCRIPTS_DIR = Path("/opt/retool/scripts")


def run_cmd(cmd, timeout=120, cwd=None):
    """Run shell command, return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1


def analyze_deb(filepath, output):
    """Deep analysis of .deb package."""
    result = {"package_info": {}, "dependencies": [], "files": [], "binaries": [],
              "configs": [], "services": [], "scripts": {}, "description": ""}

    with tempfile.TemporaryDirectory(prefix="retool_deb_") as tmpdir:
        # Extract with ar
        out, err, rc = run_cmd(f"ar x {filepath}", cwd=tmpdir)
        if rc != 0:
            result["error"] = f"ar extraction failed: {err}"
            return result

        print(f"  [deb] ar extracted: {os.listdir(tmpdir)}", flush=True)

        # Helper to extract tar (handles .gz, .xz, .zst, .bz2)
        def extract_tar(tar_path, dest_dir):
            os.makedirs(dest_dir, exist_ok=True)
            # Try with auto-detect first
            out, err, rc = run_cmd(f"tar xf {tar_path} -C {dest_dir}", timeout=60)
            if rc != 0:
                # Fallback: try with explicit flags
                if tar_path.endswith(".zst"):
                    run_cmd(f"zstd -d {tar_path} -o {tar_path.replace('.zst', '')}", timeout=30)
                    uncompressed = tar_path.replace(".zst", "")
                    if os.path.exists(uncompressed):
                        run_cmd(f"tar xf {uncompressed} -C {dest_dir}", timeout=60)
                elif tar_path.endswith(".xz"):
                    run_cmd(f"xz -d {tar_path}", timeout=30)
                    uncompressed = tar_path.replace(".xz", "")
                    if os.path.exists(uncompressed):
                        run_cmd(f"tar xf {uncompressed} -C {dest_dir}", timeout=60)
            return os.path.exists(dest_dir) and len(os.listdir(dest_dir)) > 0

        # Parse control
        for f in os.listdir(tmpdir):
            if f.startswith("control.tar"):
                control_dir = os.path.join(tmpdir, "control")
                tar_path = os.path.join(tmpdir, f)
                print(f"  [deb] Extracting control: {f}", flush=True)
                extract_tar(tar_path, control_dir)

                control_path = os.path.join(control_dir, "control")
                if not os.path.exists(control_path):
                    # Try in DEBIAN subdirectory
                    control_path = os.path.join(control_dir, "DEBIAN", "control")
                if os.path.exists(control_path):
                    with open(control_path) as cf:
                        current_key = None
                        for line in cf:
                            line = line.rstrip()
                            if ":" in line and not line.startswith(" "):
                                key, val = line.split(":", 1)
                                key, val = key.strip(), val.strip()
                                result["package_info"][key] = val
                                current_key = key
                            elif line.startswith(" ") and current_key:
                                result["package_info"][current_key] += "\n" + line.strip()
                    result["description"] = result["package_info"].get("Description", "")
                    deps = result["package_info"].get("Depends", "")
                    if deps:
                        result["dependencies"] = [d.strip().split("(")[0].strip() for d in deps.split(",")]
                    print(f"  [deb] Package: {result['package_info'].get('Package', '?')} v{result['package_info'].get('Version', '?')}", flush=True)

                # Read install scripts
                for script in ["preinst", "postinst", "prerm", "postrm"]:
                    spath = os.path.join(control_dir, script)
                    if not os.path.exists(spath):
                        spath = os.path.join(control_dir, "DEBIAN", script)
                    if os.path.exists(spath):
                        with open(spath) as sf:
                            result["scripts"][script] = sf.read(10000)

        # Parse data
        for f in os.listdir(tmpdir):
            if f.startswith("data.tar"):
                data_dir = os.path.join(tmpdir, "data")
                tar_path = os.path.join(tmpdir, f)
                print(f"  [deb] Extracting data: {f}", flush=True)
                extract_tar(tar_path, data_dir)

                for root, dirs, files in os.walk(data_dir):
                    for fname in files:
                        full_path = os.path.join(root, fname)
                        rel_path = os.path.relpath(full_path, data_dir)
                        fpath = "/" + rel_path
                        try:
                            fsize = os.path.getsize(full_path)
                        except:
                            fsize = 0

                        finfo = {"path": fpath, "size": fsize}

                        if "bin/" in rel_path or "sbin/" in rel_path:
                            finfo["type"] = "binary"
                            # Analyze binary
                            file_out, _, _ = run_cmd(f"file {full_path}")
                            finfo["file_info"] = file_out.strip()
                            # Get strings
                            strings_out, _, _ = run_cmd(f"strings -n 8 {full_path} | head -100")
                            finfo["strings_sample"] = strings_out[:2000]
                            result["binaries"].append(finfo)
                        elif rel_path.endswith((".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml")):
                            finfo["type"] = "config"
                            try:
                                with open(full_path, "r", errors="ignore") as cf:
                                    finfo["content_preview"] = cf.read(2000)
                            except:
                                pass
                            result["configs"].append(finfo)
                        elif ".service" in rel_path:
                            finfo["type"] = "service"
                            try:
                                with open(full_path, "r", errors="ignore") as sf:
                                    finfo["content"] = sf.read(2000)
                            except:
                                pass
                            result["services"].append(finfo)
                        elif rel_path.endswith((".so", ".so.1", ".so.2")):
                            finfo["type"] = "library"

                        result["files"].append(finfo)

    return result


def analyze_elf_deep(filepath, output):
    """Deep ELF binary analysis."""
    result = {"sections": [], "symbols": [], "imports": [], "strings_categorized": {},
              "language": "unknown", "framework": "unknown", "crypto_detected": [],
              "network_libs": [], "persistence_mechanisms": []}

    # readelf headers
    out, _, _ = run_cmd(f"readelf -h {filepath}")
    result["header"] = out

    # readelf sections
    out, _, _ = run_cmd(f"readelf -S {filepath}")
    result["sections_raw"] = out

    # Symbols (if not stripped)
    out, _, _ = run_cmd(f"nm -D {filepath} 2>/dev/null | head -200")
    result["dynamic_symbols"] = out

    # ldd (shared libraries)
    out, _, _ = run_cmd(f"ldd {filepath} 2>/dev/null")
    result["shared_libs"] = out

    # Detect language
    out, _, _ = run_cmd(f"strings -n 10 {filepath}")
    all_strings = out

    if "go.buildid" in all_strings or "runtime.go" in all_strings or "go.build" in all_strings:
        result["language"] = "Go"
        # Extract Go build info
        out2, _, _ = run_cmd(f"strings {filepath} | grep -i 'go1\\.' | head -5")
        result["go_version"] = out2.strip()
    elif "rust_begin_unwind" in all_strings or "rust_panic" in all_strings or "/rustc/" in all_strings:
        result["language"] = "Rust"
    elif "libstdc++" in all_strings or "GLIBCXX" in all_strings:
        result["language"] = "C++"
    elif "libc.so" in all_strings:
        result["language"] = "C"

    # Detect frameworks
    string_lower = all_strings.lower()
    if "qt" in string_lower and ("qwidget" in string_lower or "qapplication" in string_lower):
        result["framework"] = "Qt"
    elif "gtk_" in string_lower or "gtkwidget" in string_lower:
        result["framework"] = "GTK"
    elif "electron" in string_lower:
        result["framework"] = "Electron"
    elif "libflutter" in string_lower or "flutter" in string_lower:
        result["framework"] = "Flutter"
    elif "react-native" in string_lower:
        result["framework"] = "React Native"

    # Detect crypto
    for algo in ["aes", "rsa", "sha256", "sha512", "md5", "blowfish", "chacha20", "curve25519"]:
        if algo in string_lower:
            result["crypto_detected"].append(algo)

    # Detect network libs
    for lib in ["libcurl", "libssl", "libcrypto", "libwebsocket", "libsoup", "libhttp"]:
        if lib in all_strings:
            result["network_libs"].append(lib)

    # Categorized strings
    import re
    urls = re.findall(r'https?://[^\s<>"\']+', all_strings)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', all_strings)
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', all_strings)
    paths = re.findall(r'(?:/[a-zA-Z0-9._-]+){2,}', all_strings)

    result["strings_categorized"] = {
        "urls": list(set(urls))[:50],
        "ips": list(set(ips))[:30],
        "emails": list(set(emails))[:20],
        "file_paths": list(set(paths))[:50],
        "total_strings": len(all_strings.split("\n"))
    }

    # Disassemble key sections with objdump
    out, _, _ = run_cmd(f"objdump -d {filepath} | head -500")
    result["disassembly_sample"] = out[:5000]

    # Check for persistence mechanisms
    for keyword in ["crontab", "systemd", "/etc/init", "autostart", ".bashrc", ".profile", "LaunchAgent"]:
        if keyword in all_strings:
            result["persistence_mechanisms"].append(keyword)

    return result


def analyze_pe_deep(filepath, output):
    """Deep PE binary analysis."""
    result = {"imports": [], "exports": [], "sections": [], "resources": [],
              "language": "unknown", "dotnet": False, "packed": False,
              "installer_type": None, "strings_categorized": {}}

    # Detect installer
    out, _, _ = run_cmd(f"strings -n 5 {filepath} | head -200")
    if "Nullsoft" in out or "NSIS" in out:
        result["installer_type"] = "NSIS"
    elif "Inno Setup" in out:
        result["installer_type"] = "InnoSetup"
    elif "InstallShield" in out:
        result["installer_type"] = "InstallShield"
    elif "WiX" in out or "Windows Installer" in out:
        result["installer_type"] = "MSI"

    # PE analysis with pefile
    try:
        import pefile
        pe = pefile.PE(filepath)

        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        result["imports"].append({"dll": dll, "func": imp.name.decode(errors='ignore')})

        # Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result["exports"].append(exp.name.decode(errors='ignore'))

        # Sections
        for sec in pe.sections:
            name = sec.Name.decode(errors='ignore').strip('\x00')
            result["sections"].append({
                "name": name,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": sec.get_entropy()
            })

        # .NET detection
        for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name == "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR" and entry.VirtualAddress:
                result["dotnet"] = True
                result["language"] = ".NET/C#"
                break

        # Packer detection (high entropy sections)
        for sec in result["sections"]:
            if sec["entropy"] > 7.0 and sec["raw_size"] > 1000:
                result["packed"] = True
                break

        pe.close()
    except Exception as e:
        result["pe_error"] = str(e)

    # All strings
    out, _, _ = run_cmd(f"strings -n 8 {filepath}")
    all_strings = out

    # Language detection
    if result.get("dotnet"):
        result["language"] = ".NET/C#"
    elif "vcruntime" in all_strings.lower() or "msvcp" in all_strings.lower():
        result["language"] = "C++ (MSVC)"
    elif "mingw" in all_strings.lower():
        result["language"] = "C/C++ (MinGW)"
    elif "pyinstaller" in all_strings.lower():
        result["language"] = "Python (PyInstaller)"
    elif "electron" in all_strings.lower():
        result["language"] = "JavaScript (Electron)"
    elif "qt" in all_strings.lower():
        result["language"] = "C++ (Qt)"

    # Categorized strings
    import re
    urls = re.findall(r'https?://[^\s<>"\']+', all_strings)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', all_strings)
    regs = re.findall(r'HKEY_[A-Z_]+\\[^\s]+', all_strings)
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', all_strings)

    result["strings_categorized"] = {
        "urls": list(set(urls))[:50],
        "ips": list(set(ips))[:30],
        "registry_keys": list(set(regs))[:20],
        "emails": list(set(emails))[:20],
        "total_strings": len(all_strings.split("\n"))
    }

    return result


def analyze_apk_deep(filepath, output):
    """Deep APK analysis with jadx + apktool."""
    result = {"manifest": {}, "permissions": [], "activities": [], "services": [],
              "receivers": [], "providers": [], "decompiled": False, "source_code": {}}

    with tempfile.TemporaryDirectory(prefix="retool_apk_") as tmpdir:
        # Decode with apktool
        apktool_dir = os.path.join(tmpdir, "apktool_out")
        out, err, rc = run_cmd(f"apktool d -f -s {filepath} -o {apktool_dir}", timeout=120)
        if rc == 0:
            result["decompiled"] = True

            # Parse AndroidManifest.xml
            manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                with open(manifest_path, "r", errors="ignore") as mf:
                    manifest_content = mf.read()
                result["manifest"]["raw"] = manifest_content[:5000]

                # Extract permissions
                import re
                perms = re.findall(r'android\.permission\.(\w+)', manifest_content)
                result["permissions"] = list(set(perms))

                # Extract components
                activities = re.findall(r'<activity[^>]*android:name="([^"]*)"', manifest_content)
                result["activities"] = activities
                services = re.findall(r'<service[^>]*android:name="([^"]*)"', manifest_content)
                result["services"] = services
                receivers = re.findall(r'<receiver[^>]*android:name="([^"]*)"', manifest_content)
                result["receivers"] = receivers

        # Decompile with jadx
        jadx_dir = os.path.join(tmpdir, "jadx_out")
        out, err, rc = run_cmd(f"jadx -d {jadx_dir} {filepath}", timeout=180)
        if rc == 0:
            # Collect key Java files
            key_files = []
            for root, dirs, files in os.walk(jadx_dir):
                for fname in files:
                    if fname.endswith(".java"):
                        full_path = os.path.join(root, fname)
                        rel = os.path.relpath(full_path, jadx_dir)
                        try:
                            with open(full_path, "r", errors="ignore") as jf:
                                content = jf.read()
                            # Only keep interesting files (API clients, main activities, etc.)
                            if any(kw in content.lower() for kw in ["http", "api", "retrofit", "okhttp",
                                                                     "firebase", "network", "login", "auth",
                                                                     "encrypt", "decrypt", "database", "sqlite"]):
                                key_files.append({"path": rel, "content": content[:5000]})
                        except:
                            pass
            result["source_code"]["key_files"] = key_files[:30]

            # Count total files
            total_java = sum(1 for _, _, f in os.walk(jadx_dir) for fn in f if fn.endswith(".java"))
            result["source_code"]["total_java_files"] = total_java

    return result


def analyze_dotnet_deep(filepath, output):
    """Deep .NET analysis with ILSpy decompilation → C# source code."""
    result = {"decompiled": False, "namespaces": [], "classes": [], "source_files": [],
              "resources": [], "dotnet_info": {}, "error": None}

    # Get .NET metadata with pefile
    try:
        import pefile
        pe = pefile.PE(filepath)
        if hasattr(pe, 'DIRECTORY_ENTRY_COMIMAGE'):
            clr = pe.DIRECTORY_ENTRY_COMIMAGE.struct
            result["dotnet_info"] = {
                "runtime_version": f"{clr.MajorRuntimeVersion}.{clr.MinorRuntimeVersion}",
                "flags": clr.Flags,
                "entry_point": hex(clr.EntryPointRVA) if clr.EntryPointRVA else None,
            }
        pe.close()
    except Exception as e:
        result["dotnet_info_error"] = str(e)

    with tempfile.TemporaryDirectory(prefix="retool_dotnet_") as tmpdir:
        out_dir = os.path.join(tmpdir, "decompiled")
        os.makedirs(out_dir, exist_ok=True)

        # Decompile with ILSpy
        print(f"  [dotnet] Decompiling with ILSpy...", flush=True)
        out, err, rc = run_cmd(
            f"ilspycmd -p -o {out_dir} {filepath}",
            timeout=300
        )

        if rc != 0:
            # Try with just types (no resources)
            out, err, rc = run_cmd(
                f"ilspycmd -t -o {out_dir} {filepath}",
                timeout=300
            )

        if rc == 0:
            result["decompiled"] = True

            # Collect all .cs files
            cs_files = []
            namespaces = set()
            classes = []

            for root, dirs, files in os.walk(out_dir):
                for fname in files:
                    full_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(full_path, out_dir)

                    if fname.endswith(".cs"):
                        try:
                            with open(full_path, "r", errors="ignore") as f:
                                content = f.read()

                            # Extract namespace and class names
                            import re
                            ns_match = re.findall(r'namespace\s+([\w.]+)', content)
                            cls_match = re.findall(r'(?:public|internal|private|protected)?\s*(?:static\s+)?(?:partial\s+)?(?:class|struct|interface|enum)\s+(\w+)', content)

                            for ns in ns_match:
                                namespaces.add(ns)
                            for cls in cls_match:
                                classes.append({"name": cls, "namespace": ns_match[0] if ns_match else "", "file": rel_path})

                            cs_files.append({
                                "path": rel_path,
                                "content": content[:15000],  # Keep substantial code
                                "size": len(content),
                                "lines": content.count("\n")
                            })
                        except:
                            pass

            # Sort by importance: main/program files first, then by size
            def file_priority(f):
                name = f["path"].lower()
                if "program" in name or "main" in name or "entry" in name:
                    return 0
                if "app" in name or "config" in name or "settings" in name:
                    return 1
                if "api" in name or "client" in name or "network" in name or "http" in name:
                    return 2
                if "auth" in name or "login" in name or "encrypt" in name:
                    return 3
                return 4

            cs_files.sort(key=lambda x: (file_priority(x), -x["size"]))
            result["source_files"] = cs_files[:100]  # Top 100 files
            result["namespaces"] = sorted(namespaces)
            result["classes"] = classes[:200]
            result["total_cs_files"] = len(cs_files)
            result["total_lines"] = sum(f["lines"] for f in cs_files)

            print(f"  [dotnet] Decompiled {len(cs_files)} .cs files, {result['total_lines']} lines", flush=True)
        else:
            result["error"] = f"ILSpy failed: {err[:500]}" if err else "Unknown error"
            print(f"  [dotnet] ILSpy failed: {err[:200]}", flush=True)

    return result


def run_ghidra_decompile(filepath, output):
    """Run Ghidra headless analysis."""
    result = {"functions": [], "decompiled": {}, "call_graph": {}, "error": None}

    with tempfile.TemporaryDirectory(prefix="retool_ghidra_") as tmpdir:
        project_dir = os.path.join(tmpdir, "project")
        output_dir = os.path.join(tmpdir, "output")
        os.makedirs(project_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)

        # Copy file
        fname = os.path.basename(filepath)
        shutil.copy2(filepath, os.path.join(tmpdir, fname))

        # Run Ghidra headless
        ghidra_script = """
import ghidra.app.decompiler as Decomp
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType

program = getCurrentProgram()
decomp = Decomp.DecompInterface()
decomp.openProgram(program)

fm = program.getFunctionManager()
results = []

for func in fm.getFunctions(True):
    if func.isThunk():
        continue
    name = func.getName()
    addr = str(func.getEntryPoint())
    size = func.getBody().getNumAddresses()

    # Decompile
    result = decomp.decompileFunction(func, 30, monitor)
    c_code = ""
    if result and result.decompileCompleted():
        c_code = result.getDecompiledFunction().getC()

    results.append({
        "name": name,
        "address": addr,
        "size": size,
        "code": c_code[:3000] if c_code else ""
    })

# Save results
import json
with open(output_dir + "/ghidra_results.json", "w") as f:
    json.dump(results[:200], f)  # Limit to 200 functions
"""
        script_path = os.path.join(tmpdir, "analyze.py")
        with open(script_path, "w") as f:
            f.write(ghidra_script)

        cmd = (f"analyzeHeadless {project_dir} ReToolProject "
               f"-import {os.path.join(tmpdir, fname)} "
               f"-postScript {script_path} "
               f"-scriptPath {tmpdir} "
               f"-deleteProject")

        out, err, rc = run_cmd(cmd, timeout=300)

        ghidra_json = os.path.join(output_dir, "ghidra_results.json")
        if os.path.exists(ghidra_json):
            with open(ghidra_json) as f:
                funcs = json.load(f)
            result["functions"] = funcs
            # Top 20 biggest functions with decompiled code
            result["decompiled"] = sorted(funcs, key=lambda x: x.get("size", 0), reverse=True)[:20]
        else:
            result["error"] = f"Ghidra failed: {err[:500]}" if err else "No output"

    return result


def run_dynamic_analysis(filepath, output):
    """Run dynamic analysis with strace + network capture."""
    result = {"syscalls": {}, "file_ops": [], "network_ops": [], "process_tree": [],
              "captured_strings": [], "error": None}

    with tempfile.TemporaryDirectory(prefix="retool_dyn_") as tmpdir:
        fname = os.path.basename(filepath)
        work_file = os.path.join(tmpdir, fname)
        shutil.copy2(filepath, work_file)
        os.chmod(work_file, 0o755)

        # strace
        strace_out = os.path.join(tmpdir, "strace.txt")
        run_cmd(f"timeout 15 strace -f -o {strace_out} {work_file}", timeout=20)

        if os.path.exists(strace_out):
            with open(strace_out, "r", errors="ignore") as f:
                strace_data = f.read(500000)

            # Parse syscalls
            import re
            from collections import Counter
            syscall_pattern = re.compile(r'^(\w+)\(')
            syscall_counts = Counter()
            for line in strace_data.split("\n"):
                m = syscall_pattern.search(line)
                if m:
                    syscall_counts[m.group(1)] += 1

            result["syscalls"] = dict(syscall_counts.most_common(30))

            # File operations
            for line in strace_data.split("\n"):
                if any(op in line for op in ["open(", "openat(", "unlink(", "rename("]):
                    result["file_ops"].append(line[:200])
                if any(op in line for op in ["connect(", "sendto(", "recvfrom(", "socket("]):
                    result["network_ops"].append(line[:200])

            result["file_ops"] = result["file_ops"][:50]
            result["network_ops"] = result["network_ops"][:30]

        # Capture output strings
        stdout_out = os.path.join(tmpdir, "stdout.txt")
        stderr_out = os.path.join(tmpdir, "stderr.txt")
        run_cmd(f"timeout 10 {work_file} > {stdout_out} 2> {stderr_out}", timeout=15)

        if os.path.exists(stdout_out):
            with open(stdout_out, "r", errors="ignore") as f:
                result["stdout"] = f.read(5000)
        if os.path.exists(stderr_out):
            with open(stderr_out, "r", errors="ignore") as f:
                result["stderr"] = f.read(5000)

    return result


def process_task(task_file):
    """Process a single analysis task."""
    with open(task_file) as f:
        task = json.load(f)

    analysis_id = task["id"]
    filepath = task["filepath"]
    profile = task.get("profile", "quick_scan")
    file_type = task.get("file_type", "Unknown")

    output = {"id": analysis_id, "results": {}, "errors": []}

    try:
        # Always run type-specific deep analysis
        if file_type in ("DEB",):
            output["results"]["package"] = analyze_deb(filepath, output)
        elif file_type in ("ELF", "SO", "Executable"):
            output["results"]["binary"] = analyze_elf_deep(filepath, output)
        elif file_type in ("PE", "DLL", ".NET"):
            output["results"]["binary"] = analyze_pe_deep(filepath, output)
            # .NET files always get ILSpy decompilation (no protection = full source)
            pe_result = output["results"]["binary"]
            if pe_result.get("dotnet"):
                print(f"  [task] .NET detected — running ILSpy decompilation", flush=True)
                output["results"]["dotnet"] = analyze_dotnet_deep(filepath, output)
        elif file_type in ("APK",):
            output["results"]["apk"] = analyze_apk_deep(filepath, output)

        # Ghidra decompile for native binaries (if deep_static or full)
        if profile in ("deep_static", "full") and file_type in ("ELF", "PE", "SO", "DLL", ".NET", "Executable"):
            # Skip Ghidra for .NET (ILSpy is better)
            if not output["results"].get("binary", {}).get("dotnet"):
                output["results"]["ghidra"] = run_ghidra_decompile(filepath, output)

        # Dynamic analysis
        if profile in ("dynamic", "full") and file_type in ("ELF", "PE", "SO", "Executable"):
            output["results"]["dynamic"] = run_dynamic_analysis(filepath, output)

        output["status"] = "completed"
    except Exception as e:
        output["status"] = "failed"
        output["errors"].append(str(e))
        traceback.print_exc()

    # Write result
    result_file = OUTPUT_DIR / f"{analysis_id}.json"
    with open(result_file, "w") as f:
        json.dump(output, f, default=str)

    # Remove task file
    os.remove(task_file)

    return output


def main():
    """Main worker loop — watch for new tasks."""
    print("ReTool Worker started. Watching for tasks...", flush=True)
    print(f"  INPUT_DIR: {INPUT_DIR}", flush=True)
    print(f"  OUTPUT_DIR: {OUTPUT_DIR}", flush=True)
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    heartbeat = 0
    while True:
        try:
            tasks = list(INPUT_DIR.glob("*.json"))
            if tasks:
                for task_file in tasks:
                    print(f"Processing: {task_file.name}", flush=True)
                    try:
                        result = process_task(str(task_file))
                        print(f"Done: {result['id']} — {result['status']}", flush=True)
                    except Exception as e:
                        print(f"Error processing {task_file}: {e}", flush=True)
                        traceback.print_exc()
            else:
                heartbeat += 1
                if heartbeat >= 15:  # Every 30 seconds
                    # List what's in input dir for debugging
                    all_files = list(INPUT_DIR.iterdir())
                    print(f"[heartbeat] No tasks. Input dir has {len(all_files)} files: {[f.name for f in all_files[:5]]}", flush=True)
                    heartbeat = 0
        except Exception as e:
            print(f"Worker error: {e}", flush=True)
            traceback.print_exc()

        time.sleep(2)


if __name__ == "__main__":
    main()
