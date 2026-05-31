"""
Vietnamese report engine — generates detailed analysis reports.
This is the KEY feature of ReTool.
"""

import json
import os
from datetime import datetime

from app.config import settings
from app.models import Analysis


def _safe_json(text: str) -> dict:
    """Safely parse JSON text, return empty dict on failure."""
    if not text:
        return {}
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}


def _safe_json_list(text: str) -> list:
    """Safely parse JSON text as list."""
    if not text:
        return []
    try:
        result = json.loads(text)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _format_size(size_bytes: int) -> str:
    """Format file size in human-readable form."""
    if not size_bytes:
        return "Không rõ"
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def _section_header(title: str, level: int = 2) -> str:
    """Generate section header."""
    return f"\n{'#' * level} {title}\n\n"


def generate_report(analysis: Analysis, db=None) -> str:
    """Generate a comprehensive Vietnamese analysis report."""
    tech_stack = _safe_json(analysis.tech_stack)
    architecture = _safe_json(analysis.architecture)
    features = _safe_json(analysis.features)
    api_endpoints = _safe_json(analysis.api_endpoints)
    data_models = _safe_json(analysis.data_models)
    network_activity = _safe_json(analysis.network_activity)
    decompiled_code = _safe_json(analysis.decompiled_code)
    config_values = _safe_json(analysis.config_values)
    dependencies = _safe_json_list(analysis.dependencies)

    report = []
    report.append(f"# BÁO CÁO PHÂN TÍCH REVERSE ENGINEERING")
    report.append(f"**File:** {analysis.filename}")
    report.append(f"**ID:** `{analysis.id}`")
    report.append(f"**Thời gian tạo:** {analysis.created_at.strftime('%Y-%m-%d %H:%M:%S') if analysis.created_at else 'N/A'}")
    report.append(f"**Hoàn thành:** {analysis.completed_at.strftime('%Y-%m-%d %H:%M:%S') if analysis.completed_at else 'Đang xử lý'}")
    report.append("")

    # ================================================================
    # 1. TỔNG QUAN
    # ================================================================
    report.append(_section_header("1. Tổng Quan"))
    report.append(f"- **Tên file:** `{analysis.filename}`")
    report.append(f"- **Loại file:** {analysis.file_type}")
    report.append(f"- **Nền tảng:** {analysis.platform}")
    report.append(f"- **Kích thước:** {_format_size(analysis.file_size)}")
    report.append(f"- **Kiến trúc:** {architecture.get('arch', 'Không rõ')}")
    report.append(f"- **Chi tiết:** {architecture.get('details', '')}")
    report.append("")

    report.append("**Hash:**")
    report.append(f"- MD5: `{analysis.md5 or 'N/A'}`")
    report.append(f"- SHA1: `{analysis.sha1 or 'N/A'}`")
    report.append(f"- SHA256: `{analysis.sha256 or 'N/A'}`")
    report.append("")

    # ================================================================
    # 2. CÔNG NGHỆ SỬ DỤNG
    # ================================================================
    report.append(_section_header("2. Công Nghệ Sử Dụng"))
    report.append(f"- **Ngôn ngữ:** {tech_stack.get('language', 'Không rõ')}")
    report.append(f"- **Framework:** {tech_stack.get('framework', 'Không rõ')}")
    report.append(f"- **Loại ứng dụng:** {tech_stack.get('type', 'Không rõ')}")
    report.append(f"- **Nền tảng mục tiêu:** {tech_stack.get('platform', 'Không rõ')}")
    report.append(f"- **Kiến trúc:** {tech_stack.get('arch', 'Không rõ')}")

    # Additional tech details from worker
    if "compiler" in tech_stack:
        report.append(f"- **Trình biên dịch:** {tech_stack['compiler']}")
    if "runtime" in tech_stack:
        report.append(f"- **Runtime:** {tech_stack['runtime']}")
    if "sdk_version" in tech_stack:
        report.append(f"- **SDK Version:** {tech_stack['sdk_version']}")
    if "package_name" in tech_stack:
        report.append(f"- **Package:** {tech_stack['package_name']}")
    if "package_version" in tech_stack:
        report.append(f"- **Version:** {tech_stack['package_version']}")
    if "package_arch" in tech_stack:
        report.append(f"- **Architecture:** {tech_stack['package_arch']}")
    if "package_maintainer" in tech_stack:
        report.append(f"- **Maintainer:** {tech_stack['package_maintainer']}")
    report.append("")

    # ================================================================
    # 3. KIẾN TRÚC & PHỤ THUỘC
    # ================================================================
    report.append(_section_header("3. Kiến Trúc & Phụ Thuộc"))

    if dependencies:
        report.append(f"**Tổng số phụ thuộc:** {len(dependencies)}")
        report.append("")

        # Group by type
        by_type = {}
        for dep in dependencies:
            if isinstance(dep, dict):
                dtype = dep.get("type", "other")
                name = dep.get("name", "unknown")
            else:
                dtype = "other"
                name = str(dep)
            by_type.setdefault(dtype, []).append(name)

        type_labels = {
            "dotnet_reference": "Tham chiếu .NET",
            "dll_import": "DLL Import",
            "java_import": "Import Java",
            "python_import": "Import Python",
            "shared_library": "Thư viện chia sẻ (SO)",
            "maven_dependency": "Maven Dependency",
            "npm_package": "NPM Package",
            "gradle_dependency": "Gradle Dependency",
        }

        for dtype, names in by_type.items():
            label = type_labels.get(dtype, dtype)
            report.append(f"**{label}** ({len(names)}):")
            for name in names[:30]:
                report.append(f"  - `{name}`")
            if len(names) > 30:
                report.append(f"  - ... và {len(names) - 30} khác")
            report.append("")
    else:
        report.append("*Không phát hiện phụ thuộc.*")
        report.append("")

    # Architecture details from worker
    if "entry_points" in architecture:
        report.append("**Entry Points:**")
        for ep in architecture["entry_points"][:20]:
            report.append(f"  - `{ep}`")
        report.append("")

    if "modules" in architecture:
        report.append("**Modules:**")
        for mod in architecture["modules"][:20]:
            if isinstance(mod, dict):
                report.append(f"  - `{mod.get('name', '')}` — {mod.get('description', '')}")
            else:
                report.append(f"  - `{mod}`")
        report.append("")

    # ================================================================
    # 4. TÍNH NĂNG PHÁT HIỆN
    # ================================================================
    report.append(_section_header("4. Tính Năng Phát Hiện"))

    strings_info = features.get("strings_analysis", {})

    if features.get("suspicious_strings_count", 0) > 0:
        report.append(f"⚠️ **Phát hiện {features['suspicious_strings_count']} chuỗi đáng ngờ!**")
        report.append("")

    # Feature categories
    if "detected_features" in features:
        report.append("**Tính năng:**")
        for feat in features["detected_features"]:
            if isinstance(feat, dict):
                report.append(f"  - **{feat.get('name', '')}:** {feat.get('description', '')}")
            else:
                report.append(f"  - {feat}")
        report.append("")

    # Strings summary
    if strings_info:
        report.append("**Phân tích chuỗi:**")
        report.append(f"- Tổng số chuỗi: {strings_info.get('total_count', 0)}")
        report.append(f"- URLs: {len(strings_info.get('urls', []))}")
        report.append(f"- Địa chỉ IP: {len(strings_info.get('ips', []))}")
        report.append(f"- Email: {len(strings_info.get('emails', []))}")
        report.append(f"- Đường dẫn: {len(strings_info.get('paths', []))}")
        report.append(f"- Registry keys: {len(strings_info.get('registry', []))}")
        report.append(f"- Lệnh: {len(strings_info.get('commands', []))}")
        report.append(f"- API keys/tokens: {len(strings_info.get('api_keys', []))}")
        report.append("")

        if strings_info.get("urls"):
            report.append("**URLs phát hiện:**")
            for url in strings_info["urls"][:20]:
                report.append(f"  - `{url}`")
            if len(strings_info["urls"]) > 20:
                report.append(f"  - ... và {len(strings_info['urls']) - 20} khác")
            report.append("")

        if strings_info.get("ips"):
            report.append("**Địa chỉ IP phát hiện:**")
            for ip in strings_info["ips"][:20]:
                report.append(f"  - `{ip}`")
            report.append("")

        if strings_info.get("emails"):
            report.append("**Email phát hiện:**")
            for email in strings_info["emails"][:10]:
                report.append(f"  - `{email}`")
            report.append("")

        if strings_info.get("commands"):
            report.append("**Lệnh đáng chú ý:**")
            for cmd in strings_info["commands"][:10]:
                report.append(f"  - `{cmd}`")
            report.append("")

        if strings_info.get("suspicious"):
            report.append("**Chuỗi đáng ngờ:**")
            for s in strings_info["suspicious"][:10]:
                report.append(f"  - `{s}`")
            report.append("")

        if strings_info.get("api_keys"):
            report.append("**API Keys / Tokens phát hiện:**")
            for key in strings_info["api_keys"][:10]:
                report.append(f"  - `{key}`")
            report.append("")

    # Permissions (for APK)
    if "permissions" in features:
        report.append("**Quyền yêu cầu (Android):**")
        for perm in features["permissions"]:
            report.append(f"  - `{perm}`")
        report.append("")

    # Crypto detected
    if "crypto_detected" in features and features["crypto_detected"]:
        report.append("**Thuật toán mã hóa phát hiện:**")
        for algo in features["crypto_detected"]:
            report.append(f"  - `{algo}`")
        report.append("")

    # Network libraries
    if "network_libs" in features and features["network_libs"]:
        report.append("**Thư viện mạng:**")
        for lib in features["network_libs"]:
            report.append(f"  - `{lib}`")
        report.append("")

    # Persistence mechanisms
    if "persistence_mechanisms" in features and features["persistence_mechanisms"]:
        report.append("**Cơ chế persistence:**")
        for mech in features["persistence_mechanisms"]:
            report.append(f"  - `{mech}`")
        report.append("")

    # Install scripts (DEB)
    if "install_scripts" in features and features["install_scripts"]:
        report.append("**Script cài đặt (DEB package):**")
        for script_name, script_content in features["install_scripts"].items():
            report.append(f"### `{script_name}`")
            if len(script_content) > 2000:
                script_content = script_content[:2000] + "\n# ... (đã cắt bớt)"
            report.append(f"```bash\n{script_content}\n```")
            report.append("")

    # Package files (DEB)
    if "package_files" in features and features["package_files"]:
        report.append(f"**Files trong package ({len(features['package_files'])}):**")
        for f in features["package_files"][:50]:
            ftype = f.get("type", "")
            path = f.get("path", "")
            size = f.get("size", 0)
            type_str = f" [{ftype}]" if ftype else ""
            report.append(f"  - `{path}` ({_format_size(size)}){type_str}")
        if len(features["package_files"]) > 50:
            report.append(f"  - ... và {len(features['package_files']) - 50} files khác")
        report.append("")

    # Config files (DEB)
    if "config_files" in features and features["config_files"]:
        report.append("**Config files:**")
        for cf in features["config_files"][:10]:
            report.append(f"### `{cf.get('path', '')}`")
            preview = cf.get("content_preview", "")
            if preview:
                report.append(f"```\n{preview}\n```")
            report.append("")

    # Service files (DEB)
    if "service_files" in features and features["service_files"]:
        report.append("**Systemd service files:**")
        for sf in features["service_files"][:10]:
            report.append(f"### `{sf.get('path', '')}`")
            content = sf.get("content", "")
            if content:
                report.append(f"```ini\n{content}\n```")
            report.append("")

    # ================================================================
    # 5. API ENDPOINTS
    # ================================================================
    report.append(_section_header("5. API Endpoints"))

    if api_endpoints:
        endpoints = api_endpoints if isinstance(api_endpoints, list) else api_endpoints.get("endpoints", [])
        if endpoints:
            report.append(f"**Phát hiện {len(endpoints)} endpoints:**")
            report.append("")
            for ep in endpoints:
                if isinstance(ep, dict):
                    method = ep.get("method", "?")
                    path = ep.get("path", ep.get("url", "?"))
                    desc = ep.get("description", "")
                    report.append(f"- `{method} {path}` — {desc}")
                else:
                    report.append(f"- `{ep}`")
            report.append("")
        else:
            report.append("*Không phát hiện API endpoints.*")
            report.append("")
    else:
        report.append("*Không phát hiện API endpoints.*")
        report.append("")

    # ================================================================
    # 6. CẤU TRÚC DỮ LIỆU
    # ================================================================
    report.append(_section_header("6. Cấu Trúc Dữ Liệu"))

    if data_models:
        models = data_models if isinstance(data_models, list) else data_models.get("models", [])
        if models:
            for model in models:
                if isinstance(model, dict):
                    name = model.get("name", model.get("class", "Unknown"))
                    report.append(f"**{name}:**")
                    fields = model.get("fields", model.get("properties", []))
                    for field in fields:
                        if isinstance(field, dict):
                            fname = field.get("name", "")
                            ftype = field.get("type", "")
                            report.append(f"  - `{fname}`: {ftype}")
                        else:
                            report.append(f"  - `{field}`")
                    report.append("")
        else:
            report.append("*Không phát hiện cấu trúc dữ liệu.*")
            report.append("")
    else:
        report.append("*Không phát hiện cấu trúc dữ liệu.*")
        report.append("")

    # ================================================================
    # 7. MÃ NGUỒN (Decompiled)
    # ================================================================
    report.append(_section_header("7. Mã Nguồn & Phân Tích Sâu"))

    if decompiled_code:
        # ELF Header
        if "elf_header" in decompiled_code:
            report.append("**ELF Header:**")
            report.append(f"```\n{decompiled_code['elf_header'][:2000]}\n```")
            report.append("")

        # Sections
        if "sections" in decompiled_code:
            report.append("**Sections:**")
            report.append(f"```\n{decompiled_code['sections'][:3000]}\n```")
            report.append("")

        # Dynamic symbols
        if "dynamic_symbols" in decompiled_code:
            report.append("**Dynamic Symbols (imports):**")
            symbols = decompiled_code["dynamic_symbols"]
            report.append(f"```\n{symbols[:3000]}\n```")
            report.append("")

        # Disassembly
        if "disassembly" in decompiled_code:
            report.append("**Disassembly (sample):**")
            report.append(f"```asm\n{decompiled_code['disassembly'][:5000]}\n```")
            report.append("")

        # Ghidra decompiled functions
        if "ghidra_functions" in decompiled_code:
            report.append(f"**Ghidra Decompiled Functions ({len(decompiled_code['ghidra_functions'])}):**")
            report.append("")
            for func in decompiled_code["ghidra_functions"][:10]:
                name = func.get("name", "")
                addr = func.get("address", "")
                size = func.get("size", 0)
                code = func.get("code", "")
                report.append(f"### `{name}` @ {addr} ({size} bytes)")
                if code:
                    if len(code) > 2000:
                        code = code[:2000] + "\n// ... (đã cắt bớt)"
                    report.append(f"```c\n{code}\n```")
                report.append("")

        if "total_functions" in decompiled_code:
            report.append(f"*Tổng cộng {decompiled_code['total_functions']} functions được phân tích.*")
            report.append("")

        # Package binaries
        if "package_binaries" in decompiled_code:
            report.append(f"**Binaries trong package ({len(decompiled_code['package_binaries'])}):**")
            report.append("")
            for b in decompiled_code["package_binaries"][:10]:
                report.append(f"- `{b.get('path', '')}` — {b.get('file_info', '')[:100]}")
            report.append("")

        # Java classes (APK)
        if "java_classes" in decompiled_code:
            total = decompiled_code.get("total_java_files", 0)
            report.append(f"**Java Classes ({len(decompiled_code['java_classes'])} shown / {total} total):**")
            report.append("")
            for cls in decompiled_code["java_classes"][:10]:
                name = cls.get("name", "")
                code = cls.get("code", "")
                report.append(f"### `{name}`")
                if code:
                    if len(code) > 2000:
                        code = code[:2000] + "\n// ... (đã cắt bớt)"
                    report.append(f"```java\n{code}\n```")
                report.append("")

        # Fallback for old format
        if "classes" in decompiled_code:
            classes = decompiled_code["classes"]
            if classes:
                report.append(f"**Giải mã {len(classes)} classes:**")
                report.append("")
                for cls in classes[:15]:
                    if isinstance(cls, dict):
                        name = cls.get("name", "")
                        report.append(f"### `{name}`")
                        code = cls.get("code", "")
                        if code:
                            if len(code) > 2000:
                                code = code[:2000] + "\n// ... (đã cắt bớt)"
                            report.append(f"```java\n{code}\n```")
                        report.append("")
                    else:
                        report.append(f"- `{cls}`")
    else:
        report.append("*Không có mã nguồn giải mã.*")
        report.append("")

    # ================================================================
    # 8. NETWORK ACTIVITY & DYNAMIC ANALYSIS
    # ================================================================
    report.append(_section_header("8. Network Activity & Dynamic Analysis"))

    if network_activity:
        # Syscalls from dynamic analysis
        if "syscalls" in network_activity:
            report.append("**System Calls (Top 30):**")
            for syscall, count in list(network_activity["syscalls"].items())[:30]:
                report.append(f"  - `{syscall}`: {count}")
            report.append("")

        # Network operations
        if "network_operations" in network_activity:
            report.append("**Network Operations:**")
            for op in network_activity["network_operations"][:20]:
                report.append(f"  - `{op}`")
            report.append("")

        # File operations
        if "file_operations" in network_activity:
            report.append("**File Operations:**")
            for op in network_activity["file_operations"][:20]:
                report.append(f"  - `{op}`")
            report.append("")

        # stdout/stderr
        if "stdout" in network_activity and network_activity["stdout"]:
            report.append("**Program stdout:**")
            report.append(f"```\n{network_activity['stdout'][:2000]}\n```")
            report.append("")

        if "stderr" in network_activity and network_activity["stderr"]:
            report.append("**Program stderr:**")
            report.append(f"```\n{network_activity['stderr'][:2000]}\n```")
            report.append("")

        # Legacy format
        connections = network_activity.get("connections", [])
        domains = network_activity.get("domains", [])
        dns_queries = network_activity.get("dns_queries", [])

        if connections:
            report.append("**Kết nối mạng:**")
            for conn in connections[:20]:
                if isinstance(conn, dict):
                    report.append(f"  - `{conn.get('host', '')}:{conn.get('port', '')}` ({conn.get('protocol', 'TCP')})")
                else:
                    report.append(f"  - `{conn}`")
            report.append("")

        if domains:
            report.append("**Domain truy cập:**")
            for d in domains[:30]:
                report.append(f"  - `{d}`")
            report.append("")

        if not any([connections, domains, dns_queries, "syscalls" in network_activity,
                    "network_operations" in network_activity, "file_operations" in network_activity]):
            report.append("*Không phát hiện hoạt động mạng.*")
            report.append("")
    else:
        report.append("*Không phát hiện hoạt động mạng.*")
        report.append("")

    # ================================================================
    # 9. CẤU HÌNH
    # ================================================================
    report.append(_section_header("9. Cấu Hình"))

    if config_values:
        if isinstance(config_values, dict):
            for key, value in config_values.items():
                if isinstance(value, (dict, list)):
                    report.append(f"- **{key}:**")
                    report.append(f"  ```json\n{json.dumps(value, indent=2, ensure_ascii=False)[:1000]}\n```")
                else:
                    report.append(f"- **{key}:** `{value}`")
            report.append("")
        else:
            report.append("*Không phát hiện cấu hình đặc biệt.*")
            report.append("")
    else:
        report.append("*Không phát hiện cấu hình đặc biệt.*")
        report.append("")

    # ================================================================
    # 10. HƯỚNG DẪN BUILD LẠI
    # ================================================================
    report.append(_section_header("10. Hướng Dẫn Build Lại"))

    report.append("Để tái tạo ứng dụng này, bạn cần:")
    report.append("")

    lang = tech_stack.get("language", "").lower()
    ftype = analysis.file_type.lower() if analysis.file_type else ""

    if "java" in lang or ftype in ("apk", "jar"):
        report.append("**Yêu cầu:**")
        report.append("- JDK 11+ (hoặc Android SDK cho APK)")
        report.append("- Gradle / Maven")
        report.append("- Android Studio (nếu là APK)")
        report.append("")
        report.append("**Bước thực hiện:**")
        report.append("1. Giải mã APK/JAR bằng `jadx` hoặc `apktool`")
        report.append("2. Import project vào Android Studio / IntelliJ IDEA")
        report.append("3. Cài đặt dependencies theo danh sách ở mục 3")
        report.append("4. Build lại bằng Gradle: `./gradlew assembleDebug`")
    elif ".net" in lang or "csharp" in lang:
        report.append("**Yêu cầu:**")
        report.append("- .NET SDK 6+")
        report.append("- Visual Studio 2022 hoặc JetBrains Rider")
        report.append("")
        report.append("**Bước thực hiện:**")
        report.append("1. Giải mã bằng `dnSpy` hoặc `ILSpy`")
        report.append("2. Tạo project mới trong Visual Studio")
        report.append("3. Copy mã nguồn đã giải mã")
        report.append("4. Cài đặt NuGet packages theo danh sách dependencies")
        report.append("5. Build: `dotnet build`")
    elif "python" in lang:
        report.append("**Yêu cầu:**")
        report.append("- Python 3.8+")
        report.append("- pip")
        report.append("")
        report.append("**Bước thực hiện:**")
        report.append("1. Giải mã nếu bị đóng gói (pyinstaller, py2exe)")
        report.append("2. Cài dependencies: `pip install -r requirements.txt`")
        report.append("3. Chạy: `python main.py`")
    elif ftype in ("pe", "exe", "dll"):
        report.append("**Yêu cầu:**")
        report.append("- Ghidra / IDA Pro để phân tích")
        report.append("- Visual Studio (nếu cần rebuild)")
        report.append("")
        report.append("**Bước thực hiện:**")
        report.append("1. Mở file trong Ghidra để phân tích assembly")
        report.append("2. Sử dụng Hex-Rays hoặc Ghidra Decompiler để xem mã C")
        report.append("3. Tạo project mới và reimplement theo mã đã giải mã")
    elif ftype in ("elf",):
        report.append("**Yêu cầu:**")
        report.append("- GCC / G++ toolchain")
        report.append("- Ghidra để phân tích")
        report.append("")
        report.append("**Bước thực hiện:**")
        report.append("1. Phân tích bằng Ghidra")
        report.append("2. Reimplement từ mã C giải mã")
        report.append("3. Compile: `gcc -o output source.c`")
    else:
        report.append("**Yêu cầu:**")
        report.append("- Công cụ reverse engineering phù hợp (Ghidra, IDA Pro, etc.)")
        report.append("- Trình biên dịch/runtime tương ứng")
        report.append("")
        report.append("**Bước thực hiện:**")
        report.append("1. Sử dụng tool phù hợp để phân tích binary")
        report.append("2. Giải mã cấu trúc và logic chương trình")
        report.append("3. Reimplement dựa trên kết quả phân tích")

    report.append("")
    report.append("---")
    report.append(f"*Báo cáo được tạo tự động bởi ReTool v2 — {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")

    report_text = "\n".join(report)

    # Save report to file
    try:
        report_dir = os.path.join(settings.REPORTS_DIR, analysis.id)
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, "report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text)
    except Exception:
        pass

    # Store in DB
    if hasattr(analysis, "ai_summary"):
        analysis.ai_summary = report_text

    return report_text