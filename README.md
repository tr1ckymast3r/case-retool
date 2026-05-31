# ReTool v2 — Reverse Engineering Analysis Platform

Phân tích phần mềm đối thủ: bóc tách cơ chế hoạt động, dependencies, cấu trúc dữ liệu. Hỗ trợ đa nền tảng (Windows, Linux, macOS, Android, iOS).

## URL

```
http://100.87.34.74:3010
```

## Hỗ trợ file types

| Loại file | Định dạng | Công cụ phân tích |
|-----------|-----------|-------------------|
| Linux Binary | ELF, SO | readelf, objdump, nm, ldd, strings |
| Windows Binary | PE, DLL, .NET | pefile, strings |
| Debian Package | .deb (gz/xz/zst) | ar, tar, dpkg |
| Android App | .apk | apktool, jadx |
| iOS App | .ipa | unzip, plist parsing |
| macOS Binary | Mach-O | file, strings |
| Java Archive | .jar | unzip, strings |
| RPM Package | .rpm | rpm2cpio |
| Scripts | .sh, .py, .js | shebang detection |

## Architecture

2-container Docker architecture:

- **app** — FastAPI + React SPA (port 3010, lightweight)
- **worker** — Ubuntu 22.04 + Ghidra + Frida + radare2 + jadx + apktool + strace (heavy RE tools)

Shared volume `/data` connects both containers for task dispatch and result collection.

## Features

- Upload file → auto-detect type → local analysis → worker deep analysis
- Vietnamese report with: ELF headers, sections, disassembly, dynamic symbols, dependencies
- DEB package analysis: control, install scripts, file list, binary detection
- APK analysis: permissions, activities, services, jadx decompile
- Ghidra headless decompile (deep_static/full profile)
- Dynamic analysis: strace, network capture (dynamic/full profile)
- Hash: MD5, SHA1, SHA256
- String extraction: URLs, IPs, emails, registry keys, API keys, suspicious patterns

## Quick Start

```bash
docker compose up -d --build
```

App: http://localhost:3010
API docs: http://localhost:3010/docs

## API

```bash
# Upload file
curl -X POST http://localhost:3010/api/upload \
  -F "file=@target.deb;filename=target.deb" \
  -F "profile=quick_scan"

# List analyses
curl http://localhost:3010/api/analyses

# Get analysis detail
curl http://localhost:3010/api/analyses/{id}

# Re-analyze
curl -X POST http://localhost:3010/api/analyses/{id}/reanalyze
```

## Profiles

| Profile | Mô tả |
|---------|-------|
| `quick_scan` | Local analysis + worker basic (default) |
| `deep_static` | + Ghidra decompile |
| `dynamic` | + strace, network capture |
| `full` | Tất cả |

## Stack

- **Backend:** FastAPI, SQLAlchemy, SQLite
- **Frontend:** React SPA (single HTML)
- **Worker:** Python3, Ghidra 11.3.2, Frida 16.5.6, radare2, jadx 1.5.1, apktool 2.10.0
- **Infra:** Docker Compose, shared volume
