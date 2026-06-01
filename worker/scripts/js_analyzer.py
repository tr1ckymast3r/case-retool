"""
JavaScript Deep Analyzer — extracts functions, APIs, IPC handlers, crypto, etc.
Works with Python regex (no Node.js dependency).
"""

import re
import json
import os


def analyze_js_deep(filepath, output=None):
    """Deep analysis of JavaScript/Node.js files."""
    try:
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()
    except Exception as e:
        return {"error": str(e)}

    fname = os.path.basename(filepath)
    result = {
        "filename": fname,
        "size": len(content),
        "lines": content.count('\n') + 1,
        "functions": [],
        "classes": [],
        "ipc_handlers": [],
        "http_routes": [],
        "crypto_ops": [],
        "api_keys": [],
        "config_vars": [],
        "imports": [],
        "exports": [],
        "env_vars": [],
        "suspicious": [],
        "evidence_sources": [],
        "summary": "",
    }

    lines = content.split('\n')

    # ═══════════════════════════════════════════════════
    # 1. FUNCTION DECLARATIONS
    # ═══════════════════════════════════════════════════
    # Named function declarations
    for m in re.finditer(r'(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)', content):
        fn_name = m.group(1)
        params = m.group(2).strip()
        line_no = content[:m.start()].count('\n') + 1
        # Get first 3 lines of function body
        body_start = content.find('{', m.end())
        if body_start >= 0:
            body_preview = _extract_block_preview(content, body_start, max_lines=3)
        else:
            body_preview = ""
        result["functions"].append({
            "name": fn_name,
            "params": params,
            "line": line_no,
            "async": m.group(0).startswith('async'),
            "body_preview": body_preview,
        })

    # Arrow functions / const assignments
    for m in re.finditer(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>', content):
        fn_name = m.group(1)
        params = m.group(2).strip()
        line_no = content[:m.start()].count('\n') + 1
        result["functions"].append({
            "name": fn_name,
            "params": params,
            "line": line_no,
            "async": 'async' in m.group(0),
            "type": "arrow",
        })

    # Object method definitions: methodName(params) {
    for m in re.finditer(r'^\s{2,}(\w+)\s*\(([^)]*)\)\s*\{', content, re.MULTILINE):
        fn_name = m.group(1)
        if fn_name in ('if', 'for', 'while', 'switch', 'catch', 'try', 'else'):
            continue
        params = m.group(2).strip()
        line_no = content[:m.start()].count('\n') + 1
        # Avoid duplicates
        if not any(f['name'] == fn_name and f['line'] == line_no for f in result["functions"]):
            result["functions"].append({
                "name": fn_name,
                "params": params,
                "line": line_no,
                "type": "method",
            })

    # ═══════════════════════════════════════════════════
    # 2. ELECTRON IPC HANDLERS
    # ═══════════════════════════════════════════════════
    for m in re.finditer(r'ipcMain\.(handle|on|once)\s*\(\s*[\'"]([^\'"]+)[\'"]', content):
        handler_type = m.group(1)
        channel = m.group(2)
        line_no = content[:m.start()].count('\n') + 1
        # Get callback preview
        cb_start = content.find(')', m.end())
        cb_preview = content[cb_start+1:cb_start+200].strip()[:150]
        result["ipc_handlers"].append({
            "type": handler_type,
            "channel": channel,
            "line": line_no,
            "preview": cb_preview,
        })

    # ipcRenderer.send/invoke
    for m in re.finditer(r'ipcRenderer\.(send|invoke|on)\s*\(\s*[\'"]([^\'"]+)[\'"]', content):
        line_no = content[:m.start()].count('\n') + 1
        result["ipc_handlers"].append({
            "type": f"renderer.{m.group(1)}",
            "channel": m.group(2),
            "line": line_no,
        })

    # ═══════════════════════════════════════════════════
    # 3. HTTP ROUTES / API ENDPOINTS
    # ═══════════════════════════════════════════════════
    # Express-style: app.get/post/put/delete/use('/path', ...)
    for m in re.finditer(r'(?:app|router|server)\.(get|post|put|delete|patch|use|all)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', content):
        method = m.group(1).upper()
        path = m.group(2)
        line_no = content[:m.start()].count('\n') + 1
        result["http_routes"].append({
            "method": method,
            "path": path,
            "line": line_no,
        })

    # http.createServer / req.method + pathname checks
    for m in re.finditer(r'pathname\s*===?\s*[\'"`]([^\'"`]+)[\'"`]', content):
        path = m.group(1)
        line_no = content[:m.start()].count('\n') + 1
        if path.startswith('/'):
            result["http_routes"].append({
                "method": "GET/POST",
                "path": path,
                "line": line_no,
                "source": "pathname_check",
            })

    # req.method === 'GET' / 'POST' near pathname
    for m in re.finditer(r'req\.method\s*===?\s*[\'"`](\w+)[\'"`]', content):
        method = m.group(1)
        line_no = content[:m.start()].count('\n') + 1
        # Find nearest pathname
        ctx_start = max(0, m.start() - 500)
        ctx = content[ctx_start:m.start()]
        pm = re.findall(r'pathname\s*===?\s*[\'"`]([^\'"`]+)[\'"`]', ctx)
        if pm:
            result["http_routes"].append({
                "method": method,
                "path": pm[-1],
                "line": line_no,
            })

    # ═══════════════════════════════════════════════════
    # 4. CRYPTO OPERATIONS
    # ═══════════════════════════════════════════════════
    crypto_patterns = [
        (r'crypto\.createCipheriv', 'createCipheriv'),
        (r'crypto\.createDecipheriv', 'createDecipheriv'),
        (r'crypto\.createHash', 'createHash'),
        (r'crypto\.createHmac', 'createHmac'),
        (r'crypto\.randomBytes', 'randomBytes'),
        (r'crypto\.publicEncrypt', 'publicEncrypt'),
        (r'crypto\.privateDecrypt', 'privateDecrypt'),
        (r'crypto\.sign', 'sign'),
        (r'crypto\.verify', 'verify'),
        (r'crypto\.generateKeyPair', 'generateKeyPair'),
        (r'AES', 'AES'),
        (r'RSA', 'RSA'),
        (r'SHA256|SHA-256', 'SHA-256'),
        (r'SHA512|SHA-512', 'SHA-512'),
        (r'MD5', 'MD5'),
        (r'hmac', 'HMAC'),
        (r'bcrypt', 'bcrypt'),
    ]
    for pattern, name in crypto_patterns:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            line_no = content[:m.start()].count('\n') + 1
            line_text = lines[line_no-1].strip() if line_no <= len(lines) else ""
            result["crypto_ops"].append({
                "operation": name,
                "line": line_no,
                "context": line_text[:120],
            })

    # ═══════════════════════════════════════════════════
    # 5. API KEYS / SECRETS / TOKENS
    # ═══════════════════════════════════════════════════
    key_patterns = [
        r'(?:api[_-]?key|apikey|secret|token|password|passwd|auth|credential|private[_-]?key)\s*[:=]\s*[\'"`]([^\'"`]{8,})[\'"`]',
        r'(?:ENCRYPTION[_-]?KEY|SIGNATURE[_-]?KEY|SECRET[_-]?KEY|JWT[_-]?SECRET)\s*[:=]\s*[\'"`]([^\'"`]{8,})[\'"`]',
        r'(?:ADMIN[_-]?(?:PASSWORD|USER|PASS))\s*[:=]\s*[\'"`]([^\'"`]{4,})[\'"`]',
    ]
    for pattern in key_patterns:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            line_no = content[:m.start()].count('\n') + 1
            line_text = lines[line_no-1].strip() if line_no <= len(lines) else ""
            # Redact value partially
            val = m.group(1)
            redacted = val[:4] + '***' + val[-4:] if len(val) > 8 else '***'
            result["api_keys"].append({
                "type": _classify_secret(line_text),
                "value_preview": redacted,
                "line": line_no,
                "context": line_text[:150],
            })

    # ═══════════════════════════════════════════════════
    # 6. CONFIG VARIABLES
    # ═══════════════════════════════════════════════════
    for m in re.finditer(r'(?:const|let|var)\s+(CONFIG|config|CONFIGURATION|settings|SETTINGS|options|OPTIONS)\s*=\s*\{', content):
        var_name = m.group(1)
        line_no = content[:m.start()].count('\n') + 1
        block_start = content.find('{', m.end())
        if block_start >= 0:
            block_preview = _extract_block_preview(content, block_start, max_lines=20)
        else:
            block_preview = ""
        result["config_vars"].append({
            "name": var_name,
            "line": line_no,
            "preview": block_preview,
        })

    # ═══════════════════════════════════════════════════
    # 7. IMPORTS / REQUIRES
    # ═══════════════════════════════════════════════════
    for m in re.finditer(r'require\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*\)', content):
        module = m.group(1)
        if not module.startswith('.'):
            result["imports"].append(module)

    for m in re.finditer(r'import\s+.*?from\s+[\'"`]([^\'"`]+)[\'"`]', content):
        module = m.group(1)
        if not module.startswith('.'):
            result["imports"].append(module)

    # Deduplicate imports
    result["imports"] = list(dict.fromkeys(result["imports"]))

    # ═══════════════════════════════════════════════════
    # 8. ENV VARS
    # ═══════════════════════════════════════════════════
    for m in re.finditer(r'process\.env\.(\w+)', content):
        var = m.group(1)
        line_no = content[:m.start()].count('\n') + 1
        result["env_vars"].append({"name": var, "line": line_no})
    result["env_vars"] = list({v['name']: v for v in result["env_vars"]}.values())

    # ═══════════════════════════════════════════════════
    # 9. SUSPICIOUS PATTERNS
    # ═══════════════════════════════════════════════════
    suspicious_patterns = [
        (r'eval\s*\(', 'eval() — code execution'),
        (r'exec\s*\(', 'exec() — command execution'),
        (r'execSync\s*\(', 'execSync() — sync command execution'),
        (r'spawn\s*\(', 'spawn() — process spawning'),
        (r'child_process', 'child_process — subprocess'),
        (r'fs\.writeFileSync', 'writeFileSync — file write'),
        (r'fs\.unlinkSync', 'unlinkSync — file delete'),
        (r'fs\.chmod', 'chmod — permission change'),
        (r'net\.createConnection', 'createConnection — network'),
        (r'dgram\.createSocket', 'createSocket — UDP'),
        (r'new\s+WebSocket', 'WebSocket — real-time connection'),
        (r'navigator\.userAgent', 'User-Agent access'),
        (r'screen\.(width|height)', 'Screen resolution access'),
        (r'WebGL', 'WebGL fingerprinting'),
        (r'canvas\.toDataURL', 'Canvas fingerprinting'),
        (r'AudioContext', 'Audio fingerprinting'),
        (r'hardwareConcurrency', 'CPU cores detection'),
        (r'deviceMemory', 'Device memory detection'),
        (r'fingerprint', 'Fingerprinting'),
        (r'puppeteer|playwright', 'Browser automation'),
        (r'headless', 'Headless browser'),
        (r'proxy', 'Proxy usage'),
        (r'timeout|setTimeout|setInterval', 'Timer operations'),
    ]
    for pattern, desc in suspicious_patterns:
        matches = list(re.finditer(pattern, content, re.IGNORECASE))
        if matches:
            for m in matches[:3]:  # Max 3 per pattern
                line_no = content[:m.start()].count('\n') + 1
                result["suspicious"].append({
                    "pattern": desc,
                    "line": line_no,
                    "count": len(matches),
                })

    # ═══════════════════════════════════════════════════
    # 10. EVIDENCE SOURCES (URLs, domains)
    # ═══════════════════════════════════════════════════
    for m in re.finditer(r'https?://[^\s\'"`<>]+', content):
        url = m.group(0).rstrip('.,;:')
        line_no = content[:m.start()].count('\n') + 1
        result["evidence_sources"].append({"url": url, "line": line_no})
    result["evidence_sources"] = list({v['url']: v for v in result["evidence_sources"]}.values())

    # ═══════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════
    result["summary"] = (
        f"JS file: {result['lines']} lines, {len(result['functions'])} functions, "
        f"{len(result['http_routes'])} routes, {len(result['ipc_handlers'])} IPC handlers, "
        f"{len(result['crypto_ops'])} crypto ops, {len(result['api_keys'])} secrets, "
        f"{len(result['suspicious'])} suspicious patterns"
    )

    return result


def _extract_block_preview(content, brace_pos, max_lines=5):
    """Extract first N lines after opening brace."""
    after = content[brace_pos+1:]
    lines = after.split('\n')
    preview_lines = []
    depth = 1
    for line in lines[:max_lines * 3]:
        depth += line.count('{') - line.count('}')
        preview_lines.append(line)
        if depth <= 0 or len(preview_lines) >= max_lines:
            break
    return '\n'.join(preview_lines)[:500]


def _classify_secret(line_text):
    """Classify what kind of secret this is."""
    lower = line_text.lower()
    if 'encryption' in lower or 'encrypt' in lower:
        return 'Encryption Key'
    if 'signature' in lower or 'sign' in lower:
        return 'Signature Key'
    if 'admin' in lower or 'password' in lower or 'passwd' in lower:
        return 'Admin Credential'
    if 'token' in lower or 'jwt' in lower:
        return 'Token'
    if 'api' in lower or 'key' in lower:
        return 'API Key'
    if 'secret' in lower:
        return 'Secret'
    return 'Credential'
