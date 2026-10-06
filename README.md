# Security Toolkit MCP Server

A Model Context Protocol (MCP) server providing essential security and CTF tools directly through AI assistants. Perfect for beginners learning Capture The Flag challenges and security testing.

## Overview

This MCP server integrates powerful security tools into your AI workflow, making it easier to solve CTF challenges without memorizing complex commands. It's designed for beginners who want to learn security concepts while having helpful tools at their fingertips.

## Features

### Cryptography & Encoding Tools
- **Hash Identification** - Identify hash types (MD5, SHA-1, SHA-256, SHA-512, bcrypt, NTLM)
- **Multi-format Decoder** - Decode Base64, Hex, URL, ROT13, and Binary strings
- **XOR Bruteforce** - Crack XOR-encrypted data with single or multi-byte keys
- **Frequency Analysis** - Analyze substitution ciphers using letter frequency
- **JWT Decoder** - Decode and inspect JSON Web Tokens

### Exploitation Tools
- **Reverse Shell Generator** - Generate payloads for Bash, Python, PHP, Perl, Ruby, and Netcat
- **SQL Injection Payloads** - Get SQLi payloads (basic, union, blind, error-based, time-based)

### Information Gathering
- **CVE Lookup** - Fetch vulnerability details from the National Vulnerability Database
- **Port Service Lookup** - Identify common services running on specific ports

## Prerequisites

- Python 3.10 or higher (required by the `mcp` SDK)
- An MCP-compatible AI client (Claude Desktop, Cline, etc.)

## Installation

### Step 1: Setup

```bash
# Clone or download this repository
cd ctf-mcp

# Install dependencies (either way works)
pip install -r requirements.txt
# or
pip install mcp requests
```

### Step 2: Configure Your AI Client

#### For Claude Desktop

Add to your `claude_desktop_config.json`:

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`  
**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "security-toolkit": {
      "command": "python",
      "args": ["/absolute/path/to/server.py"]
    }
  }
}
```

#### For Cline (VS Code Extension)

Add to Cline MCP Settings:

```json
{
  "mcpServers": {
    "security-toolkit": {
      "command": "python",
      "args": ["/absolute/path/to/server.py"]
    }
  }
}
```

### Step 3: Restart Your AI Client

Restart Claude Desktop or reload VS Code to load the MCP server.

> **Windows tip**: in your client config, point `command` to the full path of the Python executable that has the dependencies installed (for example `D:\\Python\\Python313\\python.exe`). Wrapper scripts such as `.bat` files or shell aliases may not work with some MCP clients.

## Usage Examples

Once configured, you can ask your AI assistant to use these tools naturally:

### Hash Identification
```
"What type of hash is 5d41402abc4b2a76b9719d911017c592?"
```

### Decoding Strings
```
"Decode this base64: SGVsbG8gV29ybGQh"
"Decode this hex string: 48656c6c6f"
```

### XOR Bruteforce
```
"Try to decrypt this XOR-encrypted hex: 1c0e1a0a1f"
```

### Frequency Analysis
```
"Perform frequency analysis on this ciphertext: KHOOR ZRUOG"
```

### JWT Decoding
```
"Decode this JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Reverse Shells
```
"Generate a Python reverse shell for 10.10.14.5 port 4444"
"Give me all reverse shell options for 192.168.1.10:9001"
```

### SQL Injection
```
"Show me union-based SQL injection payloads"
"What are some time-based blind SQLi payloads?"
```

### CVE Lookup
```
"Look up CVE-2024-1234"
"What vulnerabilities are associated with CVE-2021-44228?"
```

### Port Identification
```
"What service typically runs on port 3306?"
"Identify port 5432"
```

## Available Tools Reference

| Tool | Description | CTF Use Cases |
|------|-------------|---------------|
| `hash_identifier` | Identifies hash types | Web challenges, password cracking |
| `decode_string` | Decodes various formats | Steganography, crypto challenges |
| `xor_bruteforce` | Cracks XOR encryption | Crypto challenges |
| `frequency_analysis` | Analyzes cipher patterns | Classical crypto |
| `jwt_decode` | Decodes JWT tokens | Web exploitation |
| `reverse_shell_generator` | Creates reverse shells | Post-exploitation, pwn |
| `sqli_payloads` | SQL injection templates | Web challenges |
| `cve_lookup` | Fetches CVE details | Real-world vuln research |
| `port_service_lookup` | Identifies port services | Reconnaissance, enumeration |

## Learning Resources for Beginners

### Recommended CTF Platforms
- **PicoCTF** - Beginner-friendly CTF platform with guided challenges
- **OverTheWire** - Progressive wargames for learning security concepts
- **TryHackMe** - Guided cybersecurity training with virtual labs
- **HackTheBox Academy** - Structured learning paths for various security topics

### Understanding the Tools
- **Hash Identification**: Learn about different hash algorithms and their characteristics
- **Encoding vs Encryption**: Understand the difference (encoding is reversible without a key)
- **XOR Cipher**: A simple but common encryption method frequently used in CTFs
- **SQL Injection**: One of the most common web vulnerabilities in real-world applications

## Security and Legal Notice

### Educational Use Only

This tool is designed for:
- Learning cybersecurity concepts
- Authorized CTF competitions
- Legal penetration testing with explicit permission
- Testing your own systems and networks

### Prohibited Uses

Do NOT use this tool for:
- Unauthorized access to systems
- Illegal hacking activities
- Testing systems without explicit permission
- Any malicious purposes

**Always obtain proper written authorization before testing any system you don't own.**

## Troubleshooting

### MCP Server Not Loading
1. Verify Python is in your system PATH
2. Check that the absolute path to `server.py` is correct
3. Ensure all dependencies are installed: `pip install mcp requests`
4. Review the AI client logs for error messages
5. Confirm you're using Python 3.10 or higher

### Tool Not Responding
1. Restart your AI client after making configuration changes
2. Verify the server is listed in your MCP settings
3. Check terminal/console output for error messages
4. Ensure no firewall is blocking the MCP connection

### CVE Lookup Issues
- The National Vulnerability Database API may have rate limits
- Ensure you have an active internet connection
- Verify the CVE ID format follows the pattern: CVE-YYYY-NNNNN
- Some CVEs may not be available if recently published

## Technical Details

### Dependencies
- `mcp` - Model Context Protocol framework (supports both v1.x FastMCP and v2.x MCPServer)
- `requests` - HTTP library for CVE lookups

### Architecture
The server uses the `mcp` SDK (`FastMCP` in v1.x, renamed `MCPServer` in v2.x — both are supported) to expose security tools as callable functions through the MCP protocol. Each tool is implemented as a decorated function that returns JSON-formatted results, and the server runs over the stdio transport.

## Why Use MCP for Security Tools?

The Model Context Protocol integration provides several advantages:

- **Context Awareness** - AI assistants maintain conversation context across multiple tool uses
- **Intelligent Chaining** - Tools can be combined automatically (decode, then identify, then crack)
- **Natural Language Interface** - No need to memorize command syntax or flags
- **Educational Explanations** - AI can explain results in beginner-friendly terms
- **Adaptive Guidance** - Suggestions for next steps based on tool outputs

This approach is particularly effective for learning security concepts while building practical skills.

## Contributing

Contributions are welcome. When adding new tools or features:
- Maintain clear, beginner-friendly documentation
- Focus on educational value
- Include usage examples
- Add explanations for complex security concepts
- Follow existing code style and patterns

## License

This project is provided for educational purposes. Users are responsible for ensuring their use complies with applicable laws and regulations.

## Best Practices for CTF Beginners

1. **Start Simple** - Begin with easier CTF challenges and gradually increase difficulty
2. **Understand, Don't Just Use** - Learn why tools work, not just how to use them
3. **Document Your Process** - Keep notes on what worked and what didn't
4. **Read Write-ups** - After solving (or attempting) challenges, read other solutions
5. **Practice Regularly** - Consistent practice is key to improving security skills
6. **Join Communities** - Engage with CTF communities on Discord, Reddit, or forums
7. **Ask Questions** - Use the AI assistant to explain concepts you don't understand

## Getting Help

- Ask your AI assistant to use these tools and explain the results in detail
- Request step-by-step explanations of security concepts
- Have the AI suggest alternative approaches when stuck on challenges
- Use the AI to learn the theory behind each tool and technique

---

**Remember**: Ethical hacking requires permission. Always operate within legal boundaries and respect system owners' rights.
