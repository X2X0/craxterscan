# CraxterScan

`Author: X2X0`  
`Version: 1.0.0`

## Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY, DON'T BE A FUCKING SKID**

This tool is designed exclusively for authorized penetration testing and security assessments. Unauthorized access to computer systems is illegal and punishable under various laws including the Computer Fraud and Abuse Act (CFAA) and similar international legislation.

By using CraxterScan, you acknowledge that:
- You have **explicit written authorization** to test the target systems
- You understand that unauthorized scanning is **illegal**
- All actions performed by this tool are **logged for audit purposes**
- The author is **not responsible** for any misuse of this tool

## Description

CraxterScan is a comprehensive network reconnaissance tool that automates the initial phases of penetration testing. It performs host discovery, port scanning, service enumeration, banner grabbing, and web technology detection, generating detailed reports in both JSON and HTML formats.

## Features

- **Host Discovery**: Identify active hosts within a specified IP range
- **Port Scanning**: Enumerate open ports with customizable ranges
- **Service Enumeration**: Detect running services and versions
- **Banner Grabbing**: Capture service banners for version identification
- **Web Technology Detection**: Identify CMS, frameworks, and web technologies
- **Dual Scan Modes**: Choose between stealth and aggressive scanning
- **Rate Limiting**: Prevent network saturation and detection
- **Comprehensive Logging**: Detailed audit trail of all actions
- **Multiple Report Formats**: Generate HTML and JSON reports
- **Authorization Verification**: Built-in scope verification system

## Requirements

### System Requirements
- Python 3.7 or up
- Linux/Unix system (Windows sucks)
- WIFI to fuck systems
- Root/Administrator

### Python Dependencies

```bash
pip install requests
```

### System Dependencies

The tool uses standard system utilities that should be available on most Unix-like systems:
- `ping` - For host discovery
- `socket` - Built-in Python module for network operations

## Installation

```bash
git clone https://github.com/X2X0/craxterscan.git
cd craxterscan
chmod +x craxterscan.py
pip install -r requirements.txt
```

## Usage

### skid Usage

```bash
python3 craxterscan.py -t 192.168.1.1-254
```

### red teaming Usage

```bash
python3 craxterscan.py -t 192.168.1.1-254 -m aggressive -p 1-10000 -o results
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target` | Target IP or range (required) | - |
| `-m, --mode` | Scan mode: `stealth` or `aggressive` | `stealth` |
| `-p, --ports` | Custom port range (e.g., 1-1000) | Common ports |
| `-o, --output` | Output directory for reports | `output` |
| `--skip-auth` | Skip authorization check (use responsibly) | False |

### Target Format Examples

```bash
192.168.1.1-254
10.0.0.1-50
172.16.0.1-100
```

## Scan Modes

### Stealth Mode (Default)
- Slower scan speed like shit with rate limiting
- Limited port range (common ports only)
- Reduced thread count lol
- Lower detection probability
- Recommended for covert assessments

### Aggressive Mode
- Faster scan speed
- Extended port range (1-1000 by default)
- Higher thread count
- More comprehensive results
- Higher detection probability lol

## Output Files

The tool generates three output files per scan:

1. **JSON Report**: Machine-readable results for integration with other tools
2. **HTML Report**: Human-readable report with formatted tables and styling
3. **Log File**: Detailed audit trail of all actions performed

### Output Structure

```
output/
├── craxterscan_20241024_143022.json
├── craxterscan_20241024_143022.html
└── craxterscan_20241024_143022.log
```

## Example Scenarios

### Scenario 1: Quick

```bash
python3 craxterscan.py -t 192.168.1.1-254 -m stealth
```

### Scenario 2: Deep Scan

```bash
python3 craxterscan.py -t 10.0.0.50 -m aggressive -p 1-65535
```

### Scenario 3: Web App Assessment

```bash
python3 craxterscan.py -t 192.168.1.100 -p 80,443,8080,8443
```

## What Gets Detected XD

### Network Services
- FTP (21)
- SSH (22)
- Telnet (23)
- SMTP (25)
- DNS (53)
- HTTP (80)
- POP3 (110)
- IMAP (143)
- HTTPS (443)
- SMB (445)
- MySQL (3306)
- RDP (3389)
- VNC (5900)
- HTTP Proxies (8080, 8443)

### Web Technologies
- **CMS**: WordPress, Joomla, Drupal
- **Frameworks**: React, Angular, Vue.js
- **Libraries**: jQuery, Bootstrap
- **Server Information**: Apache, Nginx, IIS, etc.
- **HTTP Headers**: Server types, powered-by headers

## Report Interpretation

### JSON Report Structure

```json
{
  "metadata": {
    "timestamp": "2024-10-24T14:30:22",
    "target": "192.168.1.1-254",
    "scan_mode": "stealth"
  },
  "hosts": {
    "192.168.1.100": {
      "ports": [
        {
          "port": 80,
          "service": "HTTP",
          "banner": "Apache/2.4.41",
          "version": "Apache/2.4.41"
        }
      ],
      "web_technologies": [...]
    }
  }
}
```

## Troubleshooting

### Common Issues

**Problem**: "Permission denied" errors  
**Solution**: Run with sudo/root skid

**Problem**: No hosts discovered  
**Solution**: Verify network connectivity and firewall rules...

**Problem**: Timeout errors  
**Solution**: Increase timeout values or use stealth mode

**Problem**: Import errors  
**Solution**: Ensure all dependencies are installed

## License

This tool is provided for red teaming and OFFsec shit, don't be a skid. (MIT license)

## Contact

For questions, suggestions, or security concerns, contact me or get lost .
