<div align="center">

# IP Blacklist Checker

A comprehensive tool for checking IP addresses against multiple DNS blacklists to assess their reputation and trustworthiness.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
[![GitHub Stars](https://img.shields.io/github/stars/yourusername/ip-blacklist-checker?style=social)](https://github.com/yourusername/ip-blacklist-checker/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/yourusername/ip-blacklist-checker)](https://github.com/yourusername/ip-blacklist-checker/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/yourusername/ip-blacklist-checker)](https://github.com/yourusername/ip-blacklist-checker/pulls)

</div>

<div align="center">

```
 ▄▄▄▄    ██▓    ▄▄▄       ▄████▄   ██ ▄█▀ ██▓     ██▓  ██████ ▄▄▄█████▓
▓█████▄ ▓██▒   ▒████▄    ▒██▀ ▀█   ██▄█▒ ▓██▒    ▓██▒▒██    ▒ ▓  ██▒ ▓▒
▒██▒ ▄██▒██░   ▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒██░    ▒██▒░ ▓██▄   ▒ ▓██░ ▒░
▒██░█▀  ▒██░   ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒██░    ░██░  ▒   ██▒░ ▓██▓ ░ 
░▓█  ▀█▓░██████▒▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░██████▒░██░▒██████▒▒  ▒██▒ ░ 
░▒▓███▀▒░ ▒░▓  ░▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░ ▒░▓  ░░▓  ▒ ▒▓▒ ▒ ░  ▒ ░░   
▒░▒   ░ ░ ░ ▒  ░ ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░░ ░ ▒  ░ ▒ ░░ ░▒  ░ ░    ░    
 ░    ░   ░ ░    ░   ▒   ░        ░ ░░ ░   ░ ░    ▒ ░░  ░  ░    ░      
 ░          ░  ░     ░  ░░ ░      ░  ░       ░  ░ ░        ░           
```

</div>

## Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Testing](#-testing)
- [Trust Score System](#-trust-score-system)
- [Ethical Usage](#-ethical-usage)
- [Known Issues](#-known-issues)
- [Version History](#-version-history)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgements](#-acknowledgements)

## 📋 Overview

IP Blacklist Checker is a powerful utility that allows you to quickly check if an IP address appears on any of 70+ known DNS blacklists, helping you determine if an IP address has been associated with spam, malicious activity, or other problematic behavior. The tool is available in both Python and Bash implementations, with enhanced visual presentation in the Python version.

## ✨ Features

### Common Features (Both Versions)

- Checks IP addresses against 70+ DNS blacklists
- Provides a comprehensive trust score based on blacklist appearances
- Shows detailed results of each blacklist check
- Groups blacklists into logical categories
- Calculates a trust score using a progressive penalty system
- Provides visual representation of trust levels
- Works with IPv4 addresses

### Python Version Features

- Rich, colorful terminal output with tables and panels
- Live progress bar during blacklist checks
- Categorized results with visual indicators
- Enhanced trust score visualization
- Detailed summary with category-specific statistics
- Graceful handling of missing dependencies
- More maintainable and modular code structure

### Bash Version Features

- Works without any additional dependencies
- Lightweight with minimal system requirements
- ASCII art header and Unicode box borders
- Color-coded results with visual indicators (✓/✗)
  - Trust score visualization with color gradients
  - Compatible with virtually any Unix-like system

## 🚀 Quick Start

Check an IP address against blacklists instantly:

```python
# Example code block for checking IP
python3 check_ip_blacklist.py 1.1.1.1
```

## 🖥️ Example Output

When you run the IP Blacklist Checker, you'll get a rich, color-coded output that provides detailed information about the IP's reputation. Here's an example of checking Google's DNS server (8.8.8.8):

```
╭────────────────────────────────── IP Blacklist Checker ───────────────────────────────────╮
│                                                                                           │
│                        Checking 8.8.8.8 against 72 DNS blacklists                         │
│                                                                                           │
╰───────────────────────────────────────────────────────────────────────────────────────────╯
[■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■] 72/72 100% • 0:00:10 remaining

╭─────────────────────────────────── Results Summary ────────────────────────────────────────╮
│ IP: 8.8.8.8 (Google LLC)                                                                   │
│                                                                                            │
│ ✅ Trust Score: 97% (Highly Trusted)                                                       │
│ ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫                         │
│                                                                                            │
│ 🔍 Results: Listed on 1 out of 72 blacklists checked                                       │
╰────────────────────────────────────────────────────────────────────────────────────────────╯

╭───────────────────────────────────── Spam Lists ─────────────────────────────────────────────╮
│ ✅ spamhaus.org                 ✅ spamcop.net                  ✅ spam.spamrats.com         │
│ ✅ l2.apews.org                 ✅ bl.mailspike.net             ✅ safe.dnsbl.sorbs.net      │
│ ✅ ix.dnsbl.manitu.net          ✅ b.barracudacentral.org       ✅ bl.blocklist.de           │
│ ✅ bl.spamcop.net               ✅ dnsbl.dronebl.org            ✅ bl.spameatingmonkey.net   │
│ ✅ bl.nszones.com               ✅ all.s5h.net                  ✅ z.mailspike.net           │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯

╭───────────────────────────────── Malware/Exploit Lists ──────────────────────────────────────╮
│ ✅ dnsbl-1.uceprotect.net       ✅ dnsbl-2.uceprotect.net       ✅ dnsbl-3.uceprotect.net    │
│ ✅ dnsbl.abuse.ch               ✅ all.s5h.net                  ✅ db.wpbl.info              │
│ ✅ combined.njabl.org           ✅ psbl.surriel.com             ✅ ubl.unsubscore.com        │
│ ✅ dnsbl.justspam.org           ✅ bogons.cymru.com             ✅ karmasphere.email         │
│ ✅ hostkarma.junkemailfilter.com                                                             │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯

╭─────────────────────────────────── Policy/Open Proxy Lists ──────────────────────────────────╮
│ ✅ dnsbl.spfbl.net              ✅ zen.spamhaus.org             ✅ truncate.gbudb.net        │
│ ✅ bl.deadbeef.com              ✅ bl.spamcannibal.org          ✅ dyna.spamrats.com         │
│ ✅ noptr.spamrats.com           ✅ spam.dnsbl.anonmails.de      ✅ bl.mailspike.net          │
│ ✅ bl.nosolicitado.org          ✅ b.barracudacentral.org       ✅ bl.blocklist.de           │
│ ✅ dnsbl.zapbl.net              ✅ list.blogspambl.com          ✅ all.s5h.net               │
│ ❌ pbl.spamhaus.org             ✅ inbox.dnsbl.inc              ✅ srnblack.surgate.net      │
│ ✅ spam.dnsbl.sorbs.net         ✅ bl.score.senderscore.com     ✅ korea.services.net        │
│ ✅ dul.blackhole.cantv.net      ✅ mail-abuse.blackhole.mx      ✅ bl.tiopan.com             │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
```

### Understanding the Output

The output is divided into several sections:

1. **Header**: Shows the tool name and confirmation of which IP is being checked against how many blacklists
2. **Progress Bar**: Displays real-time progress of the blacklist checks
3. **Results Summary**: 
   - Shows the IP address and its owner (if available)
   - Displays the trust score with a visual meter
   - Indicates how many blacklists flagged the IP
4. **Categorized Results**: Groups blacklists by type:
   - ✅ Green checkmarks indicate the IP is not listed (good)
   - ❌ Red X marks indicate the IP is listed on that blacklist (bad)

The example above shows Google's DNS server (8.8.8.8) has a very high trust score of 97%, appearing on only 1 out of 72 blacklists, making it "Highly Trusted" according to the scoring system.

## 🔧 Requirements

- Python 3.8+
- For the Bash version: Any Unix-like operating system with `bash` and standard Unix utilities
- For the Python version:
  - The `rich` library (optional, for enhanced output)
- coreutils
- curl
- jq (for test scripts)

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/fredycibersec/ip-blacklist-checker.git
   cd ip-blacklist-checker
   ```

2. Make the scripts executable:
   ```bash
   chmod +x check_ip_blacklist.sh
   chmod +x check_ip_blacklist.py
   ```

3. For the Python version, install the rich library (optional but recommended):
   ```bash
   pip install rich
   ```

## 🔍 Usage

### Bash Version

```bash
./check_ip_blacklist.sh <ip_address>
```

Example:
```bash
./check_ip_blacklist.sh 8.8.8.8
```

### Python Version

```bash
python3 check_ip_blacklist.py <ip_address>
```

Example:
```bash
python3 check_ip_blacklist.py 8.8.8.8
```

## 🧪 Testing

To test the blacklist checker against multiple sample IPs:

```bash
./test_blacklists.sh --show-all
```

This will run a series of tests to verify that the blacklist checking functionality is working correctly with various types of IP addresses.

## 📊 Trust Score System

The IP Blacklist Checker uses a sophisticated trust score system to evaluate the trustworthiness of an IP address based on its presence in various blacklists.

### How It Works

1. **Progressive Penalty System**: Unlike a simple percentage calculation, the trust score uses a progressive penalty system where each additional blacklist appearance results in a larger score reduction:
   - First blacklist hit: -5 points
   - Second blacklist hit: -10 points
   - Third blacklist hit: -15 points
   - And so on...

2. **Score Interpretation**:
   - 90-100%: **Highly Trusted** - This IP shows no significant signs of malicious activity
   - 75-89%: **Trusted** - This IP has minimal presence on blacklists
   - 50-74%: **Moderately Trusted** - This IP appears on some blacklists but is generally acceptable
   - 25-49%: **Suspicious** - This IP appears on several blacklists and should be treated with caution
   - 0-24%: **Untrusted** - This IP appears on many blacklists and is likely engaged in malicious activity

3. **Why Progressive Penalties?**: This approach better reflects the real-world risk assessment of IPs. An IP appearing on multiple blacklists indicates a pattern of problematic behavior, which is more concerning than just the raw percentage of blacklists it appears on.

### Example

- An IP not listed on any blacklists receives a perfect 100% trust score
- An IP listed on just 4 out of 72 blacklists might receive a 50% trust score
- An IP listed on 9 out of 72 blacklists might receive a 0% trust score due to the progressive penalties

## ⚠️ Ethical Usage

When using this tool, please be aware of the following ethical considerations:

- **Rate Limiting**: DNSBL.org and other blacklist providers require limiting queries to less than 100 per day per IP. Excessive queries may result in your IP being blocked.

- **Respect Service Providers**: The blacklist services are provided as a courtesy to the internet community. Avoid abusing these services with automated mass queries.

- **Legitimate Usage**: This tool is designed for security professionals, system administrators, and researchers to verify the reputation of IP addresses. Do not use it for malicious purposes.

## 🐛 Known Issues

- Some corporate networks may block DNS queries to blacklist servers
- Performance may vary depending on your DNS resolver speed
- IPv6 support is currently limited

## 📝 Version History

- **v1.0.0** - Initial release with bash implementation
- **v1.1.0** - Added Python implementation with rich terminal output
- **v1.2.0** - Enhanced trust score calculation and added more blacklists

## 👍 Contributing

Contributions to improve IP Blacklist Checker are welcome! Here's how you can contribute:

1. **Reporting Issues**: If you find a bug or have a suggestion, please open an issue on GitHub
2. **Adding Features**: Feel free to fork the repository and submit pull requests with new features
3. **Improving Documentation**: Help improve the documentation by fixing typos or adding more examples
4. **Adding Blacklists**: If you know of additional blacklists that should be included, please suggest them

### Development Guidelines

- Follow existing code style and formatting
- Add comments to explain complex code sections
- Test thoroughly before submitting a pull request
- Update the README if your changes introduce new features or change existing ones

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- Thanks to all the organizations that maintain DNS blacklists
- Rich library developers for the beautiful terminal formatting (Python version)
- All contributors who have helped improve this tool

