# notion_cybersecurity
Utilities for basic cybersecurity checks.

## Security Scan Script

The `security_scan.py` script runs common TLS and HTTP header checks using
external tools. It is designed to work on macOS and Linux.
It can optionally download any missing tools from their official
repositories when invoked with `--install-missing`.

### Requirements

- Python 3 with the `requests` package
- Optional external tools: `sslscan`, `testssl.sh`, and `shcheck`

### Usage

```bash
python security_scan.py --all --install-missing
```

When the script runs, it prompts for a target URL in the form `https://<host>` or
`https://<ip>`. If the input is invalid it will ask again. Use `--help` to see
all options.

Passing `--install-missing` will clone and build the required utilities
(`sslscan`, `testssl.sh`, and `shcheck`) in a local `tools/` directory if they
are not already installed on your system.

## Active Directory Enumeration Script

The `ad_enum.py` script automates common Active Directory reconnaissance tasks. It wraps popular utilities such as `nmap`, `enum4linux`, `smbclient`, `smbmap`, `ldapsearch`, `rpcclient`, `nmblookup`, `crackmapexec`, `bloodhound-python`, and `kerbrute`.

Simply run the script and supply the target domain controller IP along with optional domain credentials and a user wordlist when prompted.

```bash
python ad_enum.py
```

Installed tools will execute and their results are summarized in a table. Any missing utilities are reported so you can install them.
