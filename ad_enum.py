#!/usr/bin/env python3
"""Active Directory enumeration helper.

This script runs several popular enumeration tools against a target
Windows domain controller. The goal is to quickly gather as much
information as possible about the environment.
"""

import subprocess
import shutil
import ipaddress
from typing import List, Tuple, Optional
from getpass import getpass


def run_command(cmd: List[str] | str) -> Tuple[int, str]:
    """Run a command and return (returncode, output)."""
    try:
        result = subprocess.run(
            cmd,
            shell=isinstance(cmd, str),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        print(result.stdout)
        return result.returncode, result.stdout
    except FileNotFoundError:
        name = cmd if isinstance(cmd, str) else cmd[0]
        print(f"Command not found: {name}")
        return 1, ""


def find_tool(name: str) -> Optional[str]:
    """Return path to executable or None if not found."""
    return shutil.which(name)


def nmap_scan(ip: str) -> Tuple[int, str]:
    print("=== Running nmap scan ===")
    ports = "88,135,139,389,445,636,3268,3269,53"
    cmd = [
        "nmap",
        "-sS",
        "-sU",
        "-p",
        ports,
        "-A",
        ip,
    ]
    return run_command(cmd)


def enum4linux_scan(ip: str) -> Tuple[int, str]:
    print("=== Running enum4linux ===")
    cmd = ["enum4linux", "-a", ip]
    return run_command(cmd)


def smbclient_shares(ip: str, domain: str, user: str, password: str) -> Tuple[int, str]:
    print("=== Enumerating SMB shares with smbclient ===")
    if user and password:
        creds = f"{user}%{password}"
        cmd = ["smbclient", "-L", f"//{ip}/", "-U", creds, "-W", domain]
    else:
        cmd = ["smbclient", "-L", f"//{ip}/", "-N"]
    return run_command(cmd)


def smbmap_shares(ip: str, domain: str, user: str, password: str) -> Tuple[int, str]:
    print("=== Enumerating SMB shares with smbmap ===")
    if user and password:
        cmd = ["smbmap", "-H", ip, "-u", user, "-p", password, "-d", domain]
    else:
        cmd = ["smbmap", "-H", ip]
    return run_command(cmd)


def ldap_rootdse(ip: str) -> Tuple[int, str]:
    print("=== Querying LDAP RootDSE ===")
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{ip}", "-s", "base", "-b", "", "*"]
    return run_command(cmd)


def rpcclient_users(ip: str, user: str, password: str) -> Tuple[int, str]:
    print("=== Enumerating users with rpcclient ===")
    if user and password:
        creds = f"{user}%{password}"
        cmd = ["rpcclient", "-U", creds, ip, "-c", "enumdomusers"]
    else:
        cmd = ["rpcclient", "-N", ip, "-c", "enumdomusers"]
    return run_command(cmd)


def nmblookup_query(ip: str) -> Tuple[int, str]:
    print("=== Running nmblookup ===")
    cmd = ["nmblookup", "-A", ip]
    return run_command(cmd)


def crackmapexec_scan(ip: str, domain: str, user: str, password: str) -> Tuple[int, str]:
    print("=== Running crackmapexec ===")
    if user and password:
        cmd = ["crackmapexec", "smb", ip, "-u", user, "-p", password, "-d", domain]
    else:
        cmd = ["crackmapexec", "smb", ip]
    return run_command(cmd)


def bloodhound_collect(ip: str, domain: str, user: str, password: str) -> Tuple[int, str]:
    print("=== Collecting BloodHound data ===")
    if not (user and password and domain):
        print("BloodHound collection requires domain, username and password")
        return 1, ""
    cmd = [
        "bloodhound-python",
        "-c",
        "all",
        "-u",
        user,
        "-p",
        password,
        "-d",
        domain,
        "-dc",
        ip,
        "--zip",
    ]
    return run_command(cmd)


def kerbrute_userenum(ip: str, domain: str, wordlist: str) -> Tuple[int, str]:
    print("=== Enumerating usernames with kerbrute ===")
    if not wordlist:
        print("No wordlist provided for kerbrute")
        return 1, ""
    cmd = ["kerbrute", "userenum", "--dc", ip, "-d", domain, wordlist]
    return run_command(cmd)


def prompt_ip() -> str:
    while True:
        ip = input("Target Domain Controller IP: ").strip()
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            print("Invalid IP address")


def main() -> None:
    ip = prompt_ip()
    domain = input("Domain name (optional): ").strip()
    user = input("Username (optional): ").strip()
    password = getpass("Password (optional): ") if user else ""
    wordlist = input("Userlist path for kerbrute (optional): ").strip()

    steps = [
        ("nmap", find_tool("nmap"), nmap_scan, (ip,)),
        ("enum4linux", find_tool("enum4linux"), enum4linux_scan, (ip,)),
        ("smbclient", find_tool("smbclient"), smbclient_shares, (ip, domain, user, password)),
        ("smbmap", find_tool("smbmap"), smbmap_shares, (ip, domain, user, password)),
        ("ldapsearch", find_tool("ldapsearch"), ldap_rootdse, (ip,)),
        ("rpcclient", find_tool("rpcclient"), rpcclient_users, (ip, user, password)),
        ("nmblookup", find_tool("nmblookup"), nmblookup_query, (ip,)),
        ("crackmapexec", find_tool("crackmapexec"), crackmapexec_scan, (ip, domain, user, password)),
        ("bloodhound-python", find_tool("bloodhound-python"), bloodhound_collect, (ip, domain, user, password)),
        ("kerbrute", find_tool("kerbrute"), kerbrute_userenum, (ip, domain, wordlist)),
    ]

    summary: List[Tuple[str, str]] = []

    for name, path, func, args in steps:
        if not path:
            print(f"{name} not found, skipping")
            summary.append((name, "missing"))
            continue
        rc, _ = func(*args)
        result = "OK" if rc == 0 else f"error {rc}"
        summary.append((name, result))

    print("\nSummary:")
    col_width = max(len(name) for name, _ in summary) + 2
    print("+" + "-" * (col_width + 12) + "+")
    print(f"| {'Tool'.ljust(col_width)}| Result")
    print("+" + "-" * (col_width + 12) + "+")
    for name, result in summary:
        print(f"| {name.ljust(col_width)}| {result}")
    print("+" + "-" * (col_width + 12) + "+")


if __name__ == "__main__":
    main()
