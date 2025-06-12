#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
from typing import Dict, List
from urllib.parse import urlparse

TOOLS: Dict[str, Dict[str, str]] = {
    "sslscan": {
        "cmd": "sslscan",
        "repo": "https://github.com/rbsec/sslscan.git",
        "build": "make && make install"
    },
    "testssl.sh": {
        "cmd": "testssl.sh",
        "repo": "https://github.com/drwetter/testssl.sh.git"
    },
    "shcheck": {
        "cmd": "shcheck",
        "repo": "https://github.com/vavkamil/shcheck.git"
    },
}

import requests


def run_command(cmd: List[str] | str) -> int:
    """Run a command and stream its output."""
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        shell=isinstance(cmd, str),
    )
    if process.stdout:
        for line in process.stdout:
            print(line, end="")
    return process.wait()


def install_tool(name: str, base_dir: str = "tools") -> bool:
    """Clone and build the tool, returning True on success."""
    info = TOOLS.get(name)
    if not info:
        print(f"Unknown tool: {name}")
        return False
    os.makedirs(base_dir, exist_ok=True)
    dest = os.path.join(base_dir, name)
    if not os.path.exists(dest):
        print(f"Cloning {name} from {info['repo']}")
        if run_command(["git", "clone", info["repo"], dest]) != 0:
            print(f"Failed to clone {name}")
            return False
    build_cmd = info.get("build")
    if build_cmd:
        print(f"Building {name}")
        if run_command(build_cmd) != 0:
            print(f"Failed to build {name}")
            return False
    return True


def find_tool(name: str, base_dir: str = "tools") -> str | None:
    """Return command path if installed, otherwise None."""
    path = shutil.which(name)
    if path:
        return path
    candidate = os.path.join(base_dir, name, name)
    if os.path.exists(candidate):
        return candidate
    # testssl.sh stores script in repo root
    if name == "testssl.sh":
        candidate = os.path.join(base_dir, name, "testssl.sh")
        if os.path.exists(candidate):
            return candidate
    return None


def sslscan(target: str) -> int:
    cmd = find_tool("sslscan")
    if not cmd:
        print("sslscan is not installed")
        return 1
    print(f"=== Running sslscan against {target} ===")
    return run_command([cmd, target])


def testssl(target: str) -> int:
    cmd = find_tool("testssl") or find_tool("testssl.sh")
    if not cmd:
        print("testssl is not installed")
        return 1
    print(f"=== Running testssl against {target} ===")
    return run_command([cmd, target])


def shcheck(url: str) -> int:
    cmd = find_tool("shcheck")
    if not cmd:
        print("shcheck is not installed")
        return 1
    print(f"=== Running shcheck against {url} ===")
    return run_command([cmd, url])

def check_headers(url: str) -> List[str]:
    print(f"=== Checking security headers for {url} ===")
    try:
        response = requests.get(url, timeout=10)
    except Exception as exc:
        print(f"Failed to fetch {url}: {exc}")
        return []
    headers = {k.lower(): v for k, v in response.headers.items()}
    important = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-xss-protection",
    ]
    for h in important:
        if h in headers:
            print(f"{h}: {headers[h]}")
        else:
            print(f"Missing header: {h}")
    missing = [h for h in important if h not in headers]
    return missing

def prompt_for_url() -> str:
    """Prompt the user for a URL starting with https:// and return it."""
    while True:
        url = input("Enter target URL (e.g. https://example.com): ").strip()
        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.netloc:
            return url
        print("Invalid URL. Please use the format https://<host> or https://<ip>.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run basic TLS and header checks")
    parser.add_argument("--sslscan", action="store_true", help="Run sslscan")
    parser.add_argument("--testssl", action="store_true", help="Run testssl")
    parser.add_argument("--shcheck", action="store_true", help="Run shcheck")
    parser.add_argument("--headers", action="store_true", help="Check security headers")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    parser.add_argument(
        "--install-missing",
        action="store_true",
        help="Install missing external tools automatically",
    )
    args = parser.parse_args()

    url = prompt_for_url()
    host = urlparse(url).netloc

    checks: List[str] = []
    if args.all or args.sslscan:
        checks.append("sslscan")
    if args.all or args.testssl:
        checks.append("testssl.sh")
    if args.all or args.shcheck:
        checks.append("shcheck")

    missing = [t for t in set(checks) if not find_tool(t)]
    if missing and args.install_missing:
        for tool in missing:
            install_tool(tool)
        missing = [t for t in set(checks) if not find_tool(t)]
    if missing:
        print("Missing tools: " + ", ".join(missing))

    summary: List[tuple[str, str]] = []

    if args.all or args.sslscan:
        if find_tool("sslscan"):
            rc = sslscan(host)
            summary.append(("sslscan", "OK" if rc == 0 else f"error {rc}"))
        else:
            summary.append(("sslscan", "missing"))

    if args.all or args.testssl:
        if find_tool("testssl") or find_tool("testssl.sh"):
            rc = testssl(host)
            summary.append(("testssl", "OK" if rc == 0 else f"error {rc}"))
        else:
            summary.append(("testssl", "missing"))

    if args.all or args.shcheck:
        if find_tool("shcheck"):
            rc = shcheck(url)
            summary.append(("shcheck", "OK" if rc == 0 else f"error {rc}"))
        else:
            summary.append(("shcheck", "missing"))

    if args.all or args.headers:
        missing_headers = check_headers(url)
        if missing_headers:
            summary.append((
                "headers",
                "; ".join(f"**Missing {h}**" for h in missing_headers),
            ))
        else:
            summary.append(("headers", "all present"))

    # Print summary table
    col_width = max(len(name) for name, _ in summary) + 2
    print("\n" + "+" + "-" * (col_width + 20) + "+")
    print(f"| {'Check'.ljust(col_width)}| Result")
    print("+" + "-" * (col_width + 20) + "+")
    for name, result in summary:
        print(f"| {name.ljust(col_width)}| {result}")
    print("+" + "-" * (col_width + 20) + "+")


if __name__ == "__main__":
    main()
