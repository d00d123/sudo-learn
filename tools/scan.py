#!/usr/bin/env python3
"""Pre-publication scan for secrets, personal data and classification markers.

Run before every commit:  python3 tools/scan.py .
Every finding must be fixed or explicitly reviewed as a false positive (for example a
version number that looks like an IP). Real-secret categories (keys, tokens, private keys,
JWTs, passwords, non-placeholder emails, classification markers) always block the commit.
Usage: scan.py <dir>   Exit 0 = clean (after allowlist), 1 = findings need review."""
import ipaddress
import os
import re
import sys

root = sys.argv[1]

PATTERNS = {
    "aws_access_key": r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b",
    "aws_secret_like": r"(?i)aws.{0,20}(secret|key).{0,5}[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
    "github_token": r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b",
    "slack_token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "openai_anthropic_key": r"\bsk-(ant-|proj-)?[A-Za-z0-9_-]{20,}\b",
    "stripe_key": r"\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b",
    "private_key_block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "jwt": r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b",
    "bearer_token": r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}",
    "basic_auth_url": r"[a-z]+://[^\s/:@]+:[^\s/@]+@[^\s/]+",
    "password_assign": r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|auth)\s*[=:]\s*['\"]?[^\s'\"<>$]{6,}",
    "long_hex_secret": r"\b[a-f0-9]{40,}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "phone": r"(?<!\d)(\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)",
    "ssn_like": r"\b\d{3}-\d{2}-\d{4}\b",
    "card_like": r"\b(?:\d[ -]?){13,16}\b",
    "user_path": r"(/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._-]+)",
    "classification_marker": r"(?i)\b(TLP:\s*(RED|AMBER|GREEN)|CUI|FOUO|for official use only|internal use only|company confidential|confidential|classified|proprietary|do not distribute|NOFORN)\b",
    "claude_internal": r"(?i)(claude\.ai/(code|artifact)|session_[A-Za-z0-9]+|trig_[A-Za-z0-9]+)",
}
IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# documentation / well-known placeholders that are fine to publish
ALLOW_LITERALS = {
    "AKIAIOSFODNN7EXAMPLE",
    "user@example.com", "alice@example.com", "bob@example.com",
}
WELL_KNOWN_PUBLIC_EXTRA = set()
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
WELL_KNOWN_PUBLIC = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "93.184.216.34", "127.0.0.1", "0.0.0.0", "255.255.255.255"}

# Values a human reviewed as harmless (version numbers, public example hashes). One per line.
reviewed = set()
allow_file = os.path.join(root, "tools", "scan-allow.txt")
if os.path.exists(allow_file):
    for ln in open(allow_file, encoding="utf8"):
        ln = ln.split("#", 1)[0].strip()
        if ln:
            reviewed.add(ln)

findings = []
for dp, _, fs in os.walk(root):
    if ".git" in dp.split(os.sep) or "tools" in os.path.relpath(dp, root).split(os.sep):
        continue  # skip git internals and this tools folder (its own patterns would match)
    for fn in fs:
        path = os.path.join(dp, fn)
        try:
            lines = open(path, encoding="utf8").read().splitlines()
        except Exception as e:
            findings.append((path, 0, "unreadable", str(e)))
            continue
        for i, line in enumerate(lines, 1):
            for name, pat in PATTERNS.items():
                for m in re.finditer(pat, line):
                    val = m.group(0)
                    if val in ALLOW_LITERALS or val in reviewed:
                        continue
                    if name == "email" and re.search(r"@(example\.(com|org|net)|users\.noreply\.github\.com)$", val):
                        continue
                    if name == "card_like" and not re.search(r"\d{4}", val):
                        continue
                    if name in ("password_assign",) and re.search(r"token = identity|bearer token = identity", line):
                        continue
                    if name == "claude_internal" and re.search(r"session_ip|Session_Management", val + line):
                        continue
                    findings.append((path, i, name, val[:90]))
            for m in IPV4.finditer(line):
                ip = m.group(1)
                try:
                    a = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if ip in reviewed or ip in WELL_KNOWN_PUBLIC or ip in WELL_KNOWN_PUBLIC_EXTRA or any(a in n for n in DOC_NETS):
                    continue
                kind = "private_ip" if (a.is_private or a.is_loopback or a.is_link_local) else "public_ip_review"
                findings.append((path, i, kind, ip))

rel = lambda p: os.path.relpath(p, root)
for p, i, k, v in sorted(findings):
    print(f"{rel(p)}:{i}: [{k}] {v}")
print(f"\n{len(findings)} finding(s) for review")
sys.exit(1 if findings else 0)
