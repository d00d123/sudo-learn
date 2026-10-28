# sudo-learn

`sudo learn --topic security`: a daily dive into how attacks and defenses actually work, with diagrams, hands-on labs, detection ideas, and weekly reviews.

Each day covers one technical concept at the mechanism level: real protocol fields, log lines, commands, and detection logic. Learning in public.

## How each lesson is laid out

| Section | What it is |
|---|---|
| Warm-up recall | Retrieval questions from earlier days (spaced repetition) |
| Threat feed | A few verified current security stories, tied back to the concept |
| The idea, why it matters | One sentence, an analogy, and a real incident |
| How it works | Step-by-step walkthrough with a diagram and real packet or log fields |
| Misconceptions, attacker abuse | Common mistakes; MITRE ATT&CK / CWE / OWASP mapping |
| Defender playbook | Prevention, plus detection ideas (Sigma, Suricata, SIEM logic) |
| Hands-on lab | Optional, local, free tools only |
| Portfolio idea, teach it back, self-check | Build something, explain it simply, test yourself |

Every seventh day is a weekly review: recap, a combined attack-chain diagram, mixed practice questions, and a mini-challenge.

## Progress

| Day | Topic |
|---|---|
| 1 | [TCP three-way handshake and SYN floods](day-01-tcp-handshake-syn-floods/README.md) |
| 2 | [DNS resolution, caching, and attacks](day-02-dns-resolution-and-attacks/README.md) |
| 3 | [The TLS 1.3 handshake](day-03-tls-1-3-handshake/README.md) |
| 4 | [Public-key vs symmetric crypto, and why both are used together](day-04-public-key-vs-symmetric-crypto/README.md) |
| 5 | [Hashing and password cracking](day-05-hashing-and-password-cracking/README.md) |
| 6 | [HTTP, cookies, and sessions](day-06-http-cookies-sessions/README.md) |
| 7 | [Weekly review: week 1](day-07-weekly-review-1/README.md) |

## Ground rules

- Labs are meant for your own machines and lab environments only. Do not point any of it at systems you do not own or have written permission to test.
- Everything here is educational and defensive in intent. Example IPs, domains, and keys are documentation placeholders (for example `example.com` and the `192.0.2.0/24` and `203.0.113.0/24` ranges).
- Facts, CVE and technique IDs, and links are checked when each lesson is written. If you spot a mistake, open an issue.
- Every lesson is checked with `tools/scan.py` for secrets, personal data, and classification markers before it is committed.
