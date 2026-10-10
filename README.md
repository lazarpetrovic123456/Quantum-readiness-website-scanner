# Quantum-Readiness Scanner

> ✍️ **Lazar: this is a draft. Rewrite it in your own words before publishing.**
> Interviewers read READMEs, and it should sound like you.

A command-line tool that checks whether websites protect their HTTPS connections with **post-quantum cryptography**, or whether their traffic could be recorded today and decrypted in the future by a quantum computer.

## Why this matters

Almost all secure web traffic today agrees on its encryption keys using elliptic-curve Diffie-Hellman (X25519) or RSA. Both rely on maths problems that **Shor's algorithm** solves efficiently on a large quantum computer.

No quantum computer is large enough yet, but an attacker can record encrypted traffic now and decrypt it once one exists. This is called **"harvest now, decrypt later"**. For data that must stay secret for 10+ years, such as banking records, health data and government communications, the threat is already real.

In 2024 NIST standardised **ML-KEM** (FIPS 203), a key-exchange algorithm believed to resist quantum attacks. Browsers and large providers now deploy it as a **hybrid**, `X25519MLKEM768`, which combines classical X25519 with ML-KEM so the connection stays secure as long as *either* algorithm holds.

This tool measures who has made that switch.

## How it works

1. It builds a TLS 1.3 **ClientHello** by hand, offering two key-exchange options: `X25519MLKEM768` (post-quantum hybrid) and `X25519` (classical).
2. It reads the server's **ServerHello** and checks which option the server picked.
3. It reports the TLS version, the key exchange and the certificate type (RSA/ECDSA).

The ClientHello is built from raw bytes, not with Python's `ssl` library, because most installed OpenSSL versions don't support ML-KEM yet. The scanner only reads the server's first reply and never completes the handshake.

## Usage

```bash
pip install cryptography
python scanner.py google.com barclays.co.uk
python scanner.py --file sites.txt --csv results.csv
```

Example output:

```
google.com                   QUANTUM-SAFE             X25519MLKEM768 (post-quantum hybrid)
example-bank.co.uk           AT RISK                  X25519 (classical)
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `QUANTUM-SAFE` | The server chose X25519MLKEM768. Recorded traffic stays protected against a future quantum computer. |
| `AT RISK` | TLS 1.3 with classical key exchange only. Recorded traffic could be decrypted later. |
| `AT RISK (old TLS 1.2)` | The server negotiated TLS 1.2, which has no post-quantum option at all. |

## Limitations

- **Certificates are still classical everywhere.** Site certificates are signed with RSA or ECDSA, which Shor's algorithm also breaks. This is less urgent than key exchange, because forging a signature only matters at connection time and can't be done retroactively. Post-quantum certificates (ML-DSA) aren't widely deployed yet.
- It checks one server per hostname. Large sites run many servers behind load balancers, and some may differ.
- A network that intercepts TLS (corporate firewalls, some university and cloud networks) will answer for the site, so results reflect the firewall rather than the website.

## Findings

_TODO (Lazar): run the scan, then write 3–4 sentences on what you found. Which sectors are ahead? Which UK banks? What surprised you?_

## Background

This project follows on from my IB Extended Essay on how Shor's algorithm threatens RSA, and the post-quantum response.
