# VPN Config Auditor

Audits a real OpenVPN (`.ovpn`/`.conf`) or WireGuard (`.conf`) configuration file for weak crypto and missing protections — not a generic "review your VPN" checklist, but specific, named weaknesses: VORACLE-enabling compression, a missing control-channel HMAC layer, an unverified server certificate, a weak cipher or hash, and a WireGuard peer with no pre-shared key or an obvious placeholder private key.

**Only audit configs you own or are authorized to assess.**

## What This Project Does

**OpenVPN (6 checks)** — parses the real directive-file format (`directive [arg]` per line):
- Data-channel cipher is strong (flags `BF-CBC`, `DES-CBC`, `RC2`, `RC4`, `none`/`null`; requires an AES-GCM/AES-CBC/ChaCha20-Poly1305 family cipher)
- HMAC auth digest is strong (flags `MD5`, `SHA1`, `none`)
- Control channel has an additional HMAC layer (`tls-crypt` or `tls-auth`) — without it, the server responds to a TLS handshake from anyone on the internet, not just holders of a valid key
- Client verifies the server's certificate usage/identity (`remote-cert-tls` or `verify-x509-name`) — without it, a compromised *client* cert can be used to impersonate the server
- Compression is not enabled (`comp-lzo`/`compress`) — compressing encrypted traffic is what makes the **VORACLE** attack possible
- `tls-version-min` is 1.2 or higher

**WireGuard (3 checks)** — parses the real `[Interface]`/`[Peer]` INI format:
- Every peer has a `PresharedKey` configured
- The interface `PrivateKey` is present and actually looks like a generated key (44 base64 characters), not leftover placeholder text
- `AllowedIPs` isn't an unreviewed full-tunnel default (`0.0.0.0/0, ::/0`) — not automatically wrong, but flagged as something that should be a deliberate choice

Each check reports **pass/fail/skip**, severity, the actual finding, and a concrete remediation line naming the exact directive to add or change.

## Why Compression Gets Its Own Check

Most VPN hardening guides talk about cipher strength and stop there. `comp-lzo`/`compress` is a setting that looks completely unrelated to cryptography — it's just a performance knob — but compressing ciphertext before encryption creates a side channel (the compression ratio leaks information about the plaintext), which is exactly what the 2018 **VORACLE** attack exploits against OpenVPN. This check exists because it's the kind of finding a generic "is the cipher strong" audit walks right past.

## Tech Stack

- Python 3.11, standard library only (`re`, `dataclasses`, `argparse`) — no third-party dependencies

## Setup

```bash
python3 scanner.py --openvpn client.ovpn
python3 scanner.py --wireguard wg0.conf
python3 scanner.py --openvpn server.conf --json report.json --fail-on high
```

## Testing

`test_fixtures/` has four real config files — a compliant and a deliberately broken config for each format. `run_test.sh` runs the real scanner against all four:

```bash
sh test_fixtures/run_test.sh
```

18 assertions, all passing: both compliant fixtures produce zero failed checks and exit 0; the noncompliant OpenVPN fixture fails all 6 checks by name (weak `BF-CBC` cipher, `MD5` auth, no `tls-crypt`/`tls-auth`, no `remote-cert-tls`, `comp-lzo` enabled, `tls-version-min 1.0`); the noncompliant WireGuard fixture fails all 3 (missing `PresharedKey`, a placeholder `PrivateKey`, and a full-tunnel `AllowedIPs` nobody reviewed).

## Architecture

```
scanner.py (CLI: --openvpn / --wireguard mode, report formatting, --fail-on exit codes)
        |
        v
parsers.py: parse_openvpn_config() -> {directive: [args]}
            parse_wireguard_config() -> WgConfig(interface, peers)
        |
        v
checks.py: 6 OpenVPN + 3 WireGuard checks, each naming a specific
    weakness (VORACLE, MITM via unverified cert, weak cipher, etc.)
        |
        v
Console report (grouped by severity) + optional JSON; exit code reflects --fail-on
```

## Project Structure

```
vpn-config-auditor/
├── scanner.py                           # CLI
├── parsers.py                            # OpenVPN directive parser + WireGuard INI parser
├── checks.py                              # 6 OpenVPN + 3 WireGuard checks
└── test_fixtures/
    ├── compliant_client.ovpn            # Real OpenVPN syntax, passes every check
    ├── noncompliant_client.ovpn         # Deliberately weak cipher/auth/no tls-crypt/comp-lzo/old TLS
    ├── compliant_wg0.conf                # Real WireGuard syntax, passes every check
    ├── noncompliant_wg0.conf            # Placeholder key, no PSK, full-tunnel AllowedIPs
    └── run_test.sh                        # Runs scanner.py against all four, asserts findings + exit codes
```

## What I Learned

- Writing `check_ovpn_no_compression` was a reminder that not every meaningful finding is a crypto-strength comparison — some of the most impactful VPN misconfigurations (VORACLE's compression requirement being the clearest example) are enabled by a setting that has nothing to do with cipher choice at all, and a checklist built only around "is the algorithm strong enough" misses them entirely.
- Treating a WireGuard `PrivateKey` that's merely *present* as insufficient, and actually validating it looks like real key material (44 base64 characters, correct padding), caught something a presence-only check would have rubber-stamped — example/template configs commonly ship with obvious placeholder text in exactly that field.
- `AllowedIPs = 0.0.0.0/0, ::/0` deliberately got a **low**-severity "review this" finding rather than a hard fail — full-tunnel routing is completely normal and often the right choice for a client VPN, so flagging it as wrong outright would make the tool noisy and untrustworthy; flagging it as "confirm this was deliberate" is the honest framing.
- Skipping ISO 27001 Annex A tags on this project (unlike the hardening auditors) was a deliberate choice, not an oversight — these findings map much more precisely to specific named vulnerabilities and RFC-documented weaknesses than to a generic Annex A control, and forcing an Annex A reference onto each one would have diluted the thing that actually makes each finding credible.

## Next Steps

- IPsec/IKEv2 config support (strongSwan `ipsec.conf` syntax), covering the third major VPN protocol family alongside OpenVPN and WireGuard.
- A check for OpenVPN's `key-direction` consistency when `tls-auth` is used (client/server must use opposite directions) — currently only presence is checked, not correct pairing.
- Cross-reference WireGuard `Endpoint` values against `firewall-rule-auditor`'s rule model, to flag a WireGuard listening port that isn't actually allowed through the host's firewall (or is allowed far more broadly than the VPN itself needs).
- A `--batch` mode auditing every `.ovpn`/`.conf` file in a directory (a config-management repo or an `/etc/openvpn/client` directory) in one pass, aggregating findings across a fleet of client configs rather than one file at a time.
