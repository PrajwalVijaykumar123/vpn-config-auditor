"""
9 checks - 6 against real OpenVPN directive configs, 3 against real
WireGuard configs - each flagging a concrete, named weakness rather
than a vague "review your crypto" warning. No ISO mapping here (unlike
the hardening auditors) because these map more naturally to specific,
named vulnerabilities (VORACLE, weak-cipher downgrade, MITM via
unverified cert) than to a generic Annex A control - each check's
message says exactly what the weakness enables.
"""
from dataclasses import dataclass

from parsers import parse_openvpn_config, has_directive, directive_arg, parse_wireguard_config

WEAK_CIPHERS = {"des-cbc", "bf-cbc", "rc2-cbc", "rc4", "none", "null"}
STRONG_CIPHER_PREFIXES = ("aes-256-gcm", "aes-128-gcm", "aes-256-cbc", "aes-128-cbc", "chacha20-poly1305")
WEAK_AUTH_HASHES = {"md5", "sha1", "none"}


@dataclass
class CheckResult:
    check_id: str
    title: str
    severity: str          # "low" | "medium" | "high" | "critical"
    status: str            # "pass" | "fail" | "skip"
    detail: str = ""
    remediation: str = ""


# ------------------------------------------------------------- OpenVPN (6)

def check_ovpn_cipher_strength(directives: dict) -> CheckResult:
    cipher = directive_arg(directives, "cipher").lower()
    if not cipher:
        return CheckResult("OVPN-1", "A strong data-channel cipher is explicitly configured",
                            "medium", "skip", "no 'cipher' directive found")
    if cipher in WEAK_CIPHERS or not any(cipher.startswith(p) for p in STRONG_CIPHER_PREFIXES):
        return CheckResult(
            "OVPN-1", "A strong data-channel cipher is explicitly configured",
            "critical", "fail", f"cipher is '{cipher}'",
            "Set `cipher AES-256-GCM` (or AES-128-GCM / CHACHA20-POLY1305) - "
            "DES/Blowfish/RC2/RC4/none are all broken or provide no confidentiality",
        )
    return CheckResult("OVPN-1", "A strong data-channel cipher is explicitly configured",
                        "critical", "pass", f"cipher is '{cipher}'")


def check_ovpn_auth_hash_strength(directives: dict) -> CheckResult:
    auth = directive_arg(directives, "auth").lower()
    if not auth:
        return CheckResult("OVPN-2", "A strong HMAC auth digest is explicitly configured",
                            "medium", "skip", "no 'auth' directive found (default is SHA1 on older OpenVPN)")
    if auth in WEAK_AUTH_HASHES:
        return CheckResult(
            "OVPN-2", "A strong HMAC auth digest is explicitly configured",
            "high", "fail", f"auth is '{auth}'",
            "Set `auth SHA256` or stronger - MD5 and SHA1 are not suitable for a new "
            "HMAC digest, and `auth none` disables packet authentication entirely",
        )
    return CheckResult("OVPN-2", "A strong HMAC auth digest is explicitly configured",
                        "high", "pass", f"auth is '{auth}'")


def check_ovpn_control_channel_auth(directives: dict) -> CheckResult:
    if has_directive(directives, "tls-crypt") or has_directive(directives, "tls-auth"):
        which = "tls-crypt" if has_directive(directives, "tls-crypt") else "tls-auth"
        return CheckResult("OVPN-3", "The control channel has an additional HMAC layer (tls-auth/tls-crypt)",
                            "high", "pass", f"'{which}' is configured")
    return CheckResult(
        "OVPN-3", "The control channel has an additional HMAC layer (tls-auth/tls-crypt)",
        "high", "fail", "neither 'tls-crypt' nor 'tls-auth' is configured",
        "Add `tls-crypt ta.key` (preferred - also encrypts control-channel packets) or "
        "`tls-auth ta.key 1` - without this, the server responds to TLS handshakes from "
        "anyone on the internet, not just clients with a valid key",
    )


def check_ovpn_remote_cert_verification(directives: dict) -> CheckResult:
    has_remote_cert_tls = has_directive(directives, "remote-cert-tls")
    has_verify_x509 = has_directive(directives, "verify-x509-name")
    if has_remote_cert_tls or has_verify_x509:
        which = "remote-cert-tls" if has_remote_cert_tls else "verify-x509-name"
        return CheckResult("OVPN-4", "The client verifies the server's certificate usage/identity",
                            "high", "pass", f"'{which}' is configured")
    return CheckResult(
        "OVPN-4", "The client verifies the server's certificate usage/identity",
        "high", "fail", "neither 'remote-cert-tls' nor 'verify-x509-name' is configured",
        "Add `remote-cert-tls server` (client config) so a compromised client cert can't "
        "be used to impersonate the server in a MITM attack",
    )


def check_ovpn_no_compression(directives: dict) -> CheckResult:
    comp_directives = ["comp-lzo", "compress"]
    found = [d for d in comp_directives if has_directive(directives, d)]
    if not found:
        return CheckResult("OVPN-5", "Compression is not enabled on an encrypted tunnel",
                            "medium", "pass", "no compression directive found")
    for d in found:
        if d == "compress" and directive_arg(directives, "compress").lower() in ("", "stub", "stub-v2"):
            continue  # 'compress stub'/'stub-v2' negotiate compression off - not the VORACLE case
        return CheckResult(
            "OVPN-5", "Compression is not enabled on an encrypted tunnel",
            "medium", "fail", f"'{d}' is configured and enables compression",
            "Remove `comp-lzo`/`compress` (or set `compress stub`) - compressing encrypted "
            "traffic enables the VORACLE attack, which can recover plaintext from compressed, "
            "encrypted VPN sessions",
        )
    return CheckResult("OVPN-5", "Compression is not enabled on an encrypted tunnel",
                        "medium", "pass", "compression directive present but set to a disabling mode")


def check_ovpn_tls_version_min(directives: dict) -> CheckResult:
    min_ver = directive_arg(directives, "tls-version-min")
    if not min_ver:
        return CheckResult("OVPN-6", "A minimum TLS version of 1.2 or higher is enforced",
                            "medium", "skip", "no 'tls-version-min' directive found")
    try:
        numeric = float(min_ver.split()[0])
    except ValueError:
        return CheckResult("OVPN-6", "A minimum TLS version of 1.2 or higher is enforced",
                            "medium", "skip", f"could not parse tls-version-min value '{min_ver}'")
    if numeric >= 1.2:
        return CheckResult("OVPN-6", "A minimum TLS version of 1.2 or higher is enforced",
                            "medium", "pass", f"tls-version-min is {min_ver}")
    return CheckResult(
        "OVPN-6", "A minimum TLS version of 1.2 or higher is enforced",
        "medium", "fail", f"tls-version-min is {min_ver}",
        "Set `tls-version-min 1.2` - TLS 1.0/1.1 are deprecated and vulnerable to known downgrade attacks",
    )


OPENVPN_CHECKS = [
    check_ovpn_cipher_strength, check_ovpn_auth_hash_strength, check_ovpn_control_channel_auth,
    check_ovpn_remote_cert_verification, check_ovpn_no_compression, check_ovpn_tls_version_min,
]


def run_openvpn_checks(text: str) -> list:
    directives = parse_openvpn_config(text)
    return [check(directives) for check in OPENVPN_CHECKS]


# ------------------------------------------------------------- WireGuard (3)

def check_wg_preshared_key(cfg) -> CheckResult:
    missing = [i for i, peer in enumerate(cfg.peers, start=1) if not peer.get("PresharedKey")]
    if not cfg.peers:
        return CheckResult("WG-1", "Every peer has a PresharedKey configured",
                            "medium", "skip", "no [Peer] sections found")
    if not missing:
        return CheckResult("WG-1", "Every peer has a PresharedKey configured",
                            "medium", "pass", f"all {len(cfg.peers)} peer(s) have a PresharedKey")
    return CheckResult(
        "WG-1", "Every peer has a PresharedKey configured",
        "medium", "fail", f"peer(s) missing PresharedKey: {missing} (1-indexed)",
        "Add `PresharedKey = <key>` to each peer (`wg genpsk`) for a post-quantum-resistant "
        "symmetric layer on top of the Curve25519 key exchange",
    )


def check_wg_private_key_not_placeholder(cfg) -> CheckResult:
    pk = cfg.interface.get("PrivateKey", "")
    if not pk:
        return CheckResult("WG-2", "The interface PrivateKey is present and well-formed",
                            "high", "fail", "no PrivateKey found in [Interface]",
                            "Generate a real key with `wg genkey` and set PrivateKey under [Interface]")
    # A real WireGuard key is 44 base64 characters ending in '='. Obvious
    # placeholder text (short, or clearly a label) is flagged rather than
    # silently trusted.
    if len(pk) != 44 or not pk.endswith("="):
        return CheckResult(
            "WG-2", "The interface PrivateKey is present and well-formed",
            "high", "fail", f"PrivateKey does not look like a real WireGuard key: '{pk}'",
            "This looks like placeholder/example text rather than a generated key - "
            "replace it with real key material from `wg genkey` before deploying",
        )
    return CheckResult("WG-2", "The interface PrivateKey is present and well-formed",
                        "high", "pass", "PrivateKey is present and the expected length/format")


def check_wg_allowed_ips_scoped(cfg) -> CheckResult:
    full_tunnel_peers = []
    for i, peer in enumerate(cfg.peers, start=1):
        allowed = peer.get("AllowedIPs", "")
        nets = [n.strip() for n in allowed.split(",")]
        if "0.0.0.0/0" in nets and "::/0" in nets:
            full_tunnel_peers.append(i)
    if not cfg.peers:
        return CheckResult("WG-3", "AllowedIPs is documented/scoped rather than an unreviewed full tunnel",
                            "low", "skip", "no [Peer] sections found")
    if not full_tunnel_peers:
        return CheckResult("WG-3", "AllowedIPs is documented/scoped rather than an unreviewed full tunnel",
                            "low", "pass", "no peer routes the full 0.0.0.0/0 + ::/0 default")
    return CheckResult(
        "WG-3", "AllowedIPs is documented/scoped rather than an unreviewed full tunnel",
        "low", "fail", f"peer(s) with full-tunnel AllowedIPs (0.0.0.0/0, ::/0): {full_tunnel_peers} (1-indexed)",
        "Full-tunnel routing isn't automatically wrong (it's normal for a client VPN), but "
        "it should be a deliberate choice, not a default nobody reviewed - confirm this peer "
        "is meant to route all traffic, and scope AllowedIPs to specific subnets if not",
    )


WIREGUARD_CHECKS = [check_wg_preshared_key, check_wg_private_key_not_placeholder, check_wg_allowed_ips_scoped]


def run_wireguard_checks(text: str) -> list:
    cfg = parse_wireguard_config(text)
    return [check(cfg) for check in WIREGUARD_CHECKS]
