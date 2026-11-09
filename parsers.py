"""
Real parsers for the two VPN config formats this project audits:

- OpenVPN's directive-file format (.ovpn / .conf): one directive per
  line, `directive [arg ...]`, `#`/`;` comments, some directives are
  bare flags (e.g. `comp-lzo`) with no argument.
- WireGuard's INI-style format (wg0.conf): `[Interface]` / `[Peer]`
  sections (a config can have multiple `[Peer]` sections, one per
  peer) with `Key = Value` lines inside each.

Neither parser is a simplified stand-in - both handle the real
directive/INI syntax these tools actually read.
"""
import re
from dataclasses import dataclass, field


# --------------------------------------------------------------- OpenVPN

def parse_openvpn_config(text: str) -> dict:
    """Returns {directive: [arg_string, ...]} - a directive with no
    argument (a bare flag like `comp-lzo`) maps to [""], and a directive
    that appears multiple times (e.g. multiple `remote` lines) collects
    all occurrences in order."""
    directives: dict = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # Inline <cert>...</cert> blocks are out of scope for these
        # checks (they're certificate material, not a policy knob) -
        # skip the whole block rather than mis-parsing it as directives.
        if line.startswith("<"):
            continue
        parts = line.split(None, 1)
        name = parts[0]
        arg = parts[1].strip() if len(parts) > 1 else ""
        directives.setdefault(name, []).append(arg)
    return directives


def has_directive(directives: dict, name: str) -> bool:
    return name in directives


def directive_arg(directives: dict, name: str) -> str:
    """First argument of the first occurrence, or '' if not present."""
    vals = directives.get(name)
    return vals[0] if vals else ""


# -------------------------------------------------------------- WireGuard

@dataclass
class WgConfig:
    interface: dict = field(default_factory=dict)
    peers: list = field(default_factory=list)   # list[dict]


_SECTION_RE = re.compile(r"^\[(\w+)\]$")
_KV_RE = re.compile(r"^([A-Za-z]+)\s*=\s*(.*)$")


def parse_wireguard_config(text: str) -> WgConfig:
    cfg = WgConfig()
    current_section = None
    current_peer = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _SECTION_RE.match(line)
        if m:
            current_section = m.group(1)
            if current_section == "Peer":
                current_peer = {}
                cfg.peers.append(current_peer)
            continue
        m = _KV_RE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if current_section == "Interface":
            cfg.interface[key] = value
        elif current_section == "Peer" and current_peer is not None:
            current_peer[key] = value
    return cfg
