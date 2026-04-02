"""
==========================================================
Converts flight_data.json into a valid
PCAP file containing ASTERIX messages.

Supported categories (selectable via --category or -c):
  048  CAT048  Monoradar Target Reports         (EUROCONTROL-SPEC-0149-4 Ed 1.25)
  062  CAT062  SDPS System Track Messages       (EUROCONTROL-SPEC-0149-9 Ed 1.19)
  all          Write both categories into one PCAP (different UDP ports)

Usage
-----
    python json_to_asterix.py                          # CAT048 (default)
    python json_to_asterix.py -c 062                   # CAT062
    python json_to_asterix.py -c all                   # both
    python json_to_asterix.py input.json output.pcap   # custom paths
    python json_to_asterix.py -h                       # help

Dependencies
------------
    pip install scapy
"""

import json
import math
import struct
import sys
import argparse
from datetime import datetime, timezone

from scapy.all import (
    Ether, IP, UDP, Raw,
    wrpcap, PcapWriter,
)

# ── Default I/O ─────────────────────────────────────────────────────────────
INPUT_JSON  = "flight_data.json"
OUTPUT_PCAP = "asterix_output.pcap"

# ── Radar / system reference  (Abu Dhabi International Airport) ──────────────
RADAR_LAT = 24.433
RADAR_LON = 54.651
RADAR_SAC = 25
RADAR_SIC = 13

# ── Network parameters ───────────────────────────────────────────────────────
SRC_IP  = "10.17.58.184"
DST_IP  = "232.2.1.31"
ETH_DST = "01:00:5e:02:01:1f"
ETH_SRC = "bc:16:65:fe:5f:c2"

# Per-category UDP ports (different ports so Wireshark can demultiplex)
PORTS = {
    48: (21154, 22113),
    62: (21162, 22162),
}


# ════════════════════════════════════════════════════════════════════════════
#  Geometry helpers
# ════════════════════════════════════════════════════════════════════════════

def latlon_to_polar(lat, lon):
    """WGS-84 lat/lon → slant-polar + Cartesian NM from radar site."""
    R_KM    = 6371.0
    dlat    = math.radians(lat - RADAR_LAT)
    dlon    = math.radians(lon - RADAR_LON)
    cos_lat = math.cos(math.radians(RADAR_LAT))
    x_nm    = dlon * R_KM * cos_lat / 1.852
    y_nm    = dlat * R_KM           / 1.852
    rho     = math.sqrt(x_nm**2 + y_nm**2)
    theta   = (math.degrees(math.atan2(x_nm, y_nm)) + 360.0) % 360.0
    return rho, theta, x_nm, y_nm


def heading_to_vxvy(gs_knots, heading_deg):
    """Ground speed (knots) + heading (degrees from North) → Vx (East), Vy (North) in m/s."""
    gs_ms = gs_knots * 0.514444
    theta = math.radians(heading_deg)
    return gs_ms * math.sin(theta), gs_ms * math.cos(theta)


# ICAO 6-bit alphabet — shared by CAT048 / CAT062 callsign encoding
ICAO_ALPHA = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"

def encode_callsign_6bit(callsign):
    """Encode 8-char callsign as 6 bytes (8 x 6-bit ICAO alphabet)."""
    cs   = (str(callsign).upper().strip() + "        ")[:8]
    bits = 0
    for ch in cs:
        idx  = ICAO_ALPHA.find(ch)
        bits = (bits << 6) | (max(0, idx) & 0x3F)
    return struct.pack(">Q", bits)[2:]   # 48 bits = 6 bytes


# ════════════════════════════════════════════════════════════════════════════
#  Track-number registry  (shared across categories)
# ════════════════════════════════════════════════════════════════════════════

_track_numbers = {}
_track_counter = [1]

def get_track_number(icao_hex):
    if icao_hex not in _track_numbers:
        _track_numbers[icao_hex] = _track_counter[0]
        _track_counter[0] = (_track_counter[0] + 1) % 4096 or 1
    return _track_numbers[icao_hex]


# ════════════════════════════════════════════════════════════════════════════
#  FSPEC builder  (generic — used by all categories)
# ════════════════════════════════════════════════════════════════════════════

def build_fspec_and_payload(items, uap_order):

    present = set(items.keys())

    # Determine which octets are needed, then trim trailing empty ones
    active = [any(k in present for k in octet) for octet in uap_order]
    while active and not active[-1]:
        active.pop()

    fspec = b""
    for oi, (_, octet_items) in enumerate(zip(active, uap_order[:len(active)])):
        b = 0
        for i, key in enumerate(octet_items):
            if key in present:
                b |= (1 << (7 - i))
        if any(active[oi + 1:]):   # FX=1 if more FSPEC octets follow
            b |= 0x01
        fspec += bytes([b])

    # Payload in strict UAP FRN order
    payload = b""
    for octet_items in uap_order:
        for key in octet_items:
            if key in items:
                payload += items[key]

    return fspec, payload


def wrap_asterix(cat_num, fspec, payload):
    """CAT(1) + LEN(2) + FSPEC + payload."""
    block_len = 1 + 2 + len(fspec) + len(payload)
    return bytes([cat_num]) + struct.pack(">H", block_len) + fspec + payload


# ════════════════════════════════════════════════════════════════════════════
#  CAT048 — Monoradar Target Reports  (EUROCONTROL-SPEC-0149-4 Ed 1.25)
# ════════════════════════════════════════════════════════════════════════════

# UAP Table 2  (page 45 of EUROCONTROL-SPEC-0149-4 Ed 1.25)
CAT048_UAP = [
    ["010", "140", "020", "040", "070", "090", "130"],  # FSPEC octet 1  FRN 1-7
    ["220", "240", "250", "161", "042", "200", "170"],  # FSPEC octet 2  FRN 8-14
    ["210", "030", "080", "100", "110", "120", "230"],  # FSPEC octet 3  FRN 15-21
]


def cat048_enc_010(sac, sic):
    """
    I048/010 Data Source Identifier — 2 octets fixed.
    Octet 1 = SAC, Octet 2 = SIC.
    """
    return bytes([sac & 0xFF, sic & 0xFF])


def cat048_enc_140(unix_ts_sec, unix_ts_usec=0):
    """
    I048/140 Time of Day — 3 octets, LSB = 1/128 s.
    Value = seconds elapsed since last UTC midnight (spec §5.2.17).
    Derived from the absolute Unix timestamp so it is always correct.
    """
    dt      = datetime.fromtimestamp(unix_ts_sec + unix_ts_usec / 1e6, tz=timezone.utc)
    midnight = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    tod_s   = (dt - midnight).total_seconds()
    val     = int(round(tod_s * 128.0)) & 0xFFFFFF
    return struct.pack(">I", val)[1:]   # 3 bytes big-endian


def cat048_enc_040(rho_nm, theta_deg):
    """
    I048/040 Measured Position in Slant Polar Coordinates — 4 octets fixed.
    Octets 1-2: RHO   unsigned 16-bit, LSB = 1/256 NM  (range in NM per spec)
    Octets 3-4: THETA unsigned 16-bit, LSB = 360/2^16 degrees
    """
    rho_val   = max(0, int(round(rho_nm   * 256.0)))             & 0xFFFF
    theta_val = max(0, int(round(theta_deg * 65536.0 / 360.0)))  & 0xFFFF
    return struct.pack(">HH", rho_val, theta_val)


def cat048_enc_070(squawk_str):
    """
    I048/070 Mode-3/A Code — 2 octets fixed.
    V=0 G=0 L=0 spare=0 | A4 A2 A1 B4 B2 B1 C4 C2 C1 D4 D2 D1
    Each octal digit maps to 3 bits; shifts: A<<9, B<<6, C<<3, D<<0.
    """
    s = str(squawk_str).zfill(4)[:4]
    try:
        A, B, C, D = int(s[0]), int(s[1]), int(s[2]), int(s[3])
    except ValueError:
        A = B = C = D = 0
    code_bits = (A << 9) | (B << 6) | (C << 3) | D
    return struct.pack(">H", code_bits & 0x0FFF)


def cat048_enc_090(altitude_ft):
    """
    I048/090 Flight Level — 2 octets fixed.
    V=0 G=0 | FL (14-bit two's complement), LSB = 1/4 FL = 25 ft.
    """
    fl_quarter = int(round(altitude_ft / 25.0))
    fl_quarter = max(-8192, min(8191, fl_quarter))
    return struct.pack(">H", fl_quarter & 0x3FFF)


def cat048_enc_161(track_no):
    """
    I048/161 Track Number — 2 octets fixed.
    Bits 16-13: spare = 0.  Bits 12-1: track number 0..4095.
    """
    return struct.pack(">H", int(track_no) & 0x0FFF)


def cat048_enc_042(x_nm, y_nm):
    """
    I048/042 Calculated Position in Cartesian Coordinates — 4 octets fixed.
    X (East)  signed 16-bit, LSB = 1/128 NM.
    Y (North) signed 16-bit, LSB = 1/128 NM.
    """
    x_val = max(-32768, min(32767, int(round(x_nm * 128.0))))
    y_val = max(-32768, min(32767, int(round(y_nm * 128.0))))
    return struct.pack(">hh", x_val, y_val)


def cat048_enc_200(gs_knots, heading_deg):
    """
    I048/200 Calculated Track Velocity in Polar Coordinates — 4 octets fixed.
    Octets 1-2: Ground speed, unsigned 16-bit, LSB = 2^-14 NM/s.
    Octets 3-4: Heading,      unsigned 16-bit, LSB = 360/2^16 degrees.
    """
    gs_nms  = max(0.0, float(gs_knots)) / 3600.0      # knots → NM/s
    gs_val  = int(round(gs_nms * 16384.0)) & 0xFFFF   # LSB = 2^-14 NM/s
    hdg_val = int(round(float(heading_deg) * 65536.0 / 360.0)) & 0xFFFF
    return struct.pack(">HH", gs_val, hdg_val)


def cat048_enc_220(icao_hex):
    """
    I048/220 Aircraft Address — 3 octets fixed.
    24-bit Mode S ICAO address, MSB first.
    """
    try:
        val = int(str(icao_hex), 16) & 0xFFFFFF
    except (ValueError, TypeError):
        val = 0
    return struct.pack(">I", val)[1:]


def cat048_enc_240(callsign):
    """
    I048/240 Aircraft Identification — 6 octets fixed.
    8 characters x 6-bit ICAO alphabet = 48 bits.
    """
    return encode_callsign_6bit(callsign)


def build_cat048_record(ac, unix_ts_sec, unix_ts_usec=0):

    lat      = float(ac.get("latitude")  or 0.0)
    lon      = float(ac.get("longitude") or 0.0)
    alt_ft   = float(ac.get("baro_altitude") or 0) * 3.28084   # m → ft
    gs_knots = float(ac.get("velocity")   or 0) * 1.94384       # m/s → knots
    heading  = float(ac.get("true_track") or 0.0)
    callsign = str(ac.get("callsign") or "").strip()
    icao_hex = str(ac.get("icao24")   or "000000")
    squawk   = str(ac.get("squawk")   or "7000").strip()

    rho, theta, x_nm, y_nm = latlon_to_polar(lat, lon)
    track_no = get_track_number(icao_hex)

    items = {
        "010": cat048_enc_010(RADAR_SAC, RADAR_SIC),
        "140": cat048_enc_140(unix_ts_sec, unix_ts_usec),
        "040": cat048_enc_040(rho, theta),
        "220": cat048_enc_220(icao_hex),
        "161": cat048_enc_161(track_no),
        "042": cat048_enc_042(x_nm, y_nm),
    }
    if squawk and squawk not in ("0000", ""):
        items["070"] = cat048_enc_070(squawk)
    if alt_ft > 0:
        items["090"] = cat048_enc_090(alt_ft)
    if gs_knots > 0:
        items["200"] = cat048_enc_200(gs_knots, heading)
    if callsign:
        items["240"] = cat048_enc_240(callsign)

    fspec, payload = build_fspec_and_payload(items, CAT048_UAP)
    return wrap_asterix(48, fspec, payload)


# ════════════════════════════════════════════════════════════════════════════
#  CAT062 — SDPS System Track Messages  (EUROCONTROL-SPEC-0149-9 Ed 1.19)
# ════════════════════════════════════════════════════════════════════════════

# UAP Table 2  (page 126 of EUROCONTROL-SPEC-0149-9)
CAT062_UAP = [
    ["010", "---", "015", "070", "105", "100", "185"],  # FSPEC octet 1  FRN 1-7
    ["210", "060", "245", "380", "040", "080", "290"],  # FSPEC octet 2  FRN 8-14
    ["200", "295", "136", "130", "135", "220", "390"],  # FSPEC octet 3  FRN 15-21
    ["270", "300", "110", "120", "510", "500", "340"],  # FSPEC octet 4  FRN 22-28
    ["---", "---", "---", "---", "---", "RE_", "SP_"],  # FSPEC octet 5  FRN 29-35
]


def cat062_enc_010(sac, sic):
    """
    I062/010 Data Source Identifier — 2 octets fixed.
    Octet 1 = SAC, Octet 2 = SIC.
    """
    return bytes([sac & 0xFF, sic & 0xFF])


def cat062_enc_070(unix_ts_sec, unix_ts_usec=0):
    """
    I062/070 Time Of Track Information — 3 octets, LSB = 1/128 s.
    Value = seconds elapsed since last UTC midnight (spec §5.2.5).
    Derived from the absolute Unix timestamp so it is always correct.
    """
    dt      = datetime.fromtimestamp(unix_ts_sec + unix_ts_usec / 1e6, tz=timezone.utc)
    midnight = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    tod_s   = (dt - midnight).total_seconds()
    val     = int(round(tod_s * 128.0)) & 0xFFFFFF
    return struct.pack(">I", val)[1:]


def cat062_enc_040(track_no):
    """
    I062/040 Track Number — 2 octets, unsigned 16-bit.
    """
    return struct.pack(">H", int(track_no) & 0xFFFF)


def cat062_enc_100(x_nm, y_nm):
    """
    I062/100 Calculated Track Position (Cartesian) — 6 octets.
    X bits 48/25: 24-bit two's complement, LSB = 0.5 m  (East  positive).
    Y bits 24/1:  24-bit two's complement, LSB = 0.5 m  (North positive).
    """
    x_m   = x_nm * 1852.0
    y_m   = y_nm * 1852.0
    x_val = max(-(2**23), min(2**23 - 1, int(round(x_m / 0.5))))
    y_val = max(-(2**23), min(2**23 - 1, int(round(y_m / 0.5))))

    def to3bytes(v):
        return struct.pack(">i", v & 0xFFFFFF if v >= 0 else v + 0x1000000)[1:]

    return to3bytes(x_val) + to3bytes(y_val)


def cat062_enc_185(gs_knots, heading_deg):
    """
    I062/185 Calculated Track Velocity (Cartesian) — 4 octets.
    Vx bits 32/17: 16-bit signed, LSB = 0.25 m/s  (East  positive).
    Vy bits 16/1:  16-bit signed, LSB = 0.25 m/s  (North positive).
    """
    vx, vy = heading_to_vxvy(gs_knots, heading_deg)
    vx_val = max(-32768, min(32767, int(round(vx / 0.25))))
    vy_val = max(-32768, min(32767, int(round(vy / 0.25))))
    return struct.pack(">hh", vx_val, vy_val)


def cat062_enc_130(alt_ft):
    """
    I062/130 Calculated Track Geometric Altitude — 2 octets, signed.
    LSB = 6.25 ft.  Defined as height above WGS-84 ellipsoid (spec §5.2.11).
    OpenSky baro_altitude is geometric (GPS-derived), making this field correct.
    """
    val = int(round(alt_ft / 6.25))
    val = max(-32768, min(32767, val))
    return struct.pack(">h", val)


def cat062_enc_245(callsign):
    """
    I062/245 Target Identification — 7 octets.
    Octet 1: STI(2 bits) = 01 (callsign not downlinked) + 6 spare bits.
    Octets 2-7: 8 x 6-bit ICAO characters.
    """
    sti    = 0b01   # callsign not downlinked from target
    octet1 = (sti << 6) & 0xFF
    return bytes([octet1]) + encode_callsign_6bit(callsign)


def build_cat062_record(ac, unix_ts_sec, unix_ts_usec=0):

    lat      = float(ac.get("latitude")  or 0.0)
    lon      = float(ac.get("longitude") or 0.0)
    alt_ft   = float(ac.get("baro_altitude") or 0) * 3.28084   # m → ft
    gs_knots = float(ac.get("velocity")   or 0) * 1.94384       # m/s → knots
    heading  = float(ac.get("true_track") or 0.0)
    callsign = str(ac.get("callsign") or "").strip()
    icao_hex = str(ac.get("icao24")   or "000000")

    _, _, x_nm, y_nm = latlon_to_polar(lat, lon)
    track_no = get_track_number(icao_hex)

    items = {
        "010": cat062_enc_010(RADAR_SAC, RADAR_SIC),
        "070": cat062_enc_070(unix_ts_sec, unix_ts_usec),
        "100": cat062_enc_100(x_nm, y_nm),
        "040": cat062_enc_040(track_no),
    }
    if gs_knots > 0:
        items["185"] = cat062_enc_185(gs_knots, heading)
    if alt_ft > 0:
        items["130"] = cat062_enc_130(alt_ft)
    if callsign:
        items["245"] = cat062_enc_245(callsign)

    fspec, payload = build_fspec_and_payload(items, CAT062_UAP)
    return wrap_asterix(62, fspec, payload)


# ════════════════════════════════════════════════════════════════════════════
#  Scapy frame builder
# ════════════════════════════════════════════════════════════════════════════

def build_scapy_packet(asterix_bytes, cat_num, ts_sec, ts_usec):
    """
    Wrap raw ASTERIX bytes in an Ethernet/IP/UDP Scapy packet and stamp
    it with the given capture timestamp.

    Scapy handles:
      • Ethernet framing  (dst/src MAC, EtherType 0x0800)
      • IPv4 header       (including checksum calculation)
      • UDP header        (including length; checksum left as 0 per original)
      • PCAP record timestamp
    """
    src_port, dst_port = PORTS[cat_num]

    pkt = (
        Ether(dst=ETH_DST, src=ETH_SRC)
        / IP(src=SRC_IP, dst=DST_IP, ttl=61, flags="DF")
        / UDP(sport=src_port, dport=dst_port)
        / Raw(load=asterix_bytes)
    )

    # Stamp the packet so wrpcap / PcapWriter records the correct capture time
    pkt.time = ts_sec + ts_usec / 1_000_000

    return pkt


# ════════════════════════════════════════════════════════════════════════════
#  Main converter
# ════════════════════════════════════════════════════════════════════════════

BUILDERS = {
    48: (build_cat048_record, "ASTERIX CAT048 Monoradar Target Reports",
         "EUROCONTROL-SPEC-0149-4 Ed 1.25"),
    62: (build_cat062_record, "ASTERIX CAT062 SDPS System Track Messages",
         "EUROCONTROL-SPEC-0149-9 Ed 1.19"),
}


def convert(input_path, output_path, categories):
    print("=" * 70)
    print("  flight_data.json  ->  ASTERIX PCAP  (Scapy)")
    print(f"  Categories : {' + '.join(f'CAT{c}' for c in categories)}")
    print(f"  Input      : {input_path}")
    print(f"  Output     : {output_path}")
    print(f"  Radar      : SAC={RADAR_SAC} SIC={RADAR_SIC}  ({RADAR_LAT}N, {RADAR_LON}E)")
    print("=" * 70)

    with open(input_path) as f:
        data = json.load(f)

    snapshots = data.get("snapshots", [])
    print(f"\n  Snapshots: {len(snapshots)}\n")

    total_records = 0


    with PcapWriter(output_path, linktype=1, sync=True) as pcap:
        for snap_idx, snap in enumerate(snapshots):
            aircraft_list = snap.get("aircraft", [])
            if not aircraft_list:
                continue

            try:
                ts_dt = datetime.fromisoformat(snap["timestamp"])
            except Exception:
                ts_dt = datetime.now(timezone.utc)

            ts_sec  = int(ts_dt.timestamp())
            ts_usec = ts_dt.microsecond

            for ac_idx, ac in enumerate(aircraft_list):
                if ac.get("latitude") is None or ac.get("longitude") is None:
                    continue

                # Slightly offset usec per aircraft x category to avoid duplicate timestamps
                for cat_offset, cat_num in enumerate(categories):
                    builder_fn = BUILDERS[cat_num][0]
                    rec_us_raw = ts_usec + ac_idx * 500 + cat_offset * 100
                    rec_sec    = ts_sec  + rec_us_raw // 1_000_000
                    rec_us     = rec_us_raw % 1_000_000

                    try:
                        asterix = builder_fn(ac, rec_sec, rec_us)
                    except Exception as exc:
                        cs = (ac.get("callsign") or ac.get("icao24") or "?").strip()
                        print(f"  [WARN] snap={snap_idx} cat={cat_num} ac={cs}: {exc}")
                        continue

                    pkt = build_scapy_packet(asterix, cat_num, rec_sec, rec_us)
                    pcap.write(pkt)
                    total_records += 1

            if (snap_idx + 1) % 10 == 0 or snap_idx == len(snapshots) - 1:
                print(f"  Snapshot {snap_idx+1:3d}/{len(snapshots)}"
                      f"  ac={len(aircraft_list)}"
                      f"  records_this_snap={len(aircraft_list)*len(categories)}"
                      f"  ts={ts_dt.strftime('%H:%M:%S')} UTC")

    print(f"\n{'─'*70}")
    print(f"  Done! {total_records} total ASTERIX records written to '{output_path}'")
    print(f"\n  Open in Wireshark:")
    print(f"    wireshark {output_path}")
    print(f"\n  Wireshark tips:")
    print(f"    -> Edit > Preferences > Protocols > ASTERIX  (enable dissector)")
    for cat_num in categories:
        _, dp = PORTS[cat_num]
        desc  = BUILDERS[cat_num][1]
        print(f"    -> {desc}  (UDP port {dp})")
    print(f"{'─'*70}\n")


# ════════════════════════════════════════════════════════════════════════════
#  Entry point
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Convert flight_data.json -> ASTERIX PCAP (CAT048 / CAT062)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python json_to_asterix.py                            # CAT048 only (default)
  python json_to_asterix.py -c 062                     # CAT062 only
  python json_to_asterix.py -c all                     # both categories
  python json_to_asterix.py flight_data.json out.pcap
  python json_to_asterix.py flight_data.json out.pcap -c all
""")
    parser.add_argument("input",  nargs="?", default=INPUT_JSON,  help="Input JSON file")
    parser.add_argument("output", nargs="?", default=OUTPUT_PCAP, help="Output PCAP file")
    parser.add_argument("-c", "--category", default="048",
        help="Category to encode: 048 | 062 | all  (default: 048)")
    args = parser.parse_args()

    cat_arg = args.category.strip().lower()
    if cat_arg == "all":
        categories = [48, 62]
    elif cat_arg in ("048", "48"):
        categories = [48]
    elif cat_arg in ("062", "62"):
        categories = [62]
    else:
        print(f"ERROR: Unknown category '{args.category}'. Use 048, 062, or all.")
        sys.exit(1)

    convert(args.input, args.output, categories)


if __name__ == "__main__":
    main()