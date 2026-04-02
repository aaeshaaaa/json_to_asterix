# json_to_asterix

Capture live ADS-B flights and convert them into ASTERIX **CAT048** and **CAT062** PCAP files.  
Pure Python — no dependencies except `requests` and `scapy`.

---

## Files

| File | Description |
|---|---|
| `captureOpenSky.py` | Captures live flights from OpenSky Network and saves to `flight_data.json` |
| `json_to_asterix.py` | Converts `flight_data.json` into an ASTERIX PCAP (CAT048, CAT062, or both) |
| `flight_data_test.json` | Sample dataset — 6 aircraft over Abu Dhabi, 5 s interval, 10 min |
| `output.pcap` | Sample output — open directly in Wireshark |

---

## Step 1 — Capture

```bash
pip install requests
python captureOpenSky.py
```

Polls OpenSky Network every **5 seconds** for **20 minutes** over Abu Dhabi airspace and saves all snapshots to `flight_data.json`. The file is written after every poll so it is safe to stop early with Ctrl+C.

Bounding box (configurable at the top of the script):

```
lat: 22.6 – 25.0 N
lon: 51.5 – 56.5 E
```

---

## Step 2 — Convert

```bash
pip install scapy
python json_to_asterix.py                          # CAT048 only (default)
python json_to_asterix.py -c 062                   # CAT062 only
python json_to_asterix.py -c all                   # CAT048 + CAT062 in one PCAP
python json_to_asterix.py input.json output.pcap   # custom file names
python json_to_asterix.py -h                       # help
```

---

## ASTERIX compliance

| Category | Specification | Encoded fields |
|---|---|---|
| **CAT048** | EUROCONTROL-SPEC-0149-4 Ed 1.25 | I010, I140, I040, I070, I090, I161, I042, I200, I220, I240 |
| **CAT062** | EUROCONTROL-SPEC-0149-9 Ed 1.19 | I010, I070, I040, I100, I185, I130, I245 |

Radar origin: **Abu Dhabi International Airport (OMAA)** — SAC=25, SIC=13.  
Configurable at the top of `json_to_asterix.py`.

---

## Wireshark

Open the PCAP and enable the ASTERIX dissector:  
**Edit → Preferences → Protocols → ASTERIX**
