# json_to_asterix

Convert ADS-B flight data (JSON) into ASTERIX **CAT048** and **CAT062** PCAP files.
No external dependencies — pure Python.

## Usage

```bash
python json_to_asterix.py                          # uses default file names
python json_to_asterix.py input.json output.pcap   # custom names
```

Open the output in Wireshark: **Edit → Preferences → Protocols → ASTERIX**

## What it encodes

| Category | Spec | Fields |
|---|---|---|
| CAT048 | EUROCONTROL-SPEC-0149-4 Ed 1.25 | I010, I140, I020, I040, I070, I090, I130, I161, I220, I240, I042, I200, I170, I230 |
| CAT062 | EUROCONTROL-SPEC-0149-14 | I010, I040, I070, I100, I130, I185, I245 |

## Input

A JSON file with snapshots of aircraft positions — captured live from
**FlightRadar24** or **OpenSky Network**, or generated as a mockup.
A sample dataset (`flight_data_test.json`) is included: 6 aircraft over
Abu Dhabi, 5-second interval, 10 minutes.

## Radar reference point

Default origin: **Abu Dhabi International Airport (OMAA)** — SAC=25, SIC=13.
Configurable at the top of `json_to_asterix.py`.

## Files

| File | Description |
|---|---|
| `json_to_asterix.py` | Main converter |
| `flight_data_test.json` | Sample input |
| `output.pcap` | Sample output — open directly in Wireshark |
