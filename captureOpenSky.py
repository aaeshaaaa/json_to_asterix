"""
captureOpenSky.py — Abu Dhabi Flight Tracker
Polls the OpenSky Network API every 5 seconds for 20 min.
Saves all captured snapshots to flight_data.json.

Usage:
    pip install requests
    python capture.py

The bounding box covers Abu Dhabi emirate airspace:
    lat: 22.6 – 25.0
    lon: 51.5 – 56.5
"""

import json
import time
import requests
from datetime import datetime, timezone

# ── Abu Dhabi bounding box ──────────────────────────────────────────────────
LAT_MIN, LAT_MAX = 22.6, 25.0
LON_MIN, LON_MAX = 51.5, 56.5

# ── Capture settings ────────────────────────────────────────────────────────
DURATION_SECONDS = 1200   # 20 min 
POLL_INTERVAL    = 5     # seconds between API calls
OUTPUT_FILE      = "flight_data.json"

# ── OpenSky REST endpoint ───────────────────────────────────────────────────
API_URL = (
    "https://opensky-network.org/api/states/all"
    f"?lamin={LAT_MIN}&lomin={LON_MIN}&lamax={LAT_MAX}&lomax={LON_MAX}"
)

# State vector field names (OpenSky docs order)
FIELDS = [
    "icao24", "callsign", "origin_country",
    "time_position", "last_contact",
    "longitude", "latitude", "baro_altitude",
    "on_ground", "velocity",
    "true_track",        # heading in degrees (0 = north, clockwise)
    "vertical_rate",
    "sensors",
    "geo_altitude",
    "squawk",
    "spi",
    "position_source",
]


def fetch_states() -> list[dict]:
    """Call the OpenSky API and return a list of aircraft state dicts."""
    try:
        resp = requests.get(API_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        states = data.get("states") or []
        result = []
        for s in states:
            aircraft = dict(zip(FIELDS, s))
            # Drop None coords — unusable for mapping
            if aircraft.get("latitude") is None or aircraft.get("longitude") is None:
                continue
            result.append(aircraft)
        return result
    except requests.RequestException as exc:
        print(f"  [WARNING] API error: {exc}")
        return []


def main():
    print("=" * 60)
    print("  Abu Dhabi Flight Capture — OpenSky Network")
    print(f"  Duration : {DURATION_SECONDS // 60} minutes")
    print(f"  Interval : {POLL_INTERVAL} seconds")
    print(f"  Output   : {OUTPUT_FILE}")
    print("=" * 60)

    snapshots = []
    start_time = time.time()
    end_time   = start_time + DURATION_SECONDS
    poll_num   = 0

    while time.time() < end_time:
        poll_num += 1
        ts = datetime.now(timezone.utc).isoformat()
        elapsed = int(time.time() - start_time)
        remaining = int(end_time - time.time())

        print(f"\n[Poll #{poll_num}] {ts}  |  elapsed {elapsed}s  |  {remaining}s remaining")

        aircraft_list = fetch_states()
        print(f"  → {len(aircraft_list)} aircraft found")

        snapshot = {
            "timestamp": ts,
            "elapsed_seconds": elapsed,
            "aircraft": aircraft_list,
        }
        snapshots.append(snapshot)

        # Print quick summary
        for ac in aircraft_list[:5]:
            cs  = (ac.get("callsign") or "??????").strip() or "??????"
            lat = ac.get("latitude",  "?")
            lon = ac.get("longitude", "?")
            alt = ac.get("baro_altitude") or ac.get("geo_altitude") or "?"
            spd = ac.get("velocity") or "?"
            hdg = ac.get("true_track") or "?"
            print(f"    {cs:<8} lat={lat:.3f} lon={lon:.3f} alt={alt}m spd={spd}m/s hdg={hdg}°")
        if len(aircraft_list) > 5:
            print(f"    … and {len(aircraft_list) - 5} more")

        # Save after every poll so data isn't lost on interrupt
        with open(OUTPUT_FILE, "w") as f:
            json.dump({
                "capture_start": datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat(),
                "bounding_box": {
                    "lat_min": LAT_MIN, "lat_max": LAT_MAX,
                    "lon_min": LON_MIN, "lon_max": LON_MAX,
                },
                "poll_interval_seconds": POLL_INTERVAL,
                "snapshots": snapshots,
            }, f, indent=2)

        # Wait until next poll (account for time spent fetching)
        sleep_for = POLL_INTERVAL - (time.time() % POLL_INTERVAL)
        if sleep_for < 1:
            sleep_for = POLL_INTERVAL
        if time.time() + sleep_for < end_time:
            time.sleep(sleep_for)

    print("\n" + "=" * 60)
    print(f"  Capture complete! {len(snapshots)} snapshots saved to {OUTPUT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()
