import json, time, requests, os

LOG_FILE = "/logs/cowrie.json"
INGEST_URL = "https://ingestion-production-c968.up.railway.app/ingest/event"

print("Waiting for log file...")
while not os.path.exists(LOG_FILE):
    time.sleep(2)

print("Sender started!")
with open(LOG_FILE, "r") as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        try:
            event = json.loads(line.strip())
            r = requests.post(INGEST_URL, json=event, timeout=5)
            print(f"Sent: {event.get('eventid')} → {r.status_code}")
        except Exception as e:
            print(f"Error: {e}")