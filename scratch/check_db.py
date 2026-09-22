import os
import sqlite3

for root, dirs, files in os.walk('.'):
    for f in files:
        if f.endswith('.db'):
            p = os.path.join(root, f)
            print(f"Found DB: {p}")
            con = sqlite3.connect(p)
            cur = con.cursor()
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            print("  Tables:", tables)
            if 'privacy_events' in tables:
                cols = [c[1] for c in cur.execute("PRAGMA table_info(privacy_events)").fetchall()]
                print("  privacy_events columns:", cols)
            con.close()
