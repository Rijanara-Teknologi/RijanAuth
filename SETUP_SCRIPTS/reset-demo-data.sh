#!/bin/bash
# reset-demo-data.sh
# Resets the RijanAuth database to initial seeded state

echo "Resetting RijanAuth DB..."
# In dev, we can just delete sqlite file and restart app (setup will run)
# But we need to stop server first.

echo "WARNING: This script expects the server to be stopped."
rm -f apps/db.sqlite3
python force_seed.py # or similar if exist, or let app recreate on start
echo "Database reset complete. Please restart server."
