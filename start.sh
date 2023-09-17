#!/bin/bash
cd ~/domain-manager
git reset --hard HEAD
git pull
python3 -m pip install -r src/requirements.txt
sleep 1
echo "Existing Processes: $(ps -x | grep "python3 src/main.py" | grep -v "grep")"
if [ $(ps -x | grep "python3 src/main.py" | grep -v "grep" | awk '{print $1}' | wc -l) -gt 0 ]; then
        echo "Stopping Process: $(ps -x | grep "python3 src/main.py" | grep -v "grep")"
        ps -x | grep "python3 src/main.py" | grep -v "grep" | awk '{print $1}' | xargs kill
fi
sleep 1
echo "Starting Process"
python3 src/main.py