#!/bin/bash
cd ~/domain-manager/src
git pull
python3 -m pip install -r requirements.txt
sleep 1
echo "Existing Processes: $(ps -x | grep "python3 main.py" | grep -v "grep")"
if [ $(ps -x | grep "python3 main.py" | grep -v "grep" | awk '{print $1}' | wc -l) -gt 0 ]; then
        echo "Stopping Process: $(ps -x | grep "python3 main.py" | grep -v "grep")"
        ps -x | grep "python3 main.py" | grep -v "grep" | awk '{print $1}' | xargs kill
fi
sleep 1
echo "Starting Process"
python3 main.py &> ./stdout 2> ./stderr &
cat ./stderr
tail -f ./stdout