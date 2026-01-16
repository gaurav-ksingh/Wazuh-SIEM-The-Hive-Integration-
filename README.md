# Wazuh-SIEM-The-Hive-Integration

📌 STEP 1 – Install Python & PIP on Wazuh Server

Update the system and install Python 3:

sudo yum update
sudo yum install python3

📌 STEP 2 – Install TheHive Python Module

Install thehive4py using Wazuh’s internal Python environment:

sudo /var/ossec/framework/python/bin/pip3 install thehive4py


This module is required for sending alerts from Wazuh to TheHive.

📌 STEP 3 – Create Custom Integration Script (Python)

Create the Python script inside the Wazuh integrations directory:

/var/ossec/integrations/custom-w2thive.py

📄 custom-w2thive.py
#!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import re
import logging
import uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

# ---------------- USER CONFIG ----------------
lvl_threshold = 0               # Wazuh rule level threshold (0–15)
suricata_lvl_threshold = 3      # Suricata severity threshold
debug_enabled = False
info_enabled = True
# ---------------------------------------------

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = f'{pwd}/logs/integrations.log'
logger = logging.getLogger(__name__)

logger.setLevel(logging.WARNING)
if info_enabled:
    logger.setLevel(logging.INFO)
if debug_enabled:
    logger.setLevel(logging.DEBUG)

fh = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

def main(args):
    alert_file = args[1]
    hive_api_key = args[2]
    hive_url = args[3]

    hive = TheHiveApi(hive_url, hive_api_key)
    w_alert = json.load(open(alert_file))

    alt = parse_json(w_alert, '', [])
    formatted_alert = markdown_format(alt)
    artifacts = extract_artifacts(formatted_alert)
    alert = build_alert(formatted_alert, artifacts, w_alert)

    if w_alert['rule']['groups'] == ['ids', 'suricata']:
        if 'data' in w_alert and 'alert' in w_alert['data']:
            if int(w_alert['data']['alert']['severity']) <= suricata_lvl_threshold:
                send_alert(alert, hive)
    elif int(w_alert['rule']['level']) >= lvl_threshold:
        send_alert(alert, hive)

def parse_json(data, prefix, alt):
    for key, value in data.items():
        if isinstance(value, dict):
            parse_json(value, prefix + '.' + key, alt)
        else:
            alt.append(prefix + '.' + key + '|||' + str(value))
    return alt

def markdown_format(alt):
    md = ''
    sections = {}
    for line in alt:
        line = line[1:]
        key = line.split('|||')[0].split('.')[0]
        sections.setdefault(key, []).append(line)

    for section, items in sections.items():
        md += f'### {section.capitalize()}\n| Key | Value |\n|-----|-------|\n'
        for i in items:
            k, v = i.split('|||')
            md += f'| **{k}** | {v} |\n'
    return md

def extract_artifacts(text):
    artifacts = {
        'ip': re.findall(r'\d+\.\d+\.\d+\.\d+', text),
        'url': re.findall(r'https?://[^\s]+', text),
        'domain': []
    }
    for url in artifacts['url']:
        artifacts['domain'].append(url.split('//')[1].split('/')[0])
    return artifacts

def build_alert(desc, artifacts_dict, w_alert):
    artifacts = []
    for k, v in artifacts_dict.items():
        for val in v:
            artifacts.append(AlertArtifact(dataType=k, data=val))

    return Alert(
        title=w_alert['rule']['description'],
        tlp=2,
        tags=[
            'wazuh',
            f"rule={w_alert['rule']['id']}",
            f"agent={w_alert.get('agent', {}).get('name', 'N/A')}"
        ],
        description=desc,
        type='wazuh_alert',
        source='wazuh',
        sourceRef=str(uuid.uuid4())[:6],
        artifacts=artifacts
    )

def send_alert(alert, hive):
    res = hive.create_alert(alert)
    if res.status_code == 201:
        logger.info(f"Alert sent to TheHive: {res.json()['id']}")
    else:
        logger.error(f"Failed to send alert: {res.text}")

if __name__ == "__main__":
    main(sys.argv)

📌 STEP 4 – Create Bash Wrapper Script

Create a shell script (no extension):

/var/ossec/integrations/custom-w2thive

📄 custom-w2thive
#!/bin/sh

WPYTHON_BIN="framework/python/bin/python3"
SCRIPT_NAME="$(basename "$0")"
DIR_NAME="$(cd "$(dirname "$0")" && pwd)"
WAZUH_PATH="$(cd "$DIR_NAME/.." && pwd)"

PYTHON_SCRIPT="$DIR_NAME/$SCRIPT_NAME.py"
$WAZUH_PATH/$WPYTHON_BIN $PYTHON_SCRIPT "$@"

📌 STEP 5 – Set Permissions & Ownership
sudo chmod 755 /var/ossec/integrations/custom-w2thive.py
sudo chmod 755 /var/ossec/integrations/custom-w2thive
sudo chown root:wazuh /var/ossec/integrations/custom-w2thive.py
sudo chown root:wazuh /var/ossec/integrations/custom-w2thive

📌 STEP 6 – Enable Integration in Wazuh

Edit the Wazuh configuration file:

sudo nano /var/ossec/etc/ossec.conf


Add the following below the <global> tag:

<integration>
  <name>custom-w2thive</name>
  <hook_url>http://THEHIVE_SERVER_IP:9000</hook_url>
  <api_key>YOUR_THEHIVE_API_KEY</api_key>
  <alert_format>json</alert_format>
</integration>

🔄 Restart Wazuh Manager
sudo systemctl restart wazuh-manager

✅ Verification

Generate a Wazuh alert

Navigate to TheHive → Alerts

Confirm alerts are being created successfully
