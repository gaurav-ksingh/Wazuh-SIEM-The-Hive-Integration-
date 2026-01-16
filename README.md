# Wazuh-SIEM-The-Hive-Integration

# 🔗 Wazuh to TheHive Integration (Custom Python Script)

This repository demonstrates how to integrate **Wazuh Manager** with **TheHive** using a **custom Python integration** to forward Wazuh alerts into TheHive for incident response and case management.

---

## 🧪 Environment

- Wazuh Manager (OVA / VirtualBox)
- TheHive v5.2.1
- OSSEC Path: `/var/ossec`
- Python not preinstalled by default

---

## STEP 1 – Install Python & PIP

```bash
sudo yum update
sudo yum install python3
```


## STEP 2 – Install TheHive Python Module

```bash
sudo /var/ossec/framework/python/bin/pip3 install thehive4py

```

## STEP 3 – Create Custom Python Integration
File Path

```bash
/var/ossec/integrations/custom-w2thive.py

```
## Put below script in w2hive.py

```bash
#!/var/ossec/framework/python/bin/python3
import json, sys, os, re, logging, uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

lvl_threshold = 0
suricata_lvl_threshold = 3

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = f"{pwd}/logs/integrations.log"

logging.basicConfig(filename=log_file, level=logging.INFO)

def main(args):
    alert_file = args[1]
    api_key = args[2]
    hive_url = args[3]

    hive = TheHiveApi(hive_url, api_key)
    alert_json = json.load(open(alert_file))

    description = json.dumps(alert_json, indent=2)
    artifacts = []

    for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', description):
        artifacts.append(AlertArtifact(dataType='ip', data=ip))

    alert = Alert(
        title=alert_json['rule']['description'],
        tlp=2,
        tags=['wazuh', f"rule_id={alert_json['rule']['id']}"],
        description=description,
        type='wazuh_alert',
        source='wazuh',
        sourceRef=str(uuid.uuid4())[:6],
        artifacts=artifacts
    )

    if int(alert_json['rule']['level']) >= lvl_threshold:
        hive.create_alert(alert)

if __name__ == "__main__":
    main(sys.argv)

```
STEP 4 – Create Bash Wrapper Script
File Path
```bash
/var/ossec/integrations/custom-w2thive
```
```bash
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"
SCRIPT_NAME="$(basename "$0")"
DIR_NAME="$(cd "$(dirname "$0")" && pwd)"
WAZUH_PATH="$(cd "$DIR_NAME/.." && pwd)"

$WAZUH_PATH/$WPYTHON_BIN $DIR_NAME/$SCRIPT_NAME.py "$@"

```
