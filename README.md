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

## STEP 2 – Install TheHive Python Module

```bash
sudo /var/ossec/framework/python/bin/pip3 install thehive4py
