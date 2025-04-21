
# 🛡️ SOC Automation Lab

A hands-on project that simulates a modern blue-team SOC environment using a fully automated detection and response pipeline. Designed for aspiring SOC analysts and blue-team enthusiasts, this lab demonstrates how to integrate tools like **Wazuh**, **Sysmon**, **Shuffle**, **TheHive**, and **VirusTotal** into a streamlined, automated workflow capable of detecting, enriching, and responding to real-world threats like **Mimikatz**.

🔗 [Read the full blog post on Medium](https://medium.com/@vinuvarshith95/building-a-soc-automation-lab-phase-1-5f576b8b4497)

## 📌 Table of Contents

- [Overview]
- [Tools Used]
- [Setting Up the SOC Lab]
- [Simulating Attacks and Automation]
- [Architecture]
- [Detection Rule for Mimikatz]
- [Automation with Shuffle]
- [Threat Intelligence Enrichment]
- [Case Management and Alerting]
- [Project Highlights](
- [Conclusion]



## 🧠 Overview

The goal is to build an automated mini-SOC lab from scratch, where:

- Sysmon collects telemetry data from a Windows machine.
- Wazuh detects suspicious behavior using custom rules.
- Shuffle automates enrichment and responses.
- TheHive receives structured incidents for case management.
- Email alerts notify analysts in real-time.



## 🔧 Tools Used

| Tool       | Purpose                                      |
|------------|----------------------------------------------|
| **Wazuh**  | SIEM platform for log collection and alerting |
| **Sysmon** | Windows event logging for telemetry           |
| **TheHive**| Incident response & case management           |
| **Shuffle**| SOAR platform for automation workflows        |
| **VirusTotal** | Threat intelligence enrichment (hashes)  |
| **Windows 11**| Endpoint for attack simulation             |
| **DigitalOcean** | Cloud platform to host Linux services  |



## Setting Up the SOC Lab

### 1. Deploy Windows 11 Client (Locally)

- Installed **Sysmon** using SwiftOnSecurity’s configuration.
- Modified Wazuh agent's `ossec.conf` to forward Sysmon logs:
  ```xml
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  ```

### 2. Deploy Wazuh Manager on DigitalOcean

- Deployed **Ubuntu 22.04 Droplet** on DigitalOcean.
- Installed Wazuh using the official script:
  ```bash
  curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
  sudo bash ./wazuh-install.sh -a
  ```
- Registered the Windows endpoint using Wazuh Agent.

### 3. Install TheHive on DigitalOcean

- Launched a second **Ubuntu 22.04 Droplet** on DigitalOcean.
- Installed dependencies:
  - **OpenJDK**, **Cassandra**, **Elasticsearch**, and **TheHive**
- Created an admin user and generated an API key for automation.



## Simulating Attacks and Automation

### Simulating Credential Dumping with Mimikatz

1. Added an exception in Windows Defender for the `Downloads` folder.
2. Renamed `mimikatz.exe` to `you_are_awesome.exe` to simulate stealthy malware behavior.
3. Executed it to generate telemetry logs via Sysmon.

### Enabling Archive Logging in Wazuh

To log *all* data (not just alerts):

```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```

Also modified Filebeat config on the Wazuh server:
```yaml
archives:
  enabled: true
```

Created a new Kibana index pattern:
- `wazuh-archives-*`
- Time field: `@timestamp`



## Architecture

![SOC_automation](https://github.com/user-attachments/assets/a42f7f13-dd99-42f0-8e3e-ec1dc44d4517)


## Detection Rule for Mimikatz

### Why?
Even if the executable is renamed, the internal metadata reveals its original identity.

### Wazuh Custom Rule:
```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
  <description>Mimikatz usage detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

- Placed in `/var/ossec/etc/rules/local_rules.xml`
- Restarted Wazuh Manager to apply changes.



## Automation with Shuffle

### Webhook Setup

- Created a Shuffle workflow.
- Added **Webhook trigger node**.
- Modified Wazuh integration:
```xml
<integration>
  <name>custom</name>
  <hook_url>https://your-shuffle-webhook</hook_url>
  <rule_id>100002</rule_id>
</integration>
```

### Extracting Hash with Regex

- Used the `Rex` app in Shuffle to extract SHA256:
```regex
sha256=([a-fA-F0-9]{64})
```



## Threat Intelligence Enrichment

### VirusTotal in Shuffle

- API used to fetch file reputation using SHA256.
- Output:
  - File name
  - Detection count (malicious/total)
  - File type
  - Antivirus flags

Example:
```
SHA256: abcd...
Malicious Detections: 21/70
File: mimikatz.exe
```



## Case Management and Alerting

### TheHive Integration

- Connected via API key.
- Shuffle workflow creates a **new case** in TheHive.
- Case includes:
  - Hostname
  - IP address
  - Timestamp
  - User
  - Rule ID & severity

### Email Alert

- Configured Shuffle’s Email app.
- Sent real-time alerts with threat context.
- Subject: `Mimikatz Alert on [hostname]`
- Includes VirusTotal summary + attacker details.



## Project Highlights

✔️ Built fully from scratch using open-source tools  
✔️ Hosted on DigitalOcean for scalability  
✔️ Real-world attack simulation using Mimikatz  
✔️ Custom rule writing in Wazuh  
✔️ Full integration with SOAR and IR tools  
✔️ Automated alerts and case generation  
✔️ Hands-on red-team vs blue-team perspective



## 🧾 Conclusion

This lab is a practical demonstration of how you can set up and automate detection and response pipelines just like in enterprise SOCs. From telemetry to threat intelligence and incident management, this project covers every major SOC task. It also offers a platform to extend into more advanced detections, playbooks, and threat hunting.

> 💡 Perfect for students, cybersecurity enthusiasts, and blue-teamers looking to gain hands-on SOC experience.

