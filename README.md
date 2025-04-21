# SOC Automation Lab: End-to-End Detection and Response

Welcome to the SOC Automation Lab — a fully hands-on cybersecurity project designed to help aspiring blue teamers, SOC analysts, and cybersecurity enthusiasts learn how to build, automate, and manage security detection and incident response using open-source tools.

This document serves as a complete guide and documentation for replicating the SOC Automation Lab environment, inspired by industry best practices and built from scratch with practical insight.



## 🧭 Table of Contents

1. [Introduction](#introduction)
2. [Project Goals](#project-goals)
3. [Lab Environment Setup](#lab-environment-setup)
4. [Installing and Configuring Wazuh](#installing-and-configuring-wazuh)
5. [Installing Sysmon on Windows](#installing-sysmon-on-windows)
6. [Ingesting Telemetry into Wazuh](#ingesting-telemetry-into-wazuh)
7. [Custom Rule Creation for Mimikatz Detection](#custom-rule-creation-for-mimikatz-detection)
8. [Introducing Shuffle (SOAR)](#introducing-shuffle-soar)
9. [Integrating TheHive for Alert Management](#integrating-thehive-for-alert-management)
10. [Building the Automation Workflow](#building-the-automation-workflow)
11. [Enriching with VirusTotal](#enriching-with-virustotal)
12. [Active Response with IP Blocking](#active-response-with-ip-blocking)
13. [Email Alerts and Analyst Decision-making](#email-alerts-and-analyst-decision-making)
14. [Conclusion](#conclusion)



## Introduction

In today’s threat landscape, incident response needs to be proactive, fast, and automated. Traditional SOCs often suffer from alert fatigue, inefficient triage, and delays in responding to threats. The SOC Automation Lab tackles these issues by integrating three powerful open-source tools:

- **Wazuh**: For log management, threat detection, and alerting.
- **Shuffle**: As a SOAR platform to automate workflows and orchestrate actions.
- **TheHive**: For case and alert management.

By the end of this lab, you'll be able to detect a credential-dumping tool like **Mimikatz**, extract forensic data, enrich it, alert analysts, and even trigger a blocking action — all automatically.

## Project Goals

- Build a modular and scalable SOC automation lab.
- Detect advanced attacker behaviors using custom detection logic.
- Automate alert triage, data enrichment, and responsive action.
- Learn practical implementation of SOAR principles.
- Understand how open-source tools can integrate into an enterprise-grade security stack.

## Lab Environment Setup

### Hardware & Software Requirements

- **Host Machine**: At least 16GB RAM, 100GB SSD, and virtualization support.
- **VirtualBox or VMware**: To run VMs for Linux and Windows.
- **Operating Systems**:
  - Windows 10 (with Sysmon)
  - Ubuntu 22.04 LTS (Wazuh, TheHive, Shuffle)

You can also deploy Wazuh and TheHive to the cloud (DigitalOcean, AWS, etc.) using minimal droplets (2vCPU, 4GB RAM).

### Tools

| Tool | Purpose |
|------|---------|
| Wazuh | Detection, Log Management |
| Sysmon | Windows Event Telemetry |
| Shuffle | SOAR & Workflow Automation |
| TheHive | Alert and Case Management |
| VirusTotal | Threat Intelligence Enrichment |

## Installing and Configuring Wazuh

Follow these steps to set up Wazuh on a fresh Ubuntu 22.04 instance:

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Access the dashboard at `https://your-public-ip` with credentials:

```
User: admin
Password: (as generated during install)
```

## Installing Sysmon on Windows

On your Windows 10 VM:

1. Download Sysmon from Microsoft Sysinternals.
2. Get a configuration file (e.g., from SwiftOnSecurity’s Sysmon config repo).
3. Install with:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Verify logs under Event Viewer > Applications and Services > Microsoft > Windows > Sysmon.

## Ingesting Telemetry into Wazuh

Edit the `ossec.conf` file on the Windows agent:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the Wazuh agent service and check if Sysmon logs are visible on the Wazuh dashboard.

## Custom Rule Creation for Mimikatz Detection

Create a custom rule that detects Mimikatz based on original filename:

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

Save it to `local_rules.xml` and restart the Wazuh manager.

## Introducing Shuffle (SOAR)

Register an account at [Shuffle](https://shuffler.io) and create a new workflow. Use the **Webhook** trigger to accept events from Wazuh. Add a basic logic node to extract the alert fields.

Configure Wazuh’s `ossec.conf` to include:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/your-hook-id</hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Restart Wazuh and verify that Mimikatz alerts are sent to Shuffle.

## Integrating TheHive for Alert Management

Deploy TheHive on Ubuntu using StrangeBee’s packages.

Create an admin account and a separate user for Shuffle with an API key. In Shuffle, connect to TheHive and authenticate using that API key.

Drag in TheHive into your workflow and configure the `Create Alert` action.

## Building the Automation Workflow

Your final workflow should resemble:

- Webhook → Extract Hash → VirusTotal → TheHive → Email

In the logic step, extract `SHA256` using regex. In VirusTotal, query the hash and get results. Use the response to populate the alert fields in TheHive.

## Enriching with VirusTotal

Sign up at [VirusTotal](https://virustotal.com), grab your API key, and connect it to Shuffle.

Use the “Hash Report” action to fetch enrichment data. For example:

```json
{
  "id": "{{sha256}}"
}
```

Parse out the `last_analysis_stats.malicious` count to determine threat confidence.

## Active Response with IP Blocking

Wazuh supports Active Responses. You can execute firewall rules using built-in commands like `firewalldrop`. Add this configuration:

```xml
<active-response>
  <command>firewalldrop</command>
  <location>local</location>
  <level>10</level>
  <timeout>0</timeout>
</active-response>
```

You can then call this via Shuffle using the Wazuh API integration.

## Email Alerts and Analyst Decision-making

Use the **Email** app in Shuffle to notify the SOC team. Populate the message with variables from the alert (hostname, timestamp, severity).

You can also integrate a **User Input** node to ask analysts whether to proceed with response (e.g., block IP). If yes, trigger the active response.

## Conclusion

This SOC Automation Lab gives you a powerful, customizable, and fully open-source ecosystem to learn and practice blue team skills. You’ve seen how to:

- Detect credential abuse tools like Mimikatz.
- Build rules and trigger alerts.
- Enrich events using threat intel.
- Automate the triage and case creation process.
- Respond actively to malicious behaviors.

Automation isn’t about replacing analysts — it’s about freeing them from repetitive tasks so they can focus on real threats.



## 🚀 Next Steps

- Integrate MISP for threat intelligence sharing.
- Add Cortex analyzers for deeper enrichment.
- Automate Slack/Discord notifications.
- Include DNS or network-level telemetry.



## 🙏 Acknowledgments

Special thanks to the open-source communities behind Wazuh, Shuffle, and TheHive. This lab is inspired by many DFIR professionals sharing their knowledge openly.



## 📎 License

This repository is under MIT License.
