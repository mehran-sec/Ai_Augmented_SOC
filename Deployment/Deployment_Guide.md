# Deployment Guide

How to run the AI-Augmented SOC pipeline: **Wazuh** (native on the host) → **n8n** (Docker) → AbuseIPDB / VirusTotal / Claude → Slack, Jira and a Google Sheet audit log.

## What you need first

- A host with Wazuh already installed and running 
- Docker and Docker Compose
- Accounts and keys for:
    AbuseIPDB, 
    VirusTotal,
    Any LLM API Key,
    Jira Cloud project, 
    Google account (for the audit sheet) 
    Slack Incoming Webhook

## Step 1: Start n8n

From the `Deployment/` folder:

```bash
docker compose -f docker-compose.n8n.yml up -d
docker ps --filter name=n8n
```



Open `http://localhost:5678` and create the owner account.

## Step 2: Create the credentials in n8n

Create these under **Credentials → Create credential**:

| Credential type | Settings | Used by |
|---|---|---|
| **Header Auth** | Name `X-Webhook-Token`, value from `openssl rand -hex 32` | Webhook |
| **Header Auth** | Name `Key`, value is your AbuseIPDB API key | Query AbuseIPDB |
| **VirusTotal API** | Your VirusTotal API key | Query VT IP, Hash, Domain, URL |
| **LLM API** | ANY LLM API key | I used Gemini Chat Model |
| **Jira Software Cloud API** | Site URL, email, API token | Create Jira Issue |
| **Google Sheets OAuth2 API** | Follow n8n's Google sign-in flow | Audit Log |



## Step 3: Import and prepare the workflow

1. In n8n choose **Workflows → Import from File** and select `n8n-workflow.v2.json`.
2. Open each node that shows a missing credential and select the one you created. The import leaves placeholders.
3. Re-pick the choices that depend on your accounts:
   - **Create Jira Issue:** project and issue type.
   - **Audit Log (Google Sheet):** the spreadsheet.
   - **Chat Model:** the model.
4. Open the **Slack** node and replace `YOUR_SLACK_WEBHOOK_URL_HERE` with your Slack Incoming Webhook URL.

5. Create a tab named `Audit` in your Google Sheet. Put this header row in row 1, exactly as written:

```
logged_at, alert_time, outcome, reason, gate_reasons, verdict, confidence, floor_applied, rule_id, rule_level, rule_description, agent_name, user, src_ip, ip_category, file_hash, domain, url, ioc_hits, lookup_failures, suppressed_prior, fingerprint, malformed_excerpt
```

7. **Activate** the workflow with the toggle at the top right. The production webhook URL only works while the workflow is active.

## Step 4: Connect Wazuh to n8n

Run these on the  wazuh host


```bash
sudo cp Integration/bash      /var/ossec/integrations/custom-n8n
sudo cp Integration/python.py /var/ossec/integrations/custom-n8n.py
sudo chown root:wazuh /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py
sudo chmod 750        /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py
```



**Add the integration block** to `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`:

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://127.0.0.1:5678/webhook/wazuh-alerts</hook_url>
  <api_key>SAME_TOKEN_AS_THE_N8N_CREDENTIAL</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```


**Restart and check:**

```bash
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-control status | grep integratord
sudo tail -f /var/ossec/logs/integrations.log
```

`wazuh-integratord is running` should appear. 

## Step 5: Test it

Use the production URL (`/webhook/`), not `/webhook-test/`.

```bash
URL=http://localhost:5678/webhook/wazuh-alerts
TOKEN=your_token

curl -s -X POST $URL -H 'Content-Type: application/json' -H "X-Webhook-Token: $TOKEN" -d '{
  "timestamp": "2026-10-17T10:00:00.000+0000",
  "rule_id": "5763", "rule_description": "sshd: brute force trying to get access to the system.",
  "rule_level": 10, "agent_id": "001", "agent_name": "web01",
  "user": "root", "src_ip": "185.220.101.1", "command": null,
  "full_log": "Failed password for root from 185.220.101.1 port 51422 ssh2",
  "raw_alert": {
    "rule": {"id": "5763", "level": 10, "description": "sshd: brute force trying to get access to the system.",
             "groups": ["syslog","sshd","authentication_failures"], "mitre": {"id": ["T1110"]}},
    "agent": {"id": "001", "name": "web01"},
    "data": {"srcip": "185.220.101.1", "srcuser": "root"}
  }
}'
```


## Changes: 
- **Rotating the webhook token:** change the n8n credential and the `<api_key>` in `ossec.conf` together, then restart the manager.
- **Changing thresholds:** edit the `Config` node. There is nothing else to change in the workflow.
