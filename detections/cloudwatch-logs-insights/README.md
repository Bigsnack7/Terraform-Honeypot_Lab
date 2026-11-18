# CloudWatch Logs Insights Detections

These queries are the AWS-native, version-controlled translations of the Azure
Sentinel/KQL hunting and detection objectives. Terraform creates them as saved
CloudWatch Logs Insights query definitions. They do not execute on a schedule by
themselves; run them from CloudWatch Logs Insights and select an appropriate,
bounded time range. A scheduled per-source detector would require a query processor
and additional service/query costs, so this budget deployment does not silently
create one.

The Windows queries parse CloudWatch Agent XML event records. Validate the actual
CloudWatch Agent output from the target Windows Server AMI before relying on XML field
parsing. Windows audit/Sysmon/PowerShell collection is configured for the event IDs
the Azure DCR missed; no detection is considered verified until a sample event has
been observed and the query tested against it.

Credential-related Cowrie events may contain attacker-submitted passwords. Access to
the log groups should be restricted and retention kept short. Web form submissions
record field names and a credential-submission flag, not raw password values.

| Query | Source | Objective |
|---|---|---|
| `cowrie-ssh-brute-force.sql` | Cowrie JSON | Six or more failed SSH logins per source in the selected 24-hour query range |
| `cowrie-command-execution.sql` | Cowrie JSON | Successful shell command activity |
| `cowrie-post-exploitation.sql` | Cowrie JSON | Download/execute, persistence, defense-evasion, and credential-file command patterns |
| `windows-rdp-brute-force.sql` | Windows Security XML | Five failed logons per source per five minutes |
| `windows-suspicious-powershell.sql` | PowerShell and Sysmon XML | Encoded commands, download cradles, AMSI and stealth indicators |
| `windows-admin-activity.sql` | Windows Security XML | Special privileges, account/group changes, lockouts, and audit-policy changes |
| `windows-privilege-escalation.sql` | Windows Security XML | Special privileges, service installation, and scheduled-task creation |
| `windows-event-log-clearing.sql` | Windows Security XML | Security/System log clearing and clearing commands |
| `web-path-scanning.sql` | Web decoy JSON | Repeated honeytoken-path probes |

CloudWatch alarms are configured separately for EC2 status checks and explicit
service-health heartbeats. They are operational alarms, not substitutes for these
per-source behavior queries.
