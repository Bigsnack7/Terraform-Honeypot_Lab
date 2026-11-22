# Terraform Honeypot Lab

**An AWS security lab for collecting and investigating activity across Linux, web, and Windows honeypots.**

> **At a glance:** Three isolated decoys · centralized CloudWatch telemetry · nine investigation queries · GitHub Actions with AWS OIDC.

## What I built

Terraform provisions three opt-in decoys:

- **Cowrie SSH**, a **Flask web decoy**, and a **Windows RDP decoy**.
- Separate VPCs, subnets, and security groups, with listener ingress opt-in and CIDR-restricted. No public SSH/RDP admin rules; Systems Manager is the intended management path.
- CloudWatch host/application telemetry, CloudTrail management events, and nine saved Logs Insights queries for analyst-led investigations.
- GitHub Actions deployment with short-lived AWS OIDC credentials and separate plan/apply roles.

## Validation highlights

Redacted evidence demonstrates these controlled test paths:

| Test | What the evidence demonstrates |
|---|---|
| Cowrie SSH | Connection, authentication, command, and session events reached CloudWatch |
| Web form | POST field names and a honeytoken were logged; password values were not |
| Windows | Heartbeat, Security, and Sysmon samples reached CloudWatch |
| RDP failure query | Event 4625 records were grouped; the `>= 5` threshold returned bins with 9 and 8 failures |

Evidence is point-in-time, not proof of continuous health or complete Windows coverage. Queries are analyst-run, not scheduled alerts. See [validation limits](README-DETAILS.md#validation-status).

## Technology

`AWS` · `Terraform` · `CloudWatch` · `CloudTrail` · `IAM OIDC` · `GitHub Actions` · `Sysmon` · `Cowrie` · `Python`

## Explore

- [Technical guide: architecture, setup, security, and costs](README-DETAILS.md)
- [Detection query guide](detections/cloudwatch-logs-insights/README.md)
- [Redacted deployment evidence](docs/deployment-evidence/)

## Safety and cost

Honeypots are intentionally exposed and incur AWS charges; budget alerts do not cap spending. Review the plan, CIDRs, and costs before deploying, then tear down resources. See the technical guide for details.

## Author

**Oludemi Joshua** · Cybersecurity · Cloud Security · Blue Team · Security Automation
