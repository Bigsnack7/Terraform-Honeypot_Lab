fields @timestamp, @message
| parse @message /<EventID(?:\s+[^>]*)?>(?<event_id>\d+)<\/EventID>/
| filter event_id in ["1102", "104"] or @message like /(?i)(wevtutil.{0,20}\bcl\b|clear-eventlog)/
| sort @timestamp desc
