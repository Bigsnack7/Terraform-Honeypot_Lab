fields @timestamp, @message
| parse @message /<EventID(?:\s+[^>]*)?>(?<event_id>\d+)<\/EventID>/
| parse @message /<Data Name='TargetSid'>(?<target_sid>[^<]+)<\/Data>/
| filter event_id in ["4720", "4726", "4728", "4733", "4740", "4719"] or (event_id = "4732" and target_sid = "S-1-5-32-544")
| sort @timestamp desc
