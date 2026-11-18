fields @timestamp, @message
| parse @message /<EventID(?:\s+[^>]*)?>(?<event_id>\d+)<\/EventID>/
| filter event_id in ["4672", "4697", "4698"]
| sort @timestamp desc
