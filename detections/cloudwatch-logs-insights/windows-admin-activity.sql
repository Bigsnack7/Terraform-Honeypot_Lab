fields @timestamp, @message
| parse @message /<EventID(?:\s+[^>]*)?>(?<event_id>\d+)<\/EventID>/
| filter event_id in ["4672", "4720", "4728", "4732", "4733", "4740", "4719"]
| sort @timestamp desc
