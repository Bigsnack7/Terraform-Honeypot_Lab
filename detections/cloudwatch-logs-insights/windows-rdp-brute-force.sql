fields @timestamp, @message
| parse @message /<EventID(?:\s+[^>]*)?>(?<event_id>\d+)<\/EventID>/
| parse @message /<Data Name='IpAddress'>(?<src_ip>[^<]+)<\/Data>/
| filter event_id = "4625" and ispresent(src_ip) and src_ip != "-"
| stats count(*) as failures by bin(5m) as window, src_ip
| filter failures >= 5
| sort failures desc
