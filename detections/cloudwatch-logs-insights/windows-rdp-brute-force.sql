fields @timestamp, @message
| parse @message /<EventID(?:\s+[^>]*)?>(?<event_id>\d+)<\/EventID>/
| parse @message /<Data Name="IpAddress">(?<src_ip>[^<]+)<\/Data>/
| filter event_id = "4625" and ispresent(src_ip) and src_ip != "-"
| stats failures = count(*) by src_ip, bin(5m)
| filter failures >= 5
| sort failures desc
