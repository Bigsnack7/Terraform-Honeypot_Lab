fields @timestamp, src_ip, username
| filter eventid = "cowrie.login.failed"
| stats attempts = count(*), usernames = count_distinct(username) by src_ip
| filter attempts >= 6
| sort attempts desc
