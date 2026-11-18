fields @timestamp, src_ip, session, input
| filter eventid = "cowrie.command.input"
| stats commands = count(*) by src_ip, session
| sort commands desc
