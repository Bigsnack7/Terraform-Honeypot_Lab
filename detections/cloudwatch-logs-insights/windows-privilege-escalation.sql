fields @timestamp, @message
| parse @message /<EventID(?:\s+[^>]*)?>(?<event_id>\d+)<\/EventID>/
| parse @message /<Data Name='SubjectUserSid'>(?<subject_sid>[^<]+)<\/Data>/
| parse @message /<Data Name='TargetSid'>(?<target_sid>[^<]+)<\/Data>/
| filter (event_id = "4672" and subject_sid not in ["S-1-5-18", "S-1-5-19", "S-1-5-20"]) or event_id in ["4697", "4698"] or (event_id = "4732" and target_sid = "S-1-5-32-544")
| sort @timestamp desc
