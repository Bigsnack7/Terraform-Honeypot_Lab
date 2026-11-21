fields @timestamp, @message
| filter @message like /(?i)(-encodedcommand|-enc\s|invoke-expression|downloadstring|downloadfile|amsiutils|amsiscanbuffer|executionpolicy\s+bypass|windowstyle\s+hidden|clear-eventlog)/
| filter @message not like /write-health\.ps1/
| sort @timestamp desc
