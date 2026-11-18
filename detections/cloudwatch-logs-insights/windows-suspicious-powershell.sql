fields @timestamp, @message
| filter @message like /(?i)(-encodedcommand|-enc\s|invoke-expression|downloadstring|downloadfile|amsiutils|amsiscanbuffer|executionpolicy\s+bypass|windowstyle\s+hidden|clear-eventlog)/
| sort @timestamp desc
