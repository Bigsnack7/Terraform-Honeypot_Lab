fields @timestamp, src_ip, path, honeytoken, method
| filter ispresent(honeytoken)
| stats probes = count(*), paths = count_distinct(path) by src_ip, bin(10m)
| filter probes >= 3
| sort probes desc
