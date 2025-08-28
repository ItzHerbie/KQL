This detction rule/Hunting query is specific to infrastructures using xClarity. You will be able to find failed login attempts to your Integrated management Modules (IMM)s

```kql
Syslog
| where Computer == "Enter xClarity Host IP"
| where SyslogMessage contains "login failures" 
| extend appl = extract("appl=([^\\s]+)", 1, SyslogMessage)
| extend service = extract("service=([^\\s]+)", 1, SyslogMessage)
| extend severity = extract("severity=([^\\s]+)", 1, SyslogMessage)
| extend class = extract("class=([^\\s]+)", 1, SyslogMessage)
| extend appladdr = extract("appladdr=([^\\s]+)", 1, SyslogMessage)
| extend user = extract("user=([^\\s]+)", 1, SyslogMessage)
| extend src = extract("src=([^\\s]+)", 1, SyslogMessage)
| extend uuid = extract("uuid=([^\\s]+)", 1, SyslogMessage)
| extend sn = extract("sn=([^\\s]+)", 1, SyslogMessage)
| extend resourceIP = extract("resourceIP=([^\\s]+)", 1, SyslogMessage)
| extend systemName = extract("systemName=([^\\s]+)", 1, SyslogMessage)
| extend seq = extract("seq=([^\\s]+)", 1, SyslogMessage)
| extend EventID = extract("EventID=([^\\s]+)", 1, SyslogMessage)
| extend CommonEventID = extract("CommonEventID=([^\\s]+)", 1, SyslogMessage)
| extend Userid = extract("Userid: ([^\\s]+)", 1, SyslogMessage)
| extend ClientIP = extract("client at IP address ([^\\s]+)", 1, SyslogMessage)
| extend Security = extract("Security: (.*)", 1, SyslogMessage)
| summarize by TimeGenerated, appladdr, user, src, resourceIP, systemName, Userid, ClientIP, Security
