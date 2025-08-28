// This query is used to identify commands executed on HP-Aruba Top-of-Rack (ToR) switches.

Syslog
| where ipv4_is_in_range(HostIP, "EnterSubnet") // Enter Subnet of where ToR switches are located
| where SyslogMessage contains "AUDIT|CLI"
| extend 
    Time = extract(@"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[-+]\d{2}:\d{2})", 1, SyslogMessage),
    device = extract(@"\s([^\s]+)", 1, SyslogMessage),
    command = extract(@"CLI\s+""([^""]+)""", 1, SyslogMessage),
    user = extract(@"user\s+'([^']+)'", 1, SyslogMessage),
    from_address = extract(@"from address\s+'([^']+)'", 1, SyslogMessage)
| project TimeGenerated, device, Computer, user, command, from_address
| order by TimeGenerated desc
