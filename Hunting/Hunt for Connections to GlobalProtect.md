Details Coming Soon!

```kql
let ipRanges = dynamic([
"ENTER SUBNET FOR GLOBAL PROTECT",
"ENTER SUBNET FOR GLOBAL PROTECT"
]);
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where DeviceCustomString1 == "ENTER GLOBALPROTECT FIRLEWALL POLICY NAME" or DeviceCustomString1 == "ENTER GLOBALPROTECT FIRLEWALL POLICY NAME"
| where ipv4_is_in_any_range(tostring(SourceIP), ipRanges)
| summarize by SourceUserName, SourceIP, DeviceCustomString1
