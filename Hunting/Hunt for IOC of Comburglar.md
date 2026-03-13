Recentl blobg post by Black Hills Information Security: https://www.blackhillsinfosec.com/the-curious-case-of-the-comburglar/

```kql
let SuspiciousIPs = dynamic([
"23.95.182.21","38.180.143.167","52.129.44.42","87.121.61.185",
"87.121.61.251","88.99.163.99","104.225.131.18"
]);
let SuspiciousDomains = dynamic([
"techdataservice.us","ch3.techdataservice.us","ch4.techdataservice.us",
"ch6.techdataservice.us","ch7.techdataservice.us","ch9.techdataservice.us",
"console.techdataservice.us","mdns.techdataservice.us",
"push.techdataservice.us","sync.techdataservice.us",
"telemetry.techdataservice.us"
]);
let SuspiciousSHA256 = dynamic([
"0073473b4baf3c29156597aab6d948fe7dc91972fdf350f88753e1e9e5217009",
"1a783fcab9ae545dee58228b38dc9d4fa0c2d0dc35c23f4f5a9d01303ecabd72",
"1f529a76faea1e7fa56cbc24c66ddeb5a18d025af654c7e92635d9866e22819d",
"3e9efef4121da751f36070a7ffed49eb1b1f72831651e8ecf47e45dd7602c05e",
"3f5bc475d9394d352341b1f843b85cfb300e363dd27d4ca867e9e6d54317d881",
"407d179f920342312dd526abc8a194b2620d0b19a95032dd36eeb70ec3bf5d65",
"498eaa0d4e5dfa6495a8c3308a3f02f38841809b0d3cab86448b559dbbe8e47c",
"4a85f0d06561ea94150fd84a536993119ba62638e23b95cecac3e17fc21874cb",
"9ed58663f7a0bb91c0d9e058a376e78f6748fa4a88e69a0e4598312b3ba75a0c",
"a68bcf09f8c83c67dfe0b17030367ebccf0905f4f531663c73b990202e2a13b0"
]);
let SuspiciousImpHash = dynamic([
"c4f69d93110080cc2432c9cc3d2c58ab"
]);
union isfuzzy=true
(
DeviceNetworkEvents
| where RemoteIP in (SuspiciousIPs)
    or RemoteUrl has_any (SuspiciousDomains)
),
(
DeviceFileEvents
| where SHA256 in (SuspiciousSHA256)
    or InitiatingProcessSHA256 in (SuspiciousSHA256)
),
(
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName has_any (SuspiciousDomains)
),
(
DeviceImageLoadEvents
| where SHA256 in (SuspiciousSHA256)
),
(
DeviceFileEvents
| where InitiatingProcessMD5 in (SuspiciousImpHash)
)
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, RemoteIP, RemoteUrl, SHA256
| order by TimeGenerated desc
```

