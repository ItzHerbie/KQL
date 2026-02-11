What we know [Malwarebytes Report](https://www.malwarebytes.com/blog/threat-intel/2026/02/fake-7-zip-downloads-are-turning-home-pcs-into-proxy-nodes)

Indicators of Compromise (IOCs)

File paths
<ul>
<li>C:\Windows\SysWOW64\hero\Uphero.exe</li>
<li>C:\Windows\SysWOW64\hero\hero.exe</li>
<li>C:\Windows\SysWOW64\hero\hero.dll</li>
</ul>

File hashes (SHA-256)
<ul>
<li>e7291095de78484039fdc82106d191bf41b7469811c4e31b4228227911d25027 (Uphero.exe)</li>
<li>b7a7013b951c3cea178ece3363e3dd06626b9b98ee27ebfd7c161d0bbcfbd894 (hero.exe)</li>
<li>3544ffefb2a38bf4faf6181aa4374f4c186d3c2a7b9b059244b65dce8d5688d9 (hero.dll)</li>
</ul>

Domains:
<ul>
  <li>soc.hero-sms[.]co</li>
  <li>neo.herosms[.]co</li>
  <li>flux.smshero[.]co</li>
  <li>nova.smshero[.]ai</li>
  <li>apex.herosms[.]ai</li>
  <li>spark.herosms[.]io</li>
  <li>zest.hero-sms[.]ai</li>
  <li>prime.herosms[.]vip</li>
  <li>vivid.smshero[.]vip</li>
  <li>mint.smshero[.]com</li>
  <li>pulse.herosms[.]cc</li>
  <li>glide.smshero[.]cc</li>
  <li>svc.ha-teams.office[.]com</li>
  <li>iplogger[.]org</li>
</ul>

Observed IPs (Cloudflare-fronted):
<ul>
  <li>104.21.57.71</li>
  <li>172.67.160.241</li>
</ul>

### Sentinel / Defender XDR
```kql
let FileHashes = dynamic([
    "e7291095de78484039fdc82106d191bf41b7469811c4e31b4228227911d25027",
    "b7a7013b951c3cea178ece3363e3dd06626b9b98ee27ebfd7c161d0bbcfbd894",
    "3544ffefb2a38bf4faf6181aa4374f4c186d3c2a7b9b059244b65dce8d5688d9"
]);
let FilePaths = dynamic([
    @"C:\Windows\SysWOW64\hero\Uphero.exe",
    @"C:\Windows\SysWOW64\hero\hero.exe",
    @"C:\Windows\SysWOW64\hero\hero.dll"
]);
let Domains = dynamic([
    "7zip.com",
    "soc.hero-sms.co",
    "neo.herosms.co",
    "flux.smshero.co",
    "nova.smshero.ai",
    "apex.herosms.ai",
    "spark.herosms.io",
    "zest.hero-sms.ai",
    "prime.herosms.vip",
    "vivid.smshero.vip",
    "mint.smshero.com",
    "pulse.herosms.cc",
    "glide.smshero.cc",
    "svc.ha-teams.office.com",
    "iplogger.org"
]);
let IPs = dynamic([
    "104.21.57.71",
    "172.67.160.241"
]);
union
(
    DeviceFileEvents
    | where TimeGenerated >= ago(90d)
    | where SHA256 in (FileHashes)
    | project
        TimeGenerated,
        DeviceName,
        Indicator = SHA256,
        IndicatorType = "FileHash",
        FileName,
        FolderPath,
        InitiatingProcessFileName,
        ActionType
),
(
    DeviceNetworkEvents
    | where TimeGenerated >= ago(90d)
    | where RemoteUrl has_any (Domains)
    | project
        TimeGenerated,
        DeviceName,
        Indicator = RemoteUrl,
        IndicatorType = "Domain",
        RemoteIP,
        InitiatingProcessFileName,
        InitiatingProcessFolderPath,
        ActionType
),
(
    DeviceNetworkEvents
    | where TimeGenerated >= ago(90d)
    | where RemoteIP in (IPs)
    | project
        TimeGenerated,
        DeviceName,
        Indicator = RemoteIP,
        IndicatorType = "IP",
        RemoteUrl,
        InitiatingProcessFileName,
        InitiatingProcessFolderPath,
        ActionType
),
(
    SecurityAlert
    | where TimeGenerated >= ago(90d)
    | where
        Entities has_any (FileHashes)
        or Entities has_any (FilePaths)
        or Entities has_any (Domains)
        or Entities has_any (IPs)
    | where AlertSeverity in ("Low", "High", "Medium")
    | project
        TimeGenerated,
        AlertName,
        AlertSeverity,
        Indicator = tostring(Entities),
        IndicatorType = "SecurityAlertEntity",
        CompromisedEntity
)
| sort by TimeGenerated desc
```
