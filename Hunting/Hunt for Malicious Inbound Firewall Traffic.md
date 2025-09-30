Info coming soon!

```kql
CommonSecurityLog
    | extend
        TrafficDirection = iff(CommunicationDirection !in ("Outbound", "1"), "InboundOrUnknown", "Outbound"),
        Country=MaliciousIPCountry,
        Latitude=MaliciousIPLatitude,
        Longitude=MaliciousIPLongitude,
        Confidence=ThreatDescription,
        Description=ThreatDescription
| where isnotempty(MaliciousIP)
    and isnotempty(Country)
    and isnotempty(Latitude)
    and isnotempty(Longitude)
| where TrafficDirection == "InboundOrUnknown"
| where TimeGenerated >= ago(30d)
| where Country != "United States"
| where DeviceAction contains "allow"
| summarize count() by DeviceAction, IndicatorThreatType, Country, MaliciousIP, DestinationIP, ReceivedBytes, SentBytes, DeviceCustomString1, TrafficDirection

