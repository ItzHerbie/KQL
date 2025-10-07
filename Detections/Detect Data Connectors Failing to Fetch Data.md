Description:<br>
  Failure in a configured Azure Sentinel data connector. The connector has not successfully ingested logs from its source within the expected time window. This may indicate a configuration issue, connectivity problem, or upstream outage, and could result in missing or delayed security event data. <br>
  
Tactics and Techniques: Defense Evasion - T1562 0 Impari Defenses

```kql
_SentinelHealth()
| where OperationName contains "Data fetch status change"
| where Status == "Failure"
| extend ExtendedProps = parse_json(ExtendedProperties)
| extend DestinationTable = tostring(ExtendedProps["DestinationTable"])
| summarize by OperationName, Status, Description, SentinelResourceName, DestinationTable

