```KQL
let sensitiveRole = dynamic(["Global Administrator", "Authentication Administrator", "Privileged Authentication Administrator", "Data Purger"]);
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| extend Actor = InitiatedBy.user.userPrincipalName
| extend roleActivated = TargetResources[0].displayName
| extend cst = datetime_utc_to_local(TimeGenerated, 'America/Chicago')
| extend roleStartTime = datetime_utc_to_local(todatetime(AdditionalDetails[4].value), 'America/Chicago')
| extend roleEndTime = datetime_utc_to_local(todatetime(AdditionalDetails[5].value), 'America/Chicago')
| extend hour = datetime_part('hour', cst)
| where roleActivated in (sensitiveRole)
| where hour !between (06 .. 19)
| project TimeGenerated, Actor, roleActivated, ResultReason, roleStartTime, roleEndTime
