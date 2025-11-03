**Why it Matter**<br>
Detecting Privileged Identity Management (PIM) activation of sensitive roles after hours is important because it helps catch abnormal privileged access behavior that may signal compromise, insider misuse, or unauthorized activity. Most privileged actions occur during business hours or planned maintenance windows. 

After-hours PIM activation can indicate:
     - Compromised credentials being used discreetly
     - Attempted data access or system changes when less monitoring staff are online
     - Insider threat behavior when they expect less oversight

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
