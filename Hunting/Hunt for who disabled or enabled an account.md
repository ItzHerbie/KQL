```kql
union
(
SecurityEvent
| where TimeGenerated >= ago(90d)
| where EventID in ("4722", "4725")
| project TimeGenerated,
          TargetAccount = TargetUserName,
          TargetDomain = TargetDomainName,
          ReEnabledBy = SubjectUserName,
          Computer = Computer,
          Activity
| where ReEnabledBy !in ("ENTER KNOWN ACCOUNTS")
),
(
AuditLogs
| where TimeGenerated >= ago(90d)
| where OperationName in ("Enable account", "Disable account")
| extend displayName_ = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].displayName)
| extend NewValue = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue))[0])
| extend OldValue = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].oldValue))[0])
| project TimeGenerated,
          ReEnabledAccount = TargetResources.userPrincipalName,
          InitiatedByUser = InitiatedBy.user.userPrincipalName,
          InitiatedByApp = InitiatedBy.app.displayName,
          OperationName
| where InitiatedByApp !in ("ENTER KNOWN ACCOUNTS")
```
