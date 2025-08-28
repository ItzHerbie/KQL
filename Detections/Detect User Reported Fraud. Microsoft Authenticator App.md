Detect user reported suspicious activity/fraud through the Microsoft Authenticator App

```kql
AuditLogs
| where OperationName contains "Fraud reported - user is blocked for MFA" or OperationName contains "Fraud reported - no action taken"
| extend accountUPN = TargetResources[0].userPrincipalName
| extend initiater = InitiatedBy.user.userPrincipalName
| project TimeGenerated, accountUPN, initiater, OperationName
