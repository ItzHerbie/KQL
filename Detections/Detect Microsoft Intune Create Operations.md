This detection is to monitor who is creating specific operations in Intune. Only allow Intune administrators should be creating these operations. Anyone else need to be questioned. 

```kql
IntuneAuditLogs
| where OperationName in ("Create RoleDefinition",
	"Create MobileAppAssignment",
	"Create DeviceConfiguration",
	"Create DeviceConfigurationAssignment",
	"UpdateAppProtection ManagedAppPolicy"
    )
| where Identity !in ("Excluded UPN", "Excluded UPN")// Intune Admins should only be seen creating these operations. 
| extend TargetDisplayName = tostring(parse_json(tostring(parse_json(Properties).TargetDisplayNames))[0])
| extend TargetObjectID = tostring(parse_json(tostring(parse_json(Properties).TargetObjectIds))[0])
| summarize by Identity, OperationName, TargetDisplayName, TargetObjectID, ResultType
