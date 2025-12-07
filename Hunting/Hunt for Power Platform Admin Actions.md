```kql
PowerPlatformAdminActivity
| where TimeGenerated >= ago(90d)
| where ActorUserType contains "Admin"
| where ActorName !in ("Exclude Known Accounts")
// Add Criticality Level
| extend Criticality = case(
    EventOriginalType in (
        "SecurityRoleUpdated",
        "PowerAppPermissionEdited",
        "DeletePowerApp",
        "RecordScopesConsent",
        "PutConnection",
        "PutConnectionPermission",
        "PutAppConnectionUsage",
        "PatchApi"
    ), "High",
    EventOriginalType in (
        "UpdatePowerApp",
        "PublishPowerApp",
        "ImportExistingCanvasApp"
    ), "Medium",
    "Low"
)
// Add WHY the event matters
| extend Why = case(
    EventOriginalType == "SecurityRoleUpdated", "Security role was modified, which controls access and permissions for users.",
    EventOriginalType == "PowerAppPermissionEdited", "App permissions were changed, granting or revoking user access.",
    EventOriginalType == "DeletePowerApp", "An app was deleted, which may disrupt business processes.",
    EventOriginalType == "RecordScopesConsent", "Consent scopes were changed, affecting connector/data-access permissions.",
    EventOriginalType == "PutConnection", "A data connection was created or updated, affecting access to external data sources.",
    EventOriginalType == "PutConnectionPermission", "Permissions for a data connection were modified.",
    EventOriginalType == "PutAppConnectionUsage", "App usage of a connector was changed, affecting data pathways.",
    EventOriginalType == "PatchApi", "A custom connector or API was modified.",
    EventOriginalType == "UpdatePowerApp", "An existing app was updated.",
    EventOriginalType == "PublishPowerApp", "An app update was published to users.",
    EventOriginalType == "ImportExistingCanvasApp", "A canvas app was imported from another environment or package.",
    EventOriginalType == "CreatePowerApp", "A new PowerApp was created.",
    EventOriginalType == "LaunchPowerApp", "A user launched an app.",
    EventOriginalType == "AppDlpEvaluationResultChange", "DLP evaluation changed due to policy or data classification updates.",
    "Other event type"
)
// Add RISK impact
| extend Risk = case(
    EventOriginalType == "SecurityRoleUpdated", "High risk: could escalate privileges or expose sensitive data.",
    EventOriginalType == "PowerAppPermissionEdited", "High risk: users may gain unauthorized access to apps or data.",
    EventOriginalType == "DeletePowerApp", "High risk: business disruption or malicious deletion.",
    EventOriginalType == "RecordScopesConsent", "High risk: could allow data exfiltration or bypass DLP.",
    EventOriginalType == "PutConnection", "High risk: improper configuration may expose external data.",
    EventOriginalType == "PutConnectionPermission", "High risk: could grant unauthorized data access.",
    EventOriginalType == "PutAppConnectionUsage", "High risk: apps could start using sensitive connectors.",
    EventOriginalType == "PatchApi", "High risk: custom connectors could leak data or be misconfigured.",
    EventOriginalType == "UpdatePowerApp", "Medium risk: updates may introduce unintended behavior or data access.",
    EventOriginalType == "PublishPowerApp", "Medium risk: new changes affect production users.",
    EventOriginalType == "ImportExistingCanvasApp", "Medium risk: imported apps may contain insecure connectors.",
    EventOriginalType == "CreatePowerApp", "Low risk: app created but no permissions set yet.",
    EventOriginalType == "LaunchPowerApp", "Low risk: informational only.",
    EventOriginalType == "AppDlpEvaluationResultChange", "Low risk: system evaluation, not an admin action.",
    "Unknown risk"
)
| project TimeGenerated, ActorName, ActorUserType, EventOriginalType, Criticality, Why, Risk, EventResult, EnvironmentId
| order by TimeGenerated desc
```
