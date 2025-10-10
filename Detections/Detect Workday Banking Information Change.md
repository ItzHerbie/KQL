<h2>
    Description: 
</h2>
This detection is to detect on a successful sign-in to Workday where the banking information was changed within 60 minutes. 
Once it sees that banking information was changed it will do a lookback to see if a Temporary Access Pass (TAP) was issued, if an authentication method was registered, and if there was a password change 5 days prior to the user viewing or changing their banking information in Workday. 
<br />

#### Azure Sentinel/Defender XDR
```kql
// Successful Workday sign-ins (Today)
let workday_signin_logs =
    SigninLogs
    | where TimeGenerated >= startofday(now())
    | where AppDisplayName has "Workday - Production"
    | where ResultType == 0
    | project SigninTime=TimeGenerated, UserPrincipalName, SigninUserAgent=UserAgent;
// Workday banking/account change events (today)
let workday_change_banking_info =
    ASimAuditEventLogs
    | where TimeGenerated >= startofday(now())
    | where Operation in (
        "Add My Account",
        "Add My Election",
        "Add Payment Election",
        "Change My Election",
        "Change My Account",
        "Delete My Account",
        "Manage Payment Elections"
        )
    | project
        ChangeTime=TimeGenerated,
        UserPrincipalName=ActorUsername,
        Operation,
        Object,
        WorkdayUserAgent=HttpUserAgent
    | where Object != "";
// Auth method registrations (5-day lookback)
let registered_auth_methods =
    AuditLogs
    | where TimeGenerated >= startofday(now()) - 5d
    | where OperationName contains "User registered security info"
    | where ResultDescription contains "User registered"
    | extend userPrincipalName_ = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | project AuthRegisterTime=TimeGenerated, UserPrincipalName=userPrincipalName_;
// TAP issued events (5-day lookback)
let tap_issued =
    AuditLogs
    | where TimeGenerated >= startofday(now()) - 5d
    | where OperationName == "User registered security info"
    | where ResultDescription == "User registered temporary access pass method"
    | where Result == "success"
    | extend
        userPrincipalName_ = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName),
        TAPDisplayUserName = tostring(TargetResources[0].displayName)
    | project TAPTime=TimeGenerated, UserPrincipalName=userPrincipalName_, TAPDisplayUserName;
// Password reset events (5-day lookback)
let password_reset = 
    AuditLogs
    | where TimeGenerated >= startofday(now()) - 5d
    | where ResultDescription == "User successfully reset password"
    | extend userPrincipalName_ = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | project PasswordResetTime=TimeGenerated, UserPrincipalName=userPrincipalName_, ResultDescription;
let account_creation_time =
    IdentityInfo
    | summarize arg_min(AccountCreationTime, *) by AccountUPN, AccountDisplayName
    | project UserPrincipalName=AccountUPN, AccountDisplayName, AccountCreationTime;
workday_change_banking_info
| join kind=inner (workday_signin_logs) on UserPrincipalName
    | where SigninTime <= ChangeTime and ChangeTime <= SigninTime + 60m
    | extend TimeDifference = datetime_diff("minute", ChangeTime, SigninTime)
// Keep the closest sign-in per (user, change)
    | summarize arg_min(TimeDifference, *) by UserPrincipalName, ChangeTime
// Join to Auth Method registrations (within 5 days before sign-in)
| join kind=leftouter (registered_auth_methods) on UserPrincipalName
    | where isnull(AuthRegisterTime) 
        or (AuthRegisterTime >= SigninTime - 5d and AuthRegisterTime <= SigninTime)
    | summarize arg_max(AuthRegisterTime, *) by UserPrincipalName, ChangeTime, SigninTime
// Join to TAP issued events (within 5 days before AuthRegisterTime if exists, otherwise before SigninTime)
| join kind=leftouter (tap_issued) on UserPrincipalName
    | where isnull(TAPTime) 
        or (isnotnull(AuthRegisterTime) and TAPTime >= AuthRegisterTime - 5d and TAPTime <= AuthRegisterTime)
        or (isnull(AuthRegisterTime) and TAPTime >= SigninTime - 5d and TAPTime <= SigninTime)
    // If multiple TAPs exist, keep the latest one
    | summarize arg_max(TAPTime, *) by UserPrincipalName, ChangeTime, SigninTime, AuthRegisterTime
// Join to password reset events (within 5 days before AuthRegisterTime if Exists, oterwise before SigninTime)
| join kind=leftouter (password_reset) on UserPrincipalName
    | where isnull(PasswordResetTime)
        or (PasswordResetTime >= SigninTime - 5d and PasswordResetTime <= SigninTime)
    | summarize arg_max(PasswordResetTime, *) by UserPrincipalName, ChangeTime, SigninTime, AuthRegisterTime, PasswordResetTime
| join kind=leftouter (account_creation_time) on UserPrincipalName
| extend
    AuthMethodFound = iff(isnull(AuthRegisterTime), "AuthMethodFound=No", "AuthMethodFound=Yes"),
    TAPFound = iff(isnull(TAPTime), "TAPFound=No", "TAPFound=Yes"),
    PasswordResetFound = iff(isnull(PasswordResetTime), "PasswordResetFound=No", "PasswordResetFound=Yes")
| project
    UserPrincipalName,
    AccountCreationTime,
    TAPFound,
    TAPTime,
    TAPDisplayUserName,
    AuthMethodFound,
    AuthRegisterTime,
    PasswordResetFound,
    PasswordResetTime,
    SigninTime,
    ChangeTime,
    TimeDifference,
    Operation,
    Object,
    WorkdayUserAgent,
    SigninUserAgent
| order by ChangeTime desc
| where TAPFound == "TAPFound=Yes" or AuthMethodFound == "AuthMethodFound=Yes" or PasswordResetFound == "PasswordResetFound=Yes"
