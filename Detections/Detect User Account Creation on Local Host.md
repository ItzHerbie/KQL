
* Security Monitoring & Threat Detection
  * **Early Indicator of Compromise:** Attackers often create local user accounts to maintain persistence, move laterally, or escalate privileges. Detecting new accounts can reveal suspicious activity before further damage occurs.

  * **Bypassing Domain Controls:** Local accounts operate outside domain policies and monitoring systems like Azure AD/Entra ID or Active Directory. An unexpected local account may indicate someone trying to avoid centralized security logs and controls.

  * **Detecting Privilege Abuse:** Even legitimate admins can accidentally create overly privileged accounts or bypass security standards. Monitoring helps enforce least-privilege practices.

```KQL
SecurityEvent
| where EventID == "4720" // 4720 - Account Creation
| where Account != @"ADD KNOWN ACCOUNTS LIKE MIM"
| project Account, Computer, Activity, TargetAccount
```

[Reference Local Admin Account Detection for futher investigation and hunting](https://github.com/ItzHerbie/KQL/blob/main/Detections/Detect%20Local%20Admin%20Accounts.md)
