This detection monitors who is accessing external repositories to fetch or push code within the last 7days

```kql
DeviceProcessEvents
| where TimeGenerated >= ago(7d) //Change timeframe to liking
| where InitiatingProcessVersionInfoProductName in (@"Git", @"Visual Studio Code", @"Postman", @"Bot Framework Emuator") //Add tools that can be used to Fetch/Pull/Push Code
| where InitiatingProcessCommandLine contains @"fetch" or InitiatingProcessCommandLine contains @"push" 
| where ProcessCommandLine contains @"https" or ProcessCommandLine contains @"http" 
| where AccountUpn != ""
| where ProcessCommandLine !contains @"ENTER COMPANY REPO"
    and ProcessCommandLine !contains "pwsh.exe"
    and ProcessCommandLine !contains "powershell.exe"
| summarize
    by
    Time_of_Repository_Action=TimeGenerated,
    AccountUPN=AccountUpn,
    Source=DeviceName,
    RemoteRepository=ProcessCommandLine,
    FolderPath
| summarize arg_max(Time_of_Repository_Action, *) by AccountUPN, Source, RemoteRepository, FolderPath 
| summarize by Time_of_Repository_Action, AccountUPN, Source, RemoteRepository, FolderPath
| join (IdentityInfo) on AccountUPN //Joined Identity Table to get the user job title
| summarize
    by
    Time_of_Repository_Action,
    AccountUPN,
    JobTitle,
    Source,
    RemoteRepository,
    FolderPath
| sort by Time_of_Repository_Action desc 
