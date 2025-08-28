
```kql
let SpamThreshold = 500; //set threshold
EmailEvents
| where TimeGenerated >= ago(1h) // set timeframe to look at
| summarize count() by RecipientEmailAddress, DeliveryAction
| where RecipientEmailAddress !in ("Add Email Address to Exclude") // add anymail box to exclude. Multiple can be added seperated by comma.  
| where count_ >= SpamThreshold // This will match count_ of events that is greater-than-or-equal-to your SpamThreshold
