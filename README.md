# 🌍 Impossible Travel Detection with Microsoft Sentinel

This lab simulates the detection and investigation of **impossible travel events**—instances where a user logs in from geographically distant locations within a short timeframe, violating realistic physical travel capabilities. It follows the **NIST 800-61 Incident Response Lifecycle** and leverages **Microsoft Sentinel** and **Log Analytics** to identify and triage potentially compromised accounts.

---

## 🌟 Objective

* Detect anomalous logon behavior such as impossible travel using Microsoft Sentinel
* Build a KQL query and scheduled analytics rule to automate detection
* Investigate suspicious activity in Microsoft Sentinel
* Contain potential threats and validate outcomes
* Document findings and follow NIST-aligned response steps

---

## 1. 🧰 Preparation

Organizations often prohibit:

* Logging in from outside approved geographic regions
* Account sharing
* Use of personal or non-corporate VPNs

These policies reduce the likelihood of account compromise and unauthorized access. In this lab, we simulate a user account logging in from **Virginia** and **California** within a **43-minute window**, which is physically impossible and strongly indicative of account misuse or credential compromise.

Azure sign-in data is collected in the `SigninLogs` table and sent to **Log Analytics**, where **Microsoft Sentinel** consumes it to generate incidents via scheduled query rules.

---

## 🚦 Creating the Alert Rule (Potential Impossible Travel)

**Objective:** Set up a Sentinel **Scheduled Query Rule** in Log Analytics to detect users logging into multiple geographic regions.

### Rule Configuration Details

1. **Trigger Conditions:**

   * A user logs into two or more distinct locations within 7 days.

2. **KQL Query:**

**Explanation:**
This query is designed to identify users who appear to log in from multiple, distinct geographic locations within a short timeframe (e.g., 7 days), which could indicate impossible travel.

* `let TimePeriodThreshold = timespan(7d);` sets the time window for evaluating sign-in events.
* `let NumberOfDifferentLocationAllowed = 1;` defines the threshold beyond which a user is flagged (more than one location).
* `SigninLogs` is the Azure AD sign-in table used for sign-in event telemetry.
* The query parses and extracts `City`, `State`, and `Country` from the nested `LocationDetails` field.
* It groups sign-ins by `UserPrincipalName` and distinct locations.
* If a user signs in from more than one location within the period, they're flagged as having a potential impossible travel instance.

```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationAllowed = 1;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize count() by UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationAllowed
```

![Screenshot](https://github.com/user-attachments/assets/c69cab46-5d5f-4769-a6f7-bc803a16e2dc)

3. **Analytics Rule Settings:**

   * **Name:** Potential Impossible Travel Alert
   * **Description:** Detects logins from multiple geographic regions.
   * **Frequency:** Every 5 Hours
   * **Lookup Period:** Last 24 Hours
   * **Incident Creation:** Enabled
   * **Stop after Alert:** Yes

4. **Entity Mappings:**

   * **Account ID:** `AadUserId` → `UserId`
   * **Display Name:** `UserPrincipalName` → `Value`

![Screenshot](https://github.com/user-attachments/assets/2a9006f6-7d4c-4499-85b9-9afdd5a37c30)

---

## 🔍 Detection and Analysis

### Steps to Validate Incident

* ✅ Assign the incident and mark as **Active**
* 🔄 Use **Investigate** to review associated entities
* 📊 Examine analytics rule output for flagged accounts

### Account Analysis Example

```kql
let TimePeriodThreshold = timespan(7d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == "username@domain.com"
| project TimeGenerated, UserPrincipalName, UserId, City, State, Country
| order by TimeGenerated desc
```

![Screenshot](https://github.com/user-attachments/assets/2739121d-5914-4468-a480-cecee0883432)

### Observed Findings

* **Account 1:** Logins from 3 nearby locations within 4 days — considered normal behavior
* **Account 2:** Logins from 4 locations within 7 days, all within reasonable commuting distance

---

## 🛠️ Containment, Eradication, and Recovery

### Outcome

The alert was determined to be a **Benign Positive**:

* Account activity aligned with expectations
* No indication of compromise based on geographic proximity and timing

### Next Steps

* 🔍 Pivot to deeper investigation if needed:

```kql
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "AzureADObjectID"
```

* Disable account and escalate **only if** further suspicious activity is confirmed

---

## 🔄 Post-Incident Activities

1. **Policy Updates:**

   * Implement geo-fencing to restrict external logins

2. **Documentation:**

   * Log findings and decisions in your IR tracking system

---

## ✅ Closure

1. Confirm incident is resolved
2. Mark as **Benign Positive** or **False Positive** as appropriate
3. Finalize documentation and close the case

📌 **Status:** Closed as **Benign Positive**

---

## ✨ Lessons Learned

* Improved geographic restrictions help reduce alert fatigue
* Not all alerts require escalation—context matters!

📈 **Always stay vigilant!** 🛡️
