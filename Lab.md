# Splunk-Project

## Overview

The lab aims to conduct threat hunting with Splunk Enterprise in a simulated enterprise environment for the company “Frothy.” Splunk serves as a Security Incident and Event Monitor (SIEM), and a virtual instance of Splunk Enterprise is employed for threat hunting. The investigation focuses on the time frame between August 1, 2017, 00:00:00 hours, and August 31, 2017, 23:59:59 hours. The hypothesis is that attackers gained access through a spearphishing campaign, and the goal is to investigate potentially suspect email attachments.

![Screenshot 2023-12-28 124919](https://github.com/jmart375/Threat-Hunting-with-the-Splunk-SIEM/assets/91294710/de3f8d09-f95d-4ae9-bb27-7b8238693141) 

![Screenshot 2023-12-28 125117](https://github.com/jmart375/Threat-Hunting-with-the-Splunk-SIEM/assets/91294710/abed3e1b-1199-4d9c-b70a-4adfa24ed495)

## Project Scope

The Splunk project encompasses the following key areas:

1. **Search 1 – Finding Subjects Who Received Emails with Attachments**
   - To narrow down the search results, the query locates email users who received more than ten emails with         unique attachments. The search string is:
     
```spl
index=botsv2 sourcetype="stream:smtp" | stats count by recipient | where count > 10 | rename recipient AS "Email Recipient" count AS "Number of Emails Received"

```
   - Results are sorted by the "Number of Emails Received" column.
     
![Screenshot 2023-12-28 125323](https://github.com/jmart375/Threat-Hunting-with-the-Splunk-SIEM/assets/91294710/5c185c95-573e-4427-8c2a-2c04caeb7122)

2. **Search 2 – Filtering Emails by Attachment Name**
   - After identifying users with attachments, the search focuses on attachment names:
```spl
| stats count by attach_filename{} | rename attach_filename{} AS "Times Attachment Received"

```
   - Results list unique attachments and their frequencies.

![Screenshot 2023-12-28 125402](https://github.com/jmart375/Threat-Hunting-with-the-Splunk-SIEM/assets/91294710/e1eb510a-3cc6-42a7-ba6b-2fbb71ca47e8)

3. **Search 3 – Discovering Attachments with Unique File Sizes**
   - Search for attachment sizes in MB:
```sql | stats count by attach_filename{}| rename attach_filename{} AS "Attachment Name" attach_size{} AS "Attachment Size in MB" count AS "Times Attachment Received"

```
   - Results include attachment names and sizes.

![Screenshot 2023-12-28 125647](https://github.com/jmart375/Threat-Hunting-with-the-Splunk-SIEM/assets/91294710/78b659c7-0f75-466b-bcae-1b713cea1f2c)

4. **Search 4 – Filtering Unique Attachments by Unique Recipient**
   - This search eliminates duplicate instances where the same recipient received the same attachment more than      once:
```sql | strcat attach_filename{} "/" attach_size{} Attachment | stats count by Attachment | rename count AS "Times Attachment Received" | table Attachment "Recipients" | sort by -"Recipients"
```
   - Results display unique attachments and the number of recipients.

![Screenshot 2023-12-28 125821](https://github.com/jmart375/Threat-Hunting-with-the-Splunk-SIEM/assets/91294710/4361537f-aa86-4272-8cf6-3743f35b2b4a)

![Screenshot 2023-12-28 125843](https://github.com/jmart375/Threat-Hunting-with-the-Splunk-SIEM/assets/91294710/61cbfc87-0c3f-4b9e-8b58-b9895735c0bc)

**Visualizing the Results**
   - The output is visualized as a bar graph with axes labeled for easy interpretation.
     
![Screenshot 2023-12-28 125922](https://github.com/jmart375/Threat-Hunting-with-the-Splunk-SIEM/assets/91294710/0a45d65a-9fa2-4e84-893c-cbb11421d02e)

**Converting the Search into a Dashboard**
   - The search and visualizations can be converted into a dashboard for adaptability to additional data.

**Conclusion**
   - This lab showcases Splunk Enterprise Security SIEM as a powerful threat-hunting platform. Specific search       strings and visualizations were crafted to identify potential phishing emails, and the results were             organized into a dashboard for ongoing threat hunting against future network data.
