# Incident Detection Lifecycle 



# Table of Contents

* [Definitions](#Definitions)
* [Lifecycle](#Lifecycle)
* [Creation](#Creation)
* [Testing](#Testing)
* [Implementation](#Implementation)
* [Maintenance & Review](#Maintenance-&-review)
* [Retirement](#Retirement)
* [Removal](#Removal)
* [Out-of-Band Actions](#Out-of-Band-Actions)
* [Tuning](#tuning)
  * [Tuning Requests](#Tuning-Requests)
  * [Monthly Review](#monthly-review)
* [Emergency Detections](#Emergency-Detections)

# Document Definitions

- **Detection**
  - Any rule within an alerting platform which is used to detect specific activities.
  - _Example: When a login attempt occurs, a rule_ _detects_ _if it is authorized or not._
- **Alert**
  - Any detection which has been configured to notify a defined individual, group, team, etc.
  - _Example: When an unauthorized login is_ _detected__, an_ _alert_ _notifies the account owner._
- **Detection Repository**
  - A location which stores details about configured detections.
- **Standard Operating Procedure (SOP)**
  - The existing defined process which is designated for use in the associated situation(s).

# Lifecycle

![](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/archive/Lifecycle.png)

# Creation

Requests for Creation can be sent to ![Detections Intake Page](https://godaddy-corp.atlassian.net/secure/CreateIssue.jspa?pid=32819&issuetype=8)

The first part of creating a detection is to identify where the detection method will be most beneficial considering:

- What tools are best suited for identifying the event
- What logs are required to track the event
- The rules which will be triggered based on the targeted event.
- The Logic that will drive the events to be considered.
- The action that will be taken when the logic and or conditions are met.

Once the above have been considered it is important to identify teams within Security with ownership of the preferred tool / skillset to bring the detection(s) alive. The choice of tool should be one that can help design and map with the framework of choice as well as provide the ability to prioritize and focus on threats faced by the business. If an individual finds themselves capable of creating a detection, it is still mandatory to contact the tool owners for awareness, technical guidance, and updates to all additions and deletions of detections.

As part of the creation stage, it is also vital to check with other tool owners to identify similar detections that could potentially be phased out or used as an enhancement for a new detection as well as to avoid duplicates.

-----Knowlede object naming convention

# Testing

The defined logic and baseline can be tested here. When possible, testing should be carried out in the development environment before being moved into the production environment. Based on the test results, further tuning can be conducted to reduce noise. The outcome of testing can be used to optimize the baselines to build the detection(s).

Exceptions will be made to the lifecycle and will be decided by management. Where there is an urgent need for a detection to be implemented, the relevant team will be contacted and authorized by management to implement the detection bypassing the standard lifecycle. Example of such exceptions include:

- Detection of a high-risk vulnerability
- Identification of an immediate threat
- Need to prove a theory

Testing of a detection will also include an effort to continuously define the logic and baseline to ensure it is tuned properly for the best possible results.

Specific examples of how to test can be found [here](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/archive/Emergency%20Detections.png)

# Implementation

Once a detection is deployed; the relevant teams should be informed to start monitoring the relevant performance and alerts. When required, the teams must also be briefed on the SOPs when the detections are triggered. 

- GCSO (Global Cyber Security Operations) or the monitoring team must also be alerted about the new detection and provided with a playbook to handle future alerts.
- Incident Response or other Escalating Athorities should be notified as well.

# Maintenance & Review

Infrastructure environments do not stay the same for long, they are constantly evolving overtime with innovative technology, diverse types of data sources, as well as new compliance requirements. It is therefore important to perform periodic audits of detections to best identify that:

- The detection is still functional as required.
- The detection is still required.
- The detection needs to be updated. 
- The right detections are in place.

A Quarterly cadence for alert review should be established to review all items listed above

If a detection is identified as no longer required, the relevant teams must be informed before the detection is updated or removed.

# Retirement

Following the review of existing detections, any rule that is identified as not required resulting from:

- A newer detection
- New data source/ retired data source
- Excessive generation of false positives (noise)

The relevant team(s) must be informed before a detection is retired following all the correct processes to remove the detection from its repository.

# Removal

The final life cycle of a detection involves the removal of a detection form it repository and the tool. All the relevant teams that require a detection must be informed and updated on the need to remove a detection following all the appropriate processes and procedures.

# Out-of-Band Actions

## Tuning 

Tuning is a constant and ongoing project for many use-cases. As such the detections team will regularly adapt necessary changes to improve 

### Tuning Request

A request can be sent to the rule owner directly at any point through a Jira Ticket with the following items

* Rule name
*	Example Service Now Ticket or Report
*	List of items or pattern to be tuned out of the alert

see [Detections Intake Page](https://godaddy-corp.atlassian.net/secure/CreateIssue.jspa?pid=32819&issuetype=8) for requests. 

### Review

A dashboard generated from Mission Control listing all events flagged as false positive with their name, ticket number, and closed by should be reviewed by detections team.

If any event is closed as false positive with the same reasoning more than a handful of times, the detection logic will need the tunning added, or reworked to reduce the number of events generated for GCSO. 


## Emergency Detections

![](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/archive/Emergency%20Detections.png)

Emergency detections may need to be implemented to support high-priority activities such as threat hunting or incident response. Due to the urgency of these activities, it may not be possible to undergo the standard onboarding process for these detections. However, effort should be made to ensure that detections made in these situations are eventually put through the appropriate rigor to prevent them from becoming orphaned detections.

Examples of situations which may warrant the emergency creation of a detection are as follows but not limited to:

- An active threat to the company is identified.
- A short-term detection is needed to prove a theory of root cause.
- A high-risk vulnerability has an immediate risk of exploit.

When an emergency detection is required, implementation can be carried out without undergoing the standard testing process, however the following actions must be taken:

- The team(s) who control the detection realm are notified.
- Limited testing is carried out to ensure immediate function (to prevent invalid detections).

After an emergency detection is implemented, it is important to ensure that it is merged into the standard process or removed once all necessary monitoring is completed. The timeline for re-assimilation into the standard process is as follows:

- Within **24 hours** of creation, the detection is appropriately documented in the detection register.
  - These should be labeled as emergency detections per the SOP.
- Within **1 week** a review of the detection is carried out to test if retention is appropriate.
  - If a detection will be retained, it must undergo a review &amp; approval per the SOP.
  - If a detection will not be retained, it must be removed within 1 week of this review.
  - In some cases, a retain/remove decision will not be reachable during this initial review. In those cases, a retesting of the detection can be set for **up to 3 additional weeks** from the initial review deadline (totaling 4-weeks from creation).
