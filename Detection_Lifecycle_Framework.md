# Incident Detection Lifecycle Framework

Draft Document for Working Efforts - [IRT-507](https://jira.godaddy.com/browse/IRT-507)

# Table of Contents

_**[Definitions 3](#_Toc75345613)**_

_**[Lifecycle 3](#_Toc75345614)**_

_**[Creation 4](#_Toc75345615)**_

_**[Testing 4](#_Toc75345616)**_

_**[Implementation 4](#_Toc75345617)**_

_**[Maintenance 4](#_Toc75345618)**_

_**[Review 4](#_Toc75345619)**_

_**[Retirement 4](#_Toc75345620)**_

_**[Removal 4](#_Toc75345621)**_

_**[Out-of-Band Actions 4](#_Toc75345622)**_

**[Tuning Requests 4](#_Toc75345623)**

**[Emergency Detections 4](#_Toc75345624)**

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

![](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/Lifecycle.png)

# Creation

The first part of creating a detection is to identify where the detection method will be most beneficial considering:

- The rules which will be triggered based on the targeted event.
- The Logic that will drive the events to be considered.
- The action that will be taken when the logic and or conditions are met.

Once the above have been considered it important to identify teams within Security with ownership of the preferred tool / skillset to bring the detection(s) alive. The choice of tool should be one that can help design and map with the framework of choice as well as to provide with the ability to prioritize and focus on threats faced by the business. If an individual finds themselves capable of creating a detection, it is still mandatory to contact the tool owners for awareness, technical guidance as well as to aid them keep track of all additions and deletions of detections.

As part of the creation stage, it is also vital to check with other tool owners to identify similar detections that could potentially be phased out or used as an enhancement for a new detection as well as to avoid duplicates.

# Testing

The defined logic and baseline can be tested is tested here. Testing should be carried out in the development environment where possible before being moved into the production environment. Based on the test results further tuning can be conducted to reduce noise. The outcome of testing can be used to optimize the baselines to build the detection(s).

Exception will be made to the lifecycle and will be decided by management. Where there is an urgent need for a detection to be implemented, the relevant team will be contacted and authorized by management to implement the detection bypassing the standard lifecycle. Example of such exceptions include:

- A high-risk vulnerability
- An immediate threat is identified
- To prove a theory

Testing of a detection will also include an effort to continuously define the logic and baseline to ensure it is tuned properly for the best possible results.

# Implementation

Once a detection is deployed; the relevant teams should be informed to start monitoring the relevant performance and alerts. Where required, the teams must also be briefed on the SOPs when the detections are triggered. GCSO (Global Cyber Security Operations) or the monitoring team must also be alerted about the new detection and provided with a playbook to handle future alerts.

# Maintenance

Infrastructure environments do not stay the same for long, they are constantly evolving overtime with innovative technology, diverse types of data sources, as well as new compliance requirements. It is therefore important to perform periodic audits of detections to best identify that:

- The detection is still functional as required.
- The detection is still required.
- If there is a need to update the detection.
- The right detections are in place.

If a detection is identified as no longer required, the relevant teams must be informed before the detection is updated or removed.

# Review

Infrastructure environments do not stay the same for long, they are constantly evolving overtime with innovative technology, diverse types of data sources, as well as new compliance requirements. It is therefore important to perform periodic audits of detections to best identify that:

- The detection is still functional as required.
- The detection is still required.
- If there is a need to update the detection.
- The right detections are in place.

If a detection is identified as no longer required, the relevant teams must be informed before the detection is updated or removed.

# Retirement

Following the review of existing detections, any rule that is identified as not required resulting from:

- A newer detection
- New data source/ retired data source
- Excessive generation of false positives (noise)

The relevant team(s) must be informed before a detection is retired following all the correct processes to remove the detection from its repository.

# Removal

The final life cycle of a detection involves the removal of a detection form it repository and the tool. It must be ensured that all the relevant teams that require a detection are informed and updated on the need to remove a detection following all the appropriate processes and procedures.

# Out-of-Band Actions

## Tuning Requests

## Emergency Detections

![](RackMultipart20210727-4-1av054s_html_720cf162cd45addd.png)

Emergency detections may need to be implemented to support high-priority activities such as threat hunting or incident response. Due to the urgency of this activities, it may not be possible to undergo the standard onboarding process for these detections. However, effort should be made to ensure that detections made in these situations are eventually put through the appropriate rigor to prevent them from becoming orphaned detections.

Examples of situations which may warrant the emergency creation of a detection are as follows:

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
