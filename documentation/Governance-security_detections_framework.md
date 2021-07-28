# Security Detection Framework Governance

* [Purpose](#purpose)
* [Definitions](#definitions)
* [Scope](#scope)
* [Governance Roles/Responsibilities](#governance-rolesresponsibilities)
  * [Observers](#observers)
  * [Detection Creators](#detection-creators)
  * [Detection Owners](#detection-owners)
* [Governance Committee Process](#governance-committee)
  * [Governance Committee Membership](#governance-committee-membership)
    * [Joining/Leaving/Removal](#joiningleavingremoval)
      * [Joining](#joining)
      * [Leaving/Removal](#leavingremoval)
    * [Current Membership (alphabetical)](#current-membership-alphabetical)
  * [Meeting Logistics/Cadence \- markdown file for this](#meeting-logisticscadence---markdown-file-for-this)
  * [Typical Meeting Agenda](#typical-meeting-agenda)
  * [Meeting Cadence](#meeting-cadence)
* [On\-/Off\-boarding](#on-off-boarding)
  * [Onboarding](#onboarding)
  * [Offboarding](#offboarding)
* [Attribution](#attribution)

## Purpose

* This document describes the Governance Model for a Governance Committee to provide decisioning and approval for changes
made to the Security Detections Framework

## Definitions

- **Detection**
  - Any rule within an alerting platform which is used to detect specific activities.
  - Example: When a login attempt occurs, a rule detects if it is authorized or not.
- **Alert**
  - Any detection which has been configured to notify a defined individual, group, team, etc.
  - Example: When an unauthorized login is detected, an alert notifies the account owner.
- **Detection Repository**
  - A location which stores details about configured detections.

## Scope

* This repo is intended to list any detections which Godaddy is direcly responsible for maintaining. Third party detections which are maintained by the external entity do not need to be added to this repo unless there is a modification, required internal support, or specific knowledge that needs to be documented for other teams. 


## Governance Roles/Responsibilities

* Observers, Detection Creators, Detection Owners, and Governance Committee. 
* Access to any of these roles can be granted by creating a PR to add themselves to the corelating group. PR request are subject to approval by a member of the Governance Committee

### Observers

A member of the Security Detections Framework with read only access. 

### Detection Creators
* listed as a knowledge resource containing information regarding the origin of the alert. Not responsible for ongoing maintenance of the alert, but may remain an important asset in modifying the alert in the future.

### Detection Owners

* Detection Owners are responsible for validating the detection folder contains a file with complete [Meta Data](https://github.com/gdcorp-infosec/security-detections-framework/tree/main/alerts/detections#metadata), and follows the proper [Naming Schema](https://github.com/gdcorp-infosec/security-detections-framework/tree/main/alerts/detections#naming)

* Detection owners are also responsible for maintaning Testing data following the Testing guidelines

* Detection owners are not necessarily the detection creator, there are a number of scenarios in which a detection may be created by another team in support of a joint effort and ownership assigned to the owning authority.  (i.e. A detection request was sent to Threat-Research by the IR team while responding to an incident, the Threat-Research team would quickly create the alert, but ownership would remain with IR.)


## Governance Committee

As the framework goes into continued use cycles, the Governance Committee will need to conduct quarterly reviews to validate that rules are operational, testing is recent and relevant, and rule ownership is properly assigned.

The Governance Committee allow approves/rejects changes to any Detection Framework process, and governance.

A [Governance Committee private slack channel] will be available to the Committee

### Governance Committee Membership

#### Joining/Leaving/Removal

##### Joining

* A person desiring membership on the Governance Committee can create a PR adding themselves to the
  [Current Membership](#current-membership-alphabetical).
  * PR is approved/rejected by a Governance Comittee Member
* A person can be nominated to membership via PR by being added to
  the [Current Membership](#current-membership-alphabetical).
  * PR is approved/rejected by a Governance Comittee Member

Once a member joins, the [onboarding](#onboarding) procedure is applied.

##### Leaving/Removal

* Team members may retire at any time by submitting a PR removing themselves
  from [Current Membership](#current-membership-alphabetical) (required) and placing themselves
  in [Past Members](#past-members) (if they so choose)
* Failure to participate in six consecutive votes will result in a vote to remove the individual from the Governance
  Committee
* Team members can be removed by any Governance Comittee Member
* Upon death of a member, they leave the team automatically

In case a member leaves, the [offboarding](#offboarding) procedure is applied.

#### Current Membership (alphabetical)

| Governance Committee Member | Term Start Date |
| :-------------------------- | :-------------- |
| Bindi Davé     | 07/27/2021     | 
| [David Dubois](https://github.secureserver.net/ddubois-godaddy)        | 07/26/2021     |  
| [Partric Green](https://github.secureserver.net/pgreen-godaddy)        | 07/26/2021     |  
| [Jonathan Wade](https://github.secureserver.net/jwade-godaddy)         | 07/26/2021     |  
| [Thomas Whipple](https://github.secureserver.net/twhipple1-godaddy)    | 07/26/2021     |  
| [Jason White](https://github.secureserver.net/jwhite-godaddy)          | 07/26/2021     | 



| Observers                   |
| :-------------------------- |
| [Courtney Falk](https://github.secureserver.net/cfalk-godaddy) |
| |
| |


## Meeting Logistics/Cadence


### Typical Meeting Agenda

* Review list of Alerts to be retired and up/down vote
* Review Alert Testing to identify if there is a time gap exceeding 365 days
* Review list of proposed process/policy change PRs and up/down vote

### Meeting Cadence

During early adoption, meetings will be weekly to discuss issues. Governance Committee can make changes to candence and
vote on them at their discretion. This section should reflect the current meeting cadence.

Upcoming meetings should be posted to [golden_containers].


## On-/Off-boarding

### Onboarding

The new member is:

* Added to [@gdcorp-infosec/security-detections-framework].
* Added to the team mailing list [threat@godaddy.com].


### Offboarding

The ex-member is:

* Removed from [Current Membership](#current-membership-alphabetical) (required) and placed
  in Past Members (if they so choose).
  * Ideally by sending a PR of their own, at least approving said PR
  * In case of forced removal, no approval is needed
* Removed from [@appservices/goldenimage-governance]
* Removed from the projects
  * Optionally, they can retain maintainership of one or more repositories if the team agrees.
* Not allowed to call themselves a Governance Committee member any more, nor allowed to imply this to be the case
* If needed, we reserve the right to publicly announce removal


## Attribution

Governance documentation inspired by [Grafana Governance](https://grafana.com/docs/loki/latest/community/governance/),
[Adobe Governance](https://github.com/adobe/open-development-template/blob/master/Governance.md)
and [containerd Goverance](https://github.com/containerd/project/blob/master/GOVERNANCE.md).

[Tier 1]: golden_container_contribution#image-tiers
[Cloud-Automation]: https://github.secureserver.net/orgs/appservices/teams/cloud-automation
[@appservices/goldenimage-governance]: https://github.secureserver.net/orgs/appservices/teams/goldenimage-governance
[golden_containers]: https://godaddy.slack.com/archives/CLE1RE39C
[Image Tiers]: ./golden_container_contribution.md#image-tiers
[Governance Committee private slack channel]: https://godaddy.slack.com/archives/G01PJG2FW11
[EOL'd by upstream on 01 May 2021]: https://endoflife.date/alpine
[EOL'd by upstream on 01 June 2021]: https://github.com/nodejs/Release
