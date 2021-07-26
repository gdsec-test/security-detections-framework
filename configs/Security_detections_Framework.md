# Security Detection Framework Governance

* [Purpose](#purpose)
* [Definitions](#definitions)
* [Scope](#scope)
* [Governance Roles/Responsibilities](#governance-rolesresponsibilities)
* [Repository Owners](#repository-owners)
* [Governance Committee Process](#governance-committee)
  * [Governance Committee Membership](#governance-committee-membership)
    * [Joining/Leaving/Removal](#joiningleavingremoval)
      * [Joining](#joining)
      * [Leaving/Removal](#leavingremoval)
    * [Current Membership (alphabetical)](#current-membership-alphabetical)
    * [Past Members](#past-members)
  * [Meeting Logistics/Cadence \- markdown file for this](#meeting-logisticscadence---markdown-file-for-this)
  * [Voting](#voting)
  * [Typical Meeting Agenda](#typical-meeting-agenda)
  * [Meeting Cadence](#meeting-cadence)
* [Observers](#observers)
  * [Current Observers](#current-observers)
* [Golden Container Images Exceptions](#golden-container-images-exceptions)
* [On\-/Off\-boarding](#on-off-boarding)
  * [Onboarding](#onboarding)
  * [Offboarding](#offboarding)
* [Attribution](#attribution)

## Purpose

This document describes the Governance Model for a Governance Committee to provide decisioning and approval for changes
made to the Security Detections Framework
## Definitions

* _PR_ - Pull Request
* See: [Image Tiers]
* See: [Golden Container Definitions](./golden_container_contribution.md#definitionsterms) for additional definitions

## Scope

This repo is intended to list any detections which Godaddy is direcly responsible for maintaining. Third party detections which are maintained by the external entity do not need to be added to this repo unless there is a modification, required internal support, or specific knowledge that needs to be documented for other teams. 



## Governance Roles/Responsibilities

| Role                 | Description                                  | Accountabilities & Responsibilities         |
| :------------------- | :------------------------------------------- | :------------------------------------------ |
| Detection Owners     | Detection maintainers - [Cloud-Automation]   | Coding standards enforcement                |
|                      |                                              | Process standards enforcement               |
|                      |                                              | Maintenance of process                      |
|                      |                                              | Maintenance of documentation                |
|                      |                                              | Scheduling & running retros                 |
|                      |                                              | Identifying and remediating process gaps    |
|                      |                                              | Will have a permanent representative/seat at the Governance Committee |
|                      |                                              | Representative on the Governance Committee will be an active participant in said Committee |
|                      |                                              | Engaging Governance Committee for decisions under the Committee's responsibilities |
| Governance Committee | Business representatives from across GoDaddy | Determines and documents criteria for promotion/demotion of images between Tiers |
|                      |                                              | Determines if a GCI should be demoted from [Tier 1] |
|                      |                                              | Determines if a GCI should be promoted to [Tier 1] |
|                      |                                              | Drives identification & retirement of GCIs  |
|                      |                                              | Approves proposed retirement of GCIs        |
|                      |                                              | Drives adoption of GCIs                     |
|                      |                                              | Resolves handling of abandoned GCIs         |
| Observers            | Non-voting individuals                       | None                                        |

## Detection Owners

Detection Owners are responsible for 

operationalizing Governance Committee decisions, enforcing coding/process
standards, and maintaining the health of the repository and its associated features (issues, projects, etc).

Repository Owners will default to [Cloud-Automation] but can be changed by the Governance Committee. Should a change be
implemented, [Cloud-Automation] will assist the Governance Committee in transferring ownership of the repository to the
new owning team and onboarding the new team to the role.

## Governance Committee

The Governance Committee shall be responsible for deciding GCI [Image Tiers], image deprecation and will help drive
image adoption by GoDaddy teams. They will also assist in ensuring active GCIs have owning SMEs/teams.

The Governance Committee allow approves/rejects changes to the GCI process, and governance.

A [Governance Committee private slack channel] will be available to the Committee

### Governance Committee Membership

#### Joining/Leaving/Removal

##### Joining

* A person desiring membership on the Governance Committee can create a PR adding themselves to the
  [Current Membership](#current-membership-alphabetical).
  * PR is approved/rejected using standard [voting](#voting)
* A person can be nominated to membership via PR by being added to
  the [Current Membership](#current-membership-alphabetical).
  * PR is approved/rejected using standard [voting](#voting)
    and the approval of the nominee

Once a member joins, the [onboarding](#onboarding) procedure is applied.

##### Leaving/Removal

* Team members may retire at any time by submitting a PR removing themselves
  from [Current Membership](#current-membership-alphabetical) (required) and placing themselves
  in [Past Members](#past-members) (if they so choose)
* Failure to participate in six consecutive votes will result in a vote to remove the individual from the Governance
  Committee
* Team members can be removed by supermajority vote on the team mailing list.
  * For this vote, the member in question is not eligible to vote and does not count towards the quorum.
  * Any removal vote can cover only one single person.
* Upon death of a member, they leave the team automatically

In case a member leaves, the [offboarding](#offboarding) procedure is applied.

#### Current Membership (alphabetical)

| Repository Owners  |
| :----------------- |
| [Cloud-Automation] |

| Governance Committee Member | Term Start Date |
| :-------------------------- | :-------------- |
| TBD                                          




## Observers

Interested in helping grow GCIs? Open a PR with your name in this list as a way to start the conversation.

* A person desiring to be an observer can create a PR adding themselves to the [Current Observers](#current-observers).
* Merging is handled by standard [voting](#voting)
* Once merged the user is considered to be an `Observer`
* Observer privileges can be revoked, in part or whole, by a simple majority vote of the Governance Committee
* Observers will be included in the invitation list for Governance Committee meetings and can join the meetings to
  watch/listen, but are not permitted to Zoom chat/speak unless invited to do so by a Governance Committee member.
* Observers will be added to the [Governance Committee private slack channel] but are asked not to post to the channel
  unless asked to do so by a Committee member.


## On-/Off-boarding

### Onboarding

The new member is:

* Added to [@appservices/goldenimage-governance].
* Added to the team mailing list [gci-governance@godaddy.com].
* Announced on [golden_containers] by an existing team member. Ideally, the new member replies in this thread,
  acknowledging team membership.

### Offboarding

The ex-member is:

* Removed from [Current Membership](#current-membership-alphabetical) (required) and placed
  in [Past Members](#past-members) (if they so choose).
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
