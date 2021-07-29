# New Detection Operational Readiness Review (ORR)

* This serves as a template for an OOR, this will be conducted as a meeting prior to any alert moving to production

## OOR Prerequisites 

* Detection logic has been created
* Detection has been Properly added in Security Detections Framework
* Detection has been tested 
* Detection has been placed in Dev 

## OOR Meeting 

### Scheduling

* A 15-30 minute meeting to review deteciton logic, and associate detection with pre-existing or new process for response team
* Detection creater/owner is responsible for scheduling meeting with the team responsible for actioning the detection (i.e GCSO, IR, etc.)

### Meeting Agenda

* Provide the folliwng information

| | |
| :---- | :------------- | 
| Location of deteciton in framework | |
| Detection Owner | |
|Target Release| |
|Jira Story| |
|Project Status| |
|Project Driver| |
|Project Approver| |
|Project Contributors| |
|Informed on the Project| |


* Go over the following questions 


| Questions | Answers  |
| :---- | :------------- | 
| Where Does the Detecton live | |
| What are the primary data sources | |
| Expected Fire Frequency | |
| What is the Goal of Detection | |
| what is the MITRE ATT&CK category | |
| Who are the main stakeholders? | |
| Have the stakeholders reviewed and signed off on the detection | |
| What is the plan for response to the detection | |
| are there any failure points in the detection | |
| is there a main vector for tuning | |

## ORR Outcomes (date review meeting held)
Attendees: 

The purpose of this meeting is to gauge the readiness of the deployment and make a go/no-go decision on moving forward with this detection. It's important that we document any take-aways from this meeting into a list that clearly says which category:

* `BLOCKER` - must do before we deploy
* `FAST FOLLOW` - must do asap after deploy, which could be 1-30 days
* `SHOULD` - should do at some point, to be prioritized with opportunity costs
* `DONE MM/DD` - change to green/done when completed
