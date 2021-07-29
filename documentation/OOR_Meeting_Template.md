# New Detection Operational Readiness Review Meeting (ORR)

* This serves as a template for an OOR, this will be conducted as a meeting prior to any alert moving to production

## ORR Prerequisites 

* Detection logic has been created
* Detection has been Properly added in Security Detections Framework
* Detection has been tested 
* Detection has been placed in Dev 

## ORR Meeting 

### Scheduling

* A 15-30 minute meeting to review deteciton logic, and associate detection with pre-existing or new process for response team
* Detection creater/owner is responsible for scheduling meeting with the team responsible for actioning the detection (i.e GCSO, IR, etc.)

### Meeting Agenda

* Provide the folliwng information

| | |
| :---- | :------------- | 
| Location of detection in framework | 
| Detection Owner | 
|Target Release| 
|Jira Story| 


* Go over the following questions 


| Questions to answer during the meeting |  
| :---- |
| Where Does the Detection live | 
| What are the primary data sources | 
| Expected Fire Frequency | 
| What is the Goal of Detection | 
| what is the MITRE ATT&CK category | 
| Has all relivent data been uploaded to the Repo|
| What team is responding to the alert? | 
| Are there any potential failure points in the detection | 
| Are there potential fields relevant for tuning | 
| Does everyone agree the rule is good|

## ORR Outcomes Email Response 

The purpose of this meeting is to gauge the readiness of the deployment and make a go/no-go decision on moving forward with this detection. It's important that we document any take-aways from this meeting into a list that clearly says which category:

* `GO` - Send out email response to meeting group verifying atendee aproval
* `NO-GO` - Send out email response to meeting group with atendee rejection and rejection reasons, if necessary, follow up with changes to rule in future ORR Meeting. 

