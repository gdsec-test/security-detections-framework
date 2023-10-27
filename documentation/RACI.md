# Responsible, Accountable, Consulted, and Informed (RACI)


### These are the RACI responsibilities as they pertain to the detections framework.


| R = Responsible | A = Accountable|C = Consulted | I = Informed |
| :-------------- | :------------- | :----------- | :----------- |
|Those who do the work to complete the task.| The one ultimately answerable for the completion of the task, the one who ensures the prerequisites of the task are met and who delegates the work to those responsible.|	Those whose opinions are sought, typically subject matter experts; and with whom there is two-way communication.|Those who are kept up-to-date on progress, often only on completion of the task or deliverable.|

| Action|Threat Research | Detection Owner | Governance Comittee | Detection Consumer (e.g. GCSO/IR) | 
| :---- | :------------- | :-------------- | :------------------ | :------ |
| New alert is created and follows framework schemas     | I |	RA |	C | I |
| Alert is tested                 | I | RA |  C | I |
| Reporting an alert issue        | C | A  |    | R |
| Repairing alert issue           | C | RA | CI | I |
| Submitting tuning request       | C | A  | I  | R |
| Tuning an alert                 | C | RA | CI | I |
| Removing outdated detections    | C | R  | A   | IC |
| Setting up governance meetings       |   | R  | AC |  |
| Assign tasks from governace meetings | I | CI | RA | |
| Review false positive report    |   | R  | AC | I | 
| Repository permissions problem	| RAC |  |  I |   | 


