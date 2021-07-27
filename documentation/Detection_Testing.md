# Detection Testing

#### table of contents
 ** []
 
## Splunk Testing

* Within splunk there are several ways to test to validate an alert would fire, these options are to manipulate the Time window within your search query, modify the Time bucket, or populate example data into splunk

### Manipulate Time window

* This may be the simplest way to test with an output to Service Now
* This requires the alert logic be created, as well as configured to send output to Service Now
* Once a true positive event has been identified within the logs, you can adjust your time window of your alert logic to the specified date by adding 'Earliest' and 'Latest' time modifiers to the query
 ``` earliest=10/19/2018:00:00:00 latest=10/27/2018:00:00:00 ```
 Once these time modifiers have been added to the query, on the next scheduled run, the search would populate the true positive results, and send the ticket to Service Now. Once this test ticket has been sent off, the search query will need to be returned to its previous state with rolling time windows. 
 
 ### Modify the time Bucket
 
 * This Method will demonstrait within splunk every time the alert would have fired without sending any output. 
 * Thise Method requires the use of a Stats command within the search query, as well as a threashold limitation. 
 
          In this example, this search query uses a stats command, and is set to run every 15 minutes.
 
          ```
          earliest=-15m latest=now()
          index="aws_syslog" OR index=windows_events EventCode=1102 Computer!=*imaging-prod.local
          | eval Summary="The audit log was cleared."
          | stats values(Domain) as Domain values(AccountName) as AccountName count by MachineName 
          | where count > 10 
          ```
          
          if we expand the time window out to 30 days, Counts of events may be much greater than 10. in this scenario, we would add a 'Bucket' for the time to exist within to limit our count threshold to the same time window the alert should be running on
          
          ``` 
          earliest=-30d latest=now()
          index="aws_syslog" OR index=windows_events EventCode=1102 Computer!=*imaging-prod.local
          | eval Summary="The audit log was cleared."
          | bucket _time span=15m
          | stats values(Domain) as Domain values(AccountName) as AccountName count by MachineName _time
          | where count > 10 
          ```
          see the added 'Bucket' and '_time' peramaters added to the query. this will now create a full table with time stamps of every time the alert would have created a ticket in the last 30 days without actually outputing to a 3rd party
          

          
