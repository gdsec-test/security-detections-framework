# Detections

Detections are organized into sub-directories based on their platform.
Splunk-specific detections go into the splunk sub-directory, etc.

## Naming

To be able to quickly identify an alerts intention or desired goal by looking at its name, this name should be the one which populates into Service Now from the alerting platform. This creates a standard which can hopefully identify duplicate alerts with the same goal as well as allowing response to the alert to be stream lined.

The name is built from four components:

1. Environment (PCI, PKI, DEV, etc.)
2. Platform (Windows, Linux, Splunk, Okta, etc.)
3. [MITRE ATT&CK](https://attack.mitre.org/tactics/enterprise/) Category (Execution, Impact, etc.)
4. The purpose in five words or less (e.g. "Logs Failing")

These four components have their spaces replaced with dashes and are concatenated together with underscores. As an example:

1. Environment: PCI
2. Platform: Okta
3. MITRE Category: Credential Access
4. Purpose: Factor Reset-Add

Becomes: **PCI_Okta_Credential-Access_Factor-Reset-Add**

Keep all four components and the final name handy because they will go into the required metadata as explained in the following section.

## Metadata

Each detection must have a metadata file in JSON format included. The fields in the template are as defined:

* `name`
  * `full`: The properly formatted string as specified in the above section
  * `environment`: How this is being applied (PCI, PKI, DEV, etc.)
  * `attack`: The main, motivating MITRE ATT&CK TTP
  * `purpose`: A more specific focus of the alert
* `description`: Human-readable description of the alert, as well as a desired outcome or goal for responce
* `owner`: The person currently responsible for maintaining the alert
* `creator`: The original creator of the alert
* `team`: The GoDaddy team responsible for handling the alert
* `version`: Current version for this specific alert
* `lastUpdate`: Date of last update in ISO form (YYYY-MM-DD)
* `lifeCycleStage`:Description": "Which stage in the lifecycle the detection currently is; development, production, deprecated, retired
* `attack`: Relevant [MITRE ATT&CK categories](https://attack.mitre.org/tactics/enterprise/) (0 or more)
* `interval`: The time interval between regularly scheduled runs
* `test` (One of the following)
  * `archive`: Name of an archive file in the same directory that contains all testing information
  * `exception`: An explanation of why this alert is exempt from testing requirements

Find the template for the JSON metadata file [here](https://github.com/gdcorp-infosec/siem-documentation/blob/main/alerts/templates/metadata.json).
