# Detections

Detections are organized into sub-directories based on their platform.
Splunk-specific detections go into the splunk sub-directory, etc.

## Naming

To be able to quickly identify an alerts intention or desired goal by looking at its name, this name should be the one which populates into Service Now from the alerting platform. This creates a standard which can hopefully identify duplicate alerts with the same goal as well as allowing response to the alert to be stream lined.

The name is built from four components:

1. Environment (PCI, PKI, DEV, etc.)
2. Platform (Windows, Linux, Splunk, Okta, etc.)
3. [MITRE ATT&CK](https://attack.mitre.org/tactics/enterprise/) Category ()
4. The purpose in five words or less (e.g. "Logs Failing")

These four components have their spaces replaced with dashes and are concatenated together with underscores. As an example:

1. Environment: PCI
2. Platform: Okta
3. MITRE Category: Credential Access
4. Purpose: Factor Reset-Add

Becomes: **PCI_Okta_Credential-Access_Factor-Reset-Add**
