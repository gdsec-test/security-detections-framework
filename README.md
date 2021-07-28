# Detection Framework Overview

## Purpose

This repository collects SIEM alerts, configurations, and dashboards across all products and environments.
It is the central source of truth for SIEM alerting at GoDaddy.

## Work Flow

![Work Flow Diagram](https://github.com/gdcorp-infosec/siem-documentation/blob/main/workflow.png)

Writing SIEM rules should follow this high-level work flow:

* For a more in depth workflow, consult The [Detection Lifecycle](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/Detection_Lifecycle_Framework.md)

1. Idea - something was found via threat hunting, a threat intelligence report tipped things off, or an incident identified a gap in coverage
2. Identify the appropriate tool - this repository organizes rules first by tool
3. Check this repository for existing rule coverage
4. Write Detection 
   1. Branch off of this repository's main branch
   2. Adhere to the rule [Naming Schema](https://github.com/gdcorp-infosec/siem-documentation/tree/main/alerts/detections#naming) 
   3. Create the corresponding [Meta Data ](https://github.com/gdcorp-infosec/siem-documentation/tree/main/alerts/detections#metadata)    
   4. Export your rule in a text-based format (plaintext, XML, JSON, YAML, etc. [Metadata text](https://github.com/gdcorp-infosec/siem-documentation/blob/main/alerts/templates/metadata.json))
6. Test rule 
   1. Include your test cases in the repository 
   2. Provide links to any necessary artifacts
7. Provide dashboards - include any dashboards that correspond to the new rule
8. Commit your changes to this repository
9. Notify Responding Teams (GCSO, IR) of New Detection

Splunk Example Rule: [Trend-Micro_Malicious-File_unable-to-remove](https://github.com/gdcorp-infosec/siem-documentation/tree/main/alerts/detections/splunk/Trend-Micro_Malicious-File_unable-to-remove)

## Important Documents
* [Governance](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/Governance-security_detections_framework.md)
* [Detection Lifecycle](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/Detection_Lifecycle_Framework.md)
* [RACI](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/RACI.md)
* [DACI](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/DACI.md)

## Getting Started

Here are some helpful guides for specific technologies:
* [How to Write a Splunk Detection](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/How_to_Create_a_Splunk_Alert.md) 
* [How to write a Tanium custom Signal (coming soon)]
* [How to Test a Detection](https://github.com/gdcorp-infosec/security-detections-framework/blob/main/documentation/Detection_Testing.md)
 * External Documentation
    * [IDS](https://github.secureserver.net/infosec-network/ids-sensor-rules)
    * [Splunk](https://docs.splunk.com/Documentation/Splunk/8.2.0/Alert/Aboutalerts)
    * [Tanium](https://docs.tanium.com/detect/detect/authoring_signals.html)

## Process'
* [Get Splunk Access](https://x.co/getsplunk)
* [Rule Creation Assistance Request (Coming Soon)](https://jira.godaddy.com/browse/ATLSNADMIN-8989)

