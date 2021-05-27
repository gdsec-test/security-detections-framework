# SIEM Documentation

## Purpose

This repository collects SIEM alerts, configurations, and dashboards across all products and environments.
It is the central source of truth for SIEM alerting at GoDaddy.

## Work Flow

![Work Flow Diagram](https://github.com/gdcorp-infosec/siem-documentation/blob/main/workflow.png)

Writing SIEM rules should follow this high-level work flow:

1. Idea - something was found via threat hunting, a threat intelligence report tipped things off, or an incident identified a gap in coverage
2. Identify the appropriate tool - this repository organizes rules first by tool
3. Check this repository for existing rule coverage
4. Write rule
   1. Branch off of this repository's main branch
   2. Adhere to the rule naming schema
   3. Create the corresponding metadata
   4. Export your rule in a text-based format (plaintext, XML, JSON, YAML, etc.)
6. Test rule
   1. Include your test cases in the repository
   2. Provide links to any necessary artifacts
7. Provide dashboards - include any dashboards that correspond to the new rule
8. Commit your changes to this repository

## Getting Started

Here are some helpful guides on rules for specific technologies:
* [IDS](https://github.secureserver.net/infosec-network/ids-sensor-rules)
* [Splunk](https://docs.splunk.com/Documentation/Splunk/8.2.0/Alert/Aboutalerts)
* [Tanium](https://docs.tanium.com/detect/detect/authoring_signals.html)
