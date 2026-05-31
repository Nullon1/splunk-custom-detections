# Splunk Custom Detections

A collection of custom Splunk detections developed during threat hunting, detection engineering, and security research activities.

This repository contains detection use cases covering different stages of the attack lifecycle. Each detection includes not only the SPL query itself, but also supporting documentation explaining the detection logic, data sources, investigation approach, false positive considerations, and potential improvements.

The objective is to document practical detection ideas that can be adapted, tested, and improved in different environments rather than provide one-size-fits-all production rules.

## What You'll Find Here

* Custom Splunk SPL detections
* Detection engineering projects
* Threat hunting use cases
* MITRE ATT&CK mapped detections
* Analyst investigation guidance
* Detection tuning considerations
* Detection maturity assessments

## About The Detections

Every detection is maintained in its own directory and includes dedicated documentation describing:

* What the detection looks for
* Required data sources
* Detection logic
* False positive scenarios
* Investigation recommendations
* Possible future improvements

## Queries List

> - Potential Initial Access via DLL Search Order Hijacking
> - LOLBin Execution via services.exe

## Notes
These detections were developed and tested using available telemetry and lab environments. Additional tuning, exclusions, and validation may be required before deployment in production environments.
