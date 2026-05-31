# Detection : Anomalous SYSTEM-Level Scripting & LOLBin Execution via services.exe

This project contains a behavioral detection rule focused on identifying suspicious process execution originating from `services.exe` under the `SYSTEM` context in Windows environments.

The goal is to detect potential abuse of legitimate Windows services for executing scripting engines and LOLBins commonly used in post-exploitation scenarios.

## What it detects
- Execution of scripting engines (PowerShell, CMD, WMIC)
- Abuse of LOLBins (mshta, rundll32, regsvr32, certutil, bitsadmin)
- Suspicious command-line activity such as encoded commands, download cradles, and execution bypass techniques

## Data Sources
- Sysmon Event ID 1
- Splunk Endpoint Data Model (Endpoint.Processes)

## Use Case
This rule is intended for threat hunting and detection engineering purposes. It is designed as a baseline model and may require tuning based on environment-specific behavior and telemetry coverage.
It also includes analyst guidance to support investigation, False Positives and Potential improvments. 

## MITRE ATT&CK
- T1543.003 – Create or Modify System Process
- T1059 – Command and Scripting Interpreter
- T1202 – Indirect Command Execution
- T1569.002 – System Services

> Note : This detection should be adapted per environment depending on logging quality, service behavior, and organizational baselines.
