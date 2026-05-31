| Field             | Value                                                                |
| ----------------- | -------------------------------------------------------------------- |
| Detection Name    | Anomalous SYSTEM-Level Scripting & LOLBin Execution via services.exe |
| Platform          | Windows                                                              |
| Data Sources      | Sysmon Event ID 1, Splunk Endpoint Data Model                        |
| ATT&CK Techniques | T1543.003, T1569.002, T1059, T1202                                   |
| Severity          | High                                                                 |
| Maturity          | Medium-High                                                          |
| Detection Type    | Behavioral Analytics                                                 |
| Execution Context | SYSTEM                                                               |
| Parent Process    | services.exe                                                         |

# Use Case: Anomalous SYSTEM-Level Scripting & LOLBin Execution via services.exe

## Description

This detection scenario monitors the creation of high-risk processes—specifically command/script interpreters and binary execution engines (LOLBins)—directly spawned by the Service Control Manager (`services.exe`) running under the high-privileged `SYSTEM` account.

Adversaries frequently abuse system services for privilege escalation or persistence (e.g., creating malicious services or modifying existing service configuration). This rule captures anomalous command-line arguments that deviate significantly from standard enterprise administrative service behaviors.

The monitored binaries were selected based on their observed prevalence in service-based post-exploitation activity and represent a focused subset of commonly abused execution utilities. Organizations may extend this coverage based on internal threat modeling and environmental baselines.

The detection aligns with the following MITRE ATT&CK techniques:

* **T1543.003** – Create or Modify System Process: Windows Service
* **T1569.002** – System Services: Service Execution
* **T1059** – Command and Scripting Interpreter
* **T1202** – Indirect Command Execution

> Note: This detection is not guaranteed to work exactly the same in every environment,
> since each organization may need to adjust it based on its own setup and needs. But the overall structure and logic stays the same.

---

## Key Detection Pillars

* **Service Boundary Anomaly:** Under normal operating conditions, `services.exe` rarely spawns interactive shells or script engines (`powershell.exe`, `cmd.exe`) directly with download cradles, encoded execution flags, or remote execution mechanisms under the `SYSTEM` context.

* **Targeted Telemetry Fusion:** To ensure maximum fidelity and overcome standalone Data Model limitations, this detection isolates service-spawned execution tracks via accelerated `tstats` queries and enriches them with Sysmon Event ID 1 telemetry for robust command-line forensics.

* **Deterministic Logic Segmentation:** The matching logic is strictly segregated into binary categories (Script Interpreters vs. Execution Engines) to maintain code clarity, improve maintainability, and reduce false positives associated with generic system operations.

---

## Discussion / Engineering Decision Context

During development, initial hypotheses explored monitoring native service-hosted containers such as `svchost.exe` and `TrustedInstaller.exe`. However, operational telemetry analysis indicated that execution abuse within those containers predominantly manifests through process injection or child-process spawning rather than anomalous command-line arguments within the hosting binaries themselves.

To ensure production reliability, reduce low-yield alert volume, and prevent logic leakage, the detection strategy was intentionally narrowed to **Direct Shell Spawning** initiated by the Service Control Manager.

By filtering execution tools directly at the pipeline entry stage, the search engine processes a highly refined dataset, making the detection suitable for high-throughput enterprise SIEM environments.

Additionally, due to the absence of consistently normalized command-line telemetry within the accelerated Endpoint Data Model, Sysmon Event ID 1 enrichment was intentionally introduced to preserve command-line fidelity while maintaining accelerated process discovery through `tstats`.

---

## Detection Logic (Splunk SPL)

```python
| tstats summariesonly=true count
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name="services.exe"
      AND Processes.user="*SYSTEM"
      AND Processes.process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe")
    by Processes.dest Processes.process_guid Processes.parent_process_name Processes.process_name Processes.process_path
| rename Processes.* as *
| rename process_guid as ProcessGuid

| append [
    search index=winevents EventCode=1 ParentImage="*\\services.exe"
    AND (
        Image="*\\powershell.exe"
        OR Image="*\\pwsh.exe"
        OR Image="*\\cmd.exe"
        OR Image="*\\mshta.exe"
        OR Image="*\\rundll32.exe"
        OR Image="*\\regsvr32.exe"
        OR Image="*\\wmic.exe"
        OR Image="*\\certutil.exe"
        OR Image="*\\bitsadmin.exe"
    )
    | fields dest ProcessGuid CommandLine ParentImage
]

| stats values(parent_process_name) as parent_process_name
        values(process_name) as process_name
        values(process_path) as process_path
        values(CommandLine) as CommandLine
        values(ParentImage) as ParentImage
        by dest ProcessGuid

| where isnotnull(CommandLine)
    AND isnotnull(process_name)

| where (

    (
        match(process_name,"(?i)(powershell|pwsh|cmd|wmic)")
        AND
        match(CommandLine,"(?i)(-enc|-encodedcommand|-nop|-w hidden|iex|downloadstring|frombase64string|invoke-webrequest|invoke-restmethod|iwr|irm|curl|wget|/c\\s+|/k\\s+)")
    )

    OR

    (
        match(process_name,"(?i)(mshta|rundll32|regsvr32|certutil|bitsadmin)")
        AND
        match(CommandLine,"(?i)(javascript|vbscript|http|ftp|scrobj\\.dll|/s|/u|/i|-urlcache|-download)")
    )

)

| where NOT match(CommandLine,"(?i)(SplunkUniversalForwarder|Splunk_TA_windows|netstat|tasklist|LocalDateTime)")
```

---

## False Positive Considerations

* Automated patch management scripts or enterprise software deployment agents (e.g., SCCM, Microsoft Configuration Manager, Windows Update components) running tasks as `SYSTEM`.
* Legitimate backup, monitoring, or configuration-management workflows executed through automation frameworks such as Group Policy, Ansible, or enterprise orchestration platforms.
* Security tooling, EDR sensors, or vulnerability scanners launching diagnostic commands under a service context.
* Legitimate COM registration or software installation activities involving `regsvr32.exe` may generate alerts and should be validated against expected deployment, upgrade, or maintenance operations.

---

## Analyst Guidance

### 1. Parent Service Identification

* Reconstruct the complete process lineage using `ProcessGuid`.
* Review Windows System logs for:

  * **Event ID 7045** – Service Installation
  * **Event ID 7040** – Service Configuration Change
* Determine which service initiated the suspicious process execution.

### 2. Command-Line De-obfuscation

* Inspect the `CommandLine` field for:

  * Base64-encoded payloads
  * Environment variable expansion
  * Excessive whitespace padding
  * Encoded PowerShell execution
* Decode content supplied via:

  * `-enc`
  * `-EncodedCommand`

### 3. Behavioral Scope Expansion

Pivot on:

* `ProcessGuid`
* `dest`
* Parent service name

Review adjacent telemetry for:

* **Sysmon Event ID 3** – Network Connections
* **Sysmon Event ID 11** – File Creation
* Additional child-process creation activity
* Lateral movement or persistence indicators

---

## Detection Maturity

**Maturity Level:** Medium-High

This rule represents a robust hybrid detection model that combines process lineage monitoring with command-line behavioral analytics. The design prioritizes operational fidelity, scalability, and investigation efficiency while maintaining a manageable false-positive profile.

### Future Improvements

* Baseline modeling of legitimate service-hosted command-line behavior on critical assets.
* Elimination of the `append` command through complete Endpoint Data Model enrichment and validation.
* Expansion of monitored execution utilities based on organization-specific threat models.
* Integration with **Sysmon Event ID 7 (Image Load)** to improve visibility into DLL hijacking scenarios.
* Integration with **Sysmon Event ID 10 (Process Access)** to enhance detection opportunities for process injection and credential access techniques.
* Correlation with service installation and modification telemetry to provide end-to-end visibility across the service abuse lifecycle.
