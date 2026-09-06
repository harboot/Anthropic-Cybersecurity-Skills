# Angry Birds: Toy Ghouls' New Toys

Source: <https://github.com/harboot/Anthropic-Cybersecurity-Skills/blob/main/articles/angry-birds-toy-ghouls-new-toys-id.md>

> **Document type:** Threat intelligence, technical, detection, and threat-hunting analysis
> **Research provenance:** The source document identifies Kaspersky GERT/Kaspersky Security Services research, "Angry Birds: Toy Ghouls' new toys," dated September 4, 2026, as its primary research material.
> **Scope limitation:** This analysis does not include independent sample examination or external IOC enrichment. References such as **[Source—Communication]** point to the named sections of the research described in the supplied source.

## 1. Executive Summary

Kaspersky reported the first custom backdoors attributed to **Toy Ghouls**, a financially motivated group also known as **Bearlyfy, Laboo.boo**, and **Feral Wolf**. The group reportedly has targeted Russian organizations since 2025. After previously relying on GitHub tools, leaked Babuk and LockBit ransomware builders, and then its custom GenieLocker ransomware, the actor began using two "Bird" backdoor variants in early July 2026: **mqtt-bird-agent 0.1.0** and **matrix-bird-agent 0.1.0**. **[Source—Introduction]**

The backdoors were delivered to already-compromised systems over **Windows Remote Management (WinRM)** with Evil-WinRM or WinRM-fs and could install themselves as Windows services. One variant used the public HiveMQ MQTT broker; the other used an attacker-controlled Matrix server running Element. Both reported host status and metrics, received commands, executed them through PowerShell or Windows Command Shell, and returned the results. **[Source—Delivery, Installation, Communication]**

The overall risk is **high** because the implants provide persistent remote command execution and could let an attacker retain control of an endpoint. Their use of services and protocols that may appear legitimate can also complicate domain-based blocking. The source does not establish the method of compromise preceding WinRM, the number or industries of victims, data theft, lateral movement, or ransomware deployment in the same intrusion chain.

## 2. Key Points

- The two observed custom backdoors were `mqtt-bird-agent 0.1.0` (HiveMQ) and `matrix-bird-agent 0.1.0` (Element/Matrix). **[Source—Introduction]**
- The actor used WinRM, Evil-WinRM, and WinRM-fs to transfer an executable and `config.toml` to an already-compromised host. The initial compromise vector was not reported. **[Source—Delivery]**
- Persistence used the `cplsupport` service disguised as **Problem Reports Control Panel**, or the `wtas` service disguised as **Windows Telemetry Aggregator Service**. **[Source—Installation, Indicators of compromise]**
- Sensitive configuration values were sealed with ChaCha20-Poly1305 using a key derived from `MachineGuid`, binding the blob to the machine. The Element variant moved its configuration to the registry and deleted the initial configuration file. **[Source—Installation]**
- Both variants requested `http://ip-api.com/json` at startup to determine the host's public IP address and country. **[Source—Communication]**
- The HiveMQ variant executed commands with `PowerShell.exe -NonInteractive -NoProfile -Command` in a hidden window. The Matrix variant accepted messages beginning with `cmd:` and used the Windows command-line interface. **[Source—Communication]**
- The Matrix account found in the Element SQLite database was `panel-bot`; custom message types included `m.bird.status`, `m.bird.metrics`, and `m.bird.cmd_response`. **[Source—Communication]**
- `broker.hivemq.com` and `ip-api.com` are legitimate services subject to abuse. Blocking either globally without contextual validation may cause operational disruption.

## 3. Activity or Attack Flow

### Source-supported chain

**Already-compromised host (compromise mechanism not described)**
→ **Delivery:** executable and configuration transferred over WinRM with Evil-WinRM/WinRM-fs
→ **Execution:** backdoor launched from a command-line session or with its installation option
→ **Installation and persistence:** implant registered a Windows service and used an internal `--service`/`service` argument
→ **Configuration sealing:** sensitive fields sealed with a `MachineGuid`-based key; the Matrix variant stored the blob in the registry
→ **Discovery:** request to `ip-api.com/json` obtained the public IP address and country
→ **Command and control:** implant sent status and metrics and retrieved commands through HiveMQ or a Matrix/Element room
→ **Command execution:** commands ran through PowerShell (HiveMQ) or Windows Command Shell (Matrix)
→ **Response:** stdout, stderr, exit code, and duration returned to the C2 channel. **[Source—Delivery, Installation, Communication]**

### Facts, unknowns, and inference

- **Source-confirmed:** WinRM was used for delivery to systems that were already compromised.
- **Unknown:** How the credentials or WinRM privileges were obtained, and whether WinRM also supported lateral movement.
- **Analytical inference:** Service installation and writes under `HKLM` ordinarily require administrative privileges. This is a technical implication, not source evidence of a privilege-escalation method.
- **Not established:** Deployment of GenieLocker, encryption, exfiltration, credential theft, or ransomware impact on hosts carrying these backdoors.

## 4. Technical Analysis

### Shared behavior

| Area | Reported behavior |
| --- | --- |
| Operating mode | Interactive execution or persistence as a Windows service |
| Configuration | Searches for `config.toml` in the working directory and then under `%PROGRAMDATA%`; `-c`/`--config` can specify another path |
| Configuration protection | ChaCha20-Poly1305 with a key derived from `HKLM\Software\Microsoft\Cryptography\MachineGuid`; decryption failure terminates the implant |
| Discovery | `GET http://ip-api.com/json` to obtain public IP and country |
| Telemetry | Online status, hostname, timestamp, location, CPU, memory, disk, load average, and uptime |
| Core capability | Receives and executes commands, then returns stdout, stderr, exit code, and duration |

**[Source—Installation, Communication]**

### Variant differences

| Feature | HiveMQ / `mqtt-bird-agent` | Element / `matrix-bird-agent` |
| --- | --- | --- |
| Observed filename | `cplsupport.exe` | `wtass.exe` |
| Fallback configuration | `%PROGRAMDATA%\cplsupport\config.toml` | `%PROGRAMDATA%\SynapseAgent\config.toml` |
| Persistence | Service `cplsupport` / "Problem Reports Control Panel" | Service `wtas` / "Windows Telemetry Aggregator Service" |
| Configuration storage | File containing a sealed blob | File deleted after first run; blob stored at `HKLM\Software\synapse\Config\SealedConfig` |
| Sensitive data | `agent_privkey`, `channel_id`, `server_pubkey` | Server address, room ID, `access_token`; session token may be added after login |
| C2 | `broker.hivemq.com:8883` and an actor cluster | `meet.element[.]tw`, a Matrix room, and account `panel-bot` |
| Command retrieval | Request to `[cluster_id]/cmd/req` | Message beginning with `cmd:` |
| Interpreter | Hidden PowerShell with `-NonInteractive -NoProfile -Command` | Windows command-line interface |
| Interval control | Configuration-defined | `config:set_interval`, 5–3,600 seconds, persisted in the registry |
| Response | `[cluster_id]/cmd/res` | Event `m.bird.cmd_response` |

**[Source—Installation, Communication, Indicators of compromise]**

> **Protocol caveat:** The source characterizes the first variant as MQTT/HiveMQ but describes operations as GET/POST requests to paths on port 8883. Without a packet capture or sample, this analysis preserves the source's description and does not infer unreported protocol framing.

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence / Reason |
| --- | --- | --- | --- |
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 | WinRM with Evil-WinRM/WinRM-fs transferred the backdoor and configuration. The behavior supports the technique, although the source does not prove movement between hosts. |
| Persistence; Privilege Escalation | Create or Modify System Process: Windows Service | T1543.003 | The backdoor can install itself as the `cplsupport` or `wtas` service. |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | The HiveMQ variant executes commands through PowerShell with the reported parameters. |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | The Matrix variant executes commands through the Windows command-line interface. |
| Discovery | System Network Configuration Discovery: Internet Connection Discovery | T1016.001 | A request to `ip-api.com/json` determines the host's public IP address and country. |
| Discovery | System Information Discovery | T1082 | The implant collects the hostname and CPU, memory, disk, load, and uptime metrics. |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | The Matrix variant communicates through Element/Matrix; the source also describes GET/POST operations for the HiveMQ variant. |
| Command and Control | Web Service | T1102 | The actor used the public HiveMQ service and Element messenger for task and result exchange. |
| Defense Evasion | Obfuscated Files or Information | T1027 | Sensitive configuration fields are encrypted with ChaCha20-Poly1305; this concerns configuration data, not payload encryption. |
| Defense Evasion | Modify Registry | T1112 | The Matrix variant writes sealed configuration and its metrics interval to the registry. |

These mappings reflect reported behavior and do not assert that Toy Ghouls has an official MITRE ATT&CK group profile. Tactic context matters: WinRM use alone does not prove initial access or lateral movement without authentication records and connection-origin data.

## 6. Indicators and Relevant Artifacts

Network values are defanged where practical. The source supplies only MD5 file hashes; responders should calculate SHA-256 values from internally recovered samples.

### Files and hashes

| Type | Value | Context |
| --- | --- | --- |
| File / MD5 | `cplsupport.exe` — `BFADBEEE63A4F0BF19EC9DEB8FA58F58` | HiveMQ variant |
| File / MD5 | `wtass.exe` — `7916C33688385525078BEE504C90F359` | Element variant |
| Filename | `config.toml` | Generic; correlate with its path, service, hash, or behavior |

### Registry and services

- `HKLM\Software\synapse\Config\SealedConfig`
- `HKLM\Software\SynapseAgent\metrics_interval`
- `HKLM\Software\Microsoft\Cryptography\MachineGuid` — a legitimate Windows location read for key derivation, not a standalone IOC
- Service `cplsupport`; display name `Problem Reports Control Panel`
- Service `wtas`; display name `Windows Telemetry Aggregator Service`

### Network and C2 artifacts

- `meet.element[.]tw`
- `broker.hivemq[.]com:8883` — legitimate shared infrastructure; do not block on the domain alone without assessing business use
- `hxxp://ip-api[.]com/json` — a legitimate service and contextual signal, not independent proof of compromise
- HiveMQ path/topic-like artifacts: `[cluster_id]/status`, `[cluster_id]/metrics3`, `[cluster_id]/cmd/req`, and `[cluster_id]/cmd/res`
- Matrix account/role: `panel-bot`
- Command prefix: `cmd:`
- Configuration command: `config:set_interval`
- Event/message types: `m.bird.status`, `m.bird.metrics`, and `m.bird.cmd_response`

### Product verdicts listed by the source

- `HEUR:Backdoor.Win64.Suptoml.gen`
- `HEUR:Trojan.Script.Zapchast.conf`
- `Backdoor.Win64.Agent.smgdvy`
- `Trojan.Script.Zapchast.abwm`
- `Trojan.Win64.Agent.smgsfo`
- `Trojan.Script.Zapchast.abwo`

### Artifacts not provided

The source does not provide C2 IP addresses, SHA-1/SHA-256 hashes, mutexes, scheduled tasks, user agents, TLS certificate fingerprints, actual room or cluster/channel IDs, agent/server public keys, installed executable paths, or a victim-organization list. **[Source—Indicators of compromise and full report]**

## 7. Detection Opportunities

### Source-derived signals

1. **Service creation:** Alert on service names `cplsupport` and `wtas`, or their reported display names, especially when the image path points to an unsigned binary or unusual location.
2. **File matches:** Search EDR inventories, file events, sandboxes, gateways, and forensic repositories for both MD5 hashes. Calculate and distribute SHA-256 hashes for recovered samples.
3. **Registry changes:** Monitor creation or modification of `SealedConfig` and `metrics_interval` at the exact paths above.
4. **Process behavior:** Detect a newly created service process launching `powershell.exe` with `-NonInteractive -NoProfile -Command`, correlated with outbound traffic.
5. **Network activity:** Identify non-browser or unexpected agent processes reaching `ip-api.com/json`, `meet.element.tw`, or `broker.hivemq.com` on port 8883.
6. **C2 semantics:** Where application telemetry or lawful TLS inspection is available, search for `m.bird.*`, `config:set_interval`, `cmd:`, `cmd/req`, `cmd/res`, `metrics3`, and `status` in a consistent connection context.

### Additional correlation logic

- Correlate, on one host and within a short window: **WinRM activity → file creation (`cplsupport.exe`, `wtass.exe`, or `config.toml`) → service installation → internet connection**.
- Useful Windows events include Security **4697** and Service Control Manager **7045** for new services; Sysmon **1**, **3**, **11**, and **12–14** for process, network, file, and configured registry telemetry.
- PowerShell Operational **4104** may capture commands when script-block logging is enabled; Security **4688** may contain command lines when the corresponding policy is enabled.
- Review WinRM Operational logs and Security **4624** events for source, account, logon type, and temporal proximity. Compare activity with approved jump hosts and administration patterns.
- Baseline legitimate use of HiveMQ, Matrix/Element, and ip-api. Prioritize periodic connections from unexpected servers and traffic owned by a newly introduced binary.

```text
service_create
| where service_name in ("cplsupport", "wtas")
   or display_name in ("Problem Reports Control Panel",
                       "Windows Telemetry Aggregator Service")
| join host within 15m (
    network_connection
    | where domain in ("meet.element.tw", "broker.hivemq.com", "ip-api.com")
  )
```

```text
process_create
| where process_name =~ "powershell.exe"
| where command_line has_all ("-NonInteractive", "-NoProfile", "-Command")
| where parent_process is a newly_created_service
```

These examples are analytical starting points that require baseline testing. The PowerShell arguments are not unique by themselves; correlating the parent service, registry or file artifacts, and network destination should improve precision.

## 8. Threat Hunting Recommendations

| Hypothesis | What to search for | Log source | Suspicious behavior | Artifact / ATT&CK |
| --- | --- | --- | --- | --- |
| Toy Ghouls installed Bird as a service | Service name/display name, image path, installation time | Security 4697, System 7045, EDR service inventory, SYSTEM registry hive | New `cplsupport`/`wtas` service with an unsigned binary or unusual path | Service artifacts; T1543.003 |
| Delivery occurred through WinRM | WinRM session, account, source host, file write | WinRM Operational, 4624/4688, EDR, PowerShell logs | Remote administration outside the baseline followed by `config.toml` or executable creation | Evil-WinRM/WinRM-fs context; T1021.006 |
| The HiveMQ Bird variant is active | Port 8883 connection, DNS, periodicity, owning process | Firewall/NDR, DNS, proxy/TLS metadata, Sysmon 3, EDR | New binary/service contacts `broker.hivemq.com`, followed by recurring PowerShell execution | Domain and paths; T1102/T1071.001 |
| The Matrix Bird variant is active | DNS/TLS to `meet.element.tw`, local Element SQLite artifacts | DNS, proxy, firewall, EDR file access, forensic collection | Non-browser service accesses the domain; database contains `panel-bot` or `m.bird.*` | Matrix artifacts; T1102/T1071.001 |
| The implant sealed its configuration | Registry writes and `config.toml` deletion | Sysmon 11–14, EDR file/registry telemetry, USN Journal, registry hive | One process reads `MachineGuid`, writes `SealedConfig`, and deletes the configuration file | Registry artifact; T1112/T1027 |
| The implant performed public-IP discovery | Exact URL request and owning process | Proxy, DNS, NDR, EDR network telemetry | New service/non-browser requests `ip-api.com/json` immediately before C2 activity | URL; T1016.001 |
| C2 triggered command execution | Parent-child process and adjacent connections | EDR process tree, 4688, 4104, Sysmon 1/3 | Bird service launches PowerShell/cmd and C2 traffic follows execution | PowerShell flags; T1059.001/T1059.003 |

Classify every hunt result as **confirmed**, **likely**, **benign**, or **needs enrichment**. A single connection to a legitimate service is not sufficient to establish compromise.
