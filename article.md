# Cybersecurity Research Article Analysis Guide

Use this guide when a user asks for analysis of a cybersecurity research article
provided as a URL or as article text.

## Source handling

1. If the prompt contains only a URL, open and inspect the URL before beginning
   the analysis.
2. If the URL cannot be accessed, stop and tell the user that the URL cannot be
   accessed. Do not produce an analysis from the title, URL slug, search snippets,
   prior knowledge, or assumptions.
3. If the user supplies article text and asks to "buat artikel menggunakan panduan
   article.md", use the supplied text as the source.
4. Cite or reference the relevant part of the source for every important factual
   claim. Clearly distinguish source-confirmed facts from analytical inference.
5. Do not fabricate missing technical details, indicators, victimology, attribution,
   capabilities, or MITRE ATT&CK mappings.

## Analysis workflow

Analyze the provided cybersecurity research article, URL, or text.

Use the cybersecurity skills available in this repository. Automatically identify
and apply the most relevant skills for:

- threat intelligence analysis;
- malware and backdoor analysis;
- indicators of compromise;
- persistence analysis;
- command-and-control analysis;
- MITRE ATT&CK mapping; and
- detection and mitigation recommendations.

Do not simply summarize the article. Perform a structured cybersecurity analysis
using the following format.

## 1. Executive Summary

Provide a concise explanation of:

- what happened;
- the threat actor;
- malware or backdoors involved;
- targeted organizations or industries;
- the attacker's objective; and
- overall risk.

## 2. Key Points

Extract the most important findings from the research.

## 3. Attack Flow

Reconstruct the attack chain step by step, for example:

Initial Access / Delivery
→ Execution
→ Installation
→ Persistence
→ Command and Control
→ Actions performed by the attacker

Clearly distinguish facts explicitly stated in the article from reasonable
analytical inference.

## 4. Malware / Backdoor Analysis

Explain:

- malware or backdoor names;
- capabilities;
- execution behavior;
- persistence mechanisms;
- C2 mechanisms;
- protocols and services used; and
- differences between malware variants.

## 5. MITRE ATT&CK Mapping

Create a table:

| Tactic | Technique | Technique ID | Evidence / Reason |
| --- | --- | --- | --- |

Only include techniques reasonably supported by the source. Do not invent ATT&CK
mappings.

## 6. Indicators of Compromise

Extract all available IOCs and categorize them:

- IP addresses;
- domains;
- URLs;
- file hashes;
- filenames;
- registry keys;
- scheduled tasks and services;
- mutexes;
- user agents;
- MQTT topics and Matrix identifiers; and
- other relevant artifacts.

State explicitly when the source does not provide an IOC category. Do not infer an
IOC from generic technology names or legitimate shared infrastructure.

## 7. Detection Opportunities

Recommend practical detection ideas for:

- SIEM;
- EDR;
- Windows Event Logs;
- network and firewall telemetry;
- DNS;
- proxies; and
- IDS/IPS.

Where appropriate, describe detection logic rather than simply listing products.
Separate source-derived detection opportunities from additional analyst
recommendations.

## 8. Mitigation

Provide prioritized mitigation.

### Immediate

Actions SOC and incident-response teams should take if compromise is suspected.

### Short-term

Controls that can reduce exposure.

### Long-term

Hardening and architectural recommendations.

## 9. Threat Hunting Recommendations

Provide concrete, testable hunting hypotheses. For each hypothesis include:

- what to search for;
- the relevant log source;
- suspicious behavior; and
- the related IOC or ATT&CK technique.

## 10. Analyst Assessment

Provide an independent assessment of:

- the sophistication of the threat;
- interesting or unusual attacker behavior;
- why any identified C2 protocol or service may be attractive to the attacker
  (including HiveMQ/MQTT or Element/Matrix when relevant);
- potential detection challenges; and
- what SOC analysts should prioritize.

Do not discuss HiveMQ/MQTT or Element/Matrix when they are unrelated to the source.

## 11. Source Confidence

Separate:

- facts confirmed by the research source;
- analytical inference; and
- information requiring additional verification.

Name the actual research source in the first category rather than assuming that
every article comes from Securelist.
