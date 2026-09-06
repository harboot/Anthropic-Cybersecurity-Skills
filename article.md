# Cybersecurity Research Article Analysis Guide

Use this guide when a user asks for an analysis of a cybersecurity research
article provided as a URL or as article text.

## Output requirements

1. Write the article in English.
2. Save it as `articles/{title}.md`, where `{title}` is a concise, lowercase,
   kebab-case version of the article title.
3. Put the source URL supplied by the user immediately below the title, using
   this format:

   ```markdown
   # Article Title

   Source: <https://example.com/source>
   ```

4. Do not substitute a search-result URL, publisher home page, or inferred URL
   for the source URL supplied by the user.

## Source handling

1. If the prompt contains only a URL, open and inspect the URL before beginning
   the analysis.
2. If the URL cannot be accessed, stop and tell the user that it cannot be
   accessed. Do not produce an analysis from the title, URL slug, search
   snippets, prior knowledge, or assumptions.
3. If the user supplies article text and asks to create an article using this
   guide, use the supplied text as the source. Ask for the source URL if it was
   not supplied, because the output must include it below the title.
4. Make every important factual claim traceable to the supplied source. Clearly
   distinguish source-confirmed facts from analytical inference.
5. Do not fabricate missing technical details, indicators, victimology,
   attribution, capabilities, or MITRE ATT&CK mappings.

## Analysis workflow

Analyze the provided cybersecurity research article, URL, or text. Use the
cybersecurity skills available in this repository and select only the skills
that are relevant to the subject. Depending on the source, these may cover:

- threat intelligence and incident analysis;
- vulnerabilities, exploitation, identity, cloud, network, or application
  security;
- malicious software and command-and-control activity, when present;
- indicators and other observable artifacts;
- MITRE ATT&CK mapping; and
- detection and threat-hunting opportunities.

The article may address any cybersecurity topic; do not assume that every source
is about malware or a backdoor. Do not simply summarize the source. Perform a
structured analysis using the following format, adapting subsection content to
the evidence available.

## 1. Executive Summary

Briefly explain:

- what happened or what the research discovered;
- the affected technology, organizations, industries, or users;
- the relevant threat actor, vulnerability, campaign, or security issue;
- the likely objective or impact; and
- the overall risk.

Explicitly state when the source does not identify one of these elements.

## 2. Key Points

Extract the most important findings from the research.

## 3. Activity or Attack Flow

Reconstruct the reported sequence step by step. Choose labels appropriate to the
subject rather than forcing a malware lifecycle. For example:

Exposure or Initial Access
→ Exploitation or Execution
→ Follow-on Activity
→ Impact

Clearly distinguish facts stated in the source from reasonable analytical
inference. If the source does not describe a sequence, explain the affected
architecture, trust boundary, or event timeline instead.

## 4. Technical Analysis

Analyze the technical subject actually covered by the source. Relevant topics
may include:

- vulnerability root cause and exploitation prerequisites;
- affected products, versions, configurations, or components;
- authentication, authorization, cloud, identity, network, or application
  behavior;
- malware capabilities, execution, persistence, and command-and-control, when
  malware is present;
- protocols, services, data flows, and trust boundaries; and
- differences among variants, techniques, environments, or observed cases.

Do not add malware-specific subsections when the source is not about malware.

## 5. MITRE ATT&CK Mapping

Create a table:

| Tactic | Technique | Technique ID | Evidence / Reason |
| --- | --- | --- | --- |

Only include techniques reasonably supported by the source. Do not invent ATT&CK
mappings. State when ATT&CK is not applicable or the evidence is insufficient.

## 6. Indicators and Relevant Artifacts

Extract and categorize every useful artifact the source provides, such as:

- IP addresses, domains, URLs, and network endpoints;
- file hashes, filenames, paths, and package or image names;
- registry keys, scheduled tasks, services, and mutexes;
- user agents, certificates, account or tenant identifiers, and cloud artifacts;
- vulnerable product versions, CVEs, configuration keys, API routes, and log
  fields; and
- any other observables relevant to the subject.

State explicitly when the source does not provide an applicable artifact
category. Do not treat generic technology names or legitimate shared
infrastructure as standalone indicators of compromise.

## 7. Detection Opportunities

Recommend practical, evidence-based detection ideas using the telemetry relevant
to the source, which may include:

- SIEM, EDR, operating-system, identity, cloud, application, audit, and API logs;
- network, firewall, DNS, proxy, IDS/IPS, and web application firewall telemetry;
  and
- source-derived observables and behavior-based correlations.

Describe detection logic rather than merely listing products. Clearly separate
source-derived opportunities from additional analytical recommendations.

## 8. Threat Hunting Recommendations

Provide concrete, testable hunting hypotheses. For each hypothesis include:

- what to search for;
- the relevant log source;
- the suspicious behavior or condition; and
- the related artifact, vulnerability, or ATT&CK technique.

If threat hunting is not applicable to the subject, replace this section with a
brief explanation rather than inventing hypotheses.
