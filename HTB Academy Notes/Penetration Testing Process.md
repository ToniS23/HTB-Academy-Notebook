
21-08-2024 18:00 pm

Tags: [[Enumeration]] [[Cybersecurity/Tags/Vulnerability assessment]] [[Exploitation]] [[Information Gathering]] [[Post-Exploitation]]

References: https://academy.hackthebox.com/module/90/section/1569


# Penetration Testing Process

---
![[0-PT-Process.webp]]

---
## Overview

### Pre-Engagement

`Pre-engagement` is educating the client and adjusting the contract. All necessary tests and their components are strictly defined and contractually recorded. In a face-to-face meeting or conference call, many arrangements are made, such as:

- `Non-Disclosure Agreement`
- `Goals`
- `Scope`
- `Time Estimation`
- `Rules of Engagement`

### Information Gathering

`Information gathering` describes how we obtain information about the necessary components in various ways. We search for information about the target company and the software and hardware in use to find potential security gaps that we may be able to leverage for a foothold.

### Vulnerability Assessment

Once we get to the `Vulnerability Assessment` stage, we analyze the results from our `Information Gathering` stage, looking for known vulnerabilities in the systems, applications, and various versions of each to discover possible attack vectors. Vulnerability assessment is the evaluation of potential vulnerabilities, both manually and through automated means. This is used to determine the threat level and the susceptibility of a company's network infrastructure to cyber-attacks.

### Exploitation

In the `Exploitation` stage, we use the results to test our attacks against the potential vectors and execute them against the target systems to gain initial access to those systems.

### Post-Exploitation

At this stage of the penetration test, we already have access to the exploited machine and ensure that we still have access to it even if modifications and changes are made. During this phase, we may try to escalate our privileges to obtain the highest possible rights and hunt for sensitive data such as credentials or other data that the client is concerned with protecting (pillaging). Sometimes we perform post-exploitation to demonstrate to a client the impact of our access. Other times we perform post-exploitation as an input to the lateral movement process described next.

### Lateral Movement

Lateral movement describes movement within the internal network of our target company to access additional hosts at the same or a higher privilege level. It is often an iterative process combined with post-exploitation activities until we reach our goal. For example, we gain a foothold on a web server, escalate privileges and find a password in the registry. We perform further enumeration and see that this password works to access a database server as a local admin user. From here, we can pillage sensitive data from the database and find other credentials to further our access deeper into the network. In this stage, we will typically use many techniques based on the information found on the exploited host or server.

### Proof-of-Concept

In this stage, we document, step-by-step, the steps we took to achieve network compromise or some level of access. Our goal is to paint a picture of how we were able to chain together multiple weaknesses to reach our goal so they can see a clear picture of how each vulnerability fits in and help prioritize their remediation efforts. If we don't document our steps well, it's hard for the client to understand what we were able to do and, thus, makes their remediation efforts more difficult. If feasible, we could create one or more scripts to automate the steps we took to assist our client in reproducing our findings. We cover this in-depth in the `Documentation & Reporting` module.

### Post-Engagement

During post-engagement, detailed documentation is prepared for both administrators and client company management to understand the severity of the vulnerabilities found. At this stage, we also clean up all traces of our actions on all hosts and servers. During this stage, we create the deliverables for our client, hold a report walkthrough meeting, and sometimes deliver an executive presentation to target company executives or their board of directors. Lastly, we will archive our testing data per our contractual obligations and company policy. We will typically retain this data for a set period or until we perform a post-remediation assessment (retest) to test the client's fixes.

## Pre-Engagement

- NDA
- Goals, Scope
- ROE (Rules Of Engagement)
- etc.

## Information Gathering

- Open-Source Intelligence
- Infrastructure Enumeration
- Service Enumeration
- Host Enumeration

## Vulnerability Assessment

- the gathered information is analyzed

|**Analysis Type**|**Description**|
|---|---|
|`Descriptive`|Descriptive analysis is essential in any data analysis. On the one hand, it describes a data set based on individual characteristics. It helps to detect possible errors in data collection or outliers in the data set.|
|`Diagnostic`|Diagnostic analysis clarifies conditions' causes, effects, and interactions. Doing so provides insights that are obtained through correlations and interpretation. We must take a backward-looking view, similar to descriptive analysis, with the subtle difference that we try to find reasons for events and developments.|
|`Predictive`|By evaluating historical and current data, predictive analysis creates a predictive model for future probabilities. Based on the results of descriptive and diagnostic analyses, this method of data analysis makes it possible to identify trends, detect deviations from expected values at an early stage, and predict future occurrences as accurately as possible.|
|`Prescriptive`|Prescriptive analytics aims to narrow down what actions to take to eliminate or prevent a future problem or trigger a specific activity or process.

## Exploitation

- we start exploiting based on the gathered information and vulnerability assessment

Note: The preparation of the exploit is also in this phase.

## Post-Exploitation

- here we gather as much sensitive information and data as possible

EDR (Endpoint Detection and Response) system = monitors end users devices

### Pillaging

- hunting for passwords on shares, local machines, in scripts, configuration files, password vaults, documents (Excel, Word, .txt files, etc.), and even email

### Persistence

- after exploiting and gaining a foothold we need to maintain our access
- this is done as a first step in the post-exploitation phase

## Lateral Movement

- in this stage we test what an attacker can do with the entire network














# Useful Links:

https://searchcode.com/ // used for OSINT
https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml // common ports
https://www.cve.org/ResourcesSupport/FAQs // CVE Database
https://nvd.nist.gov/vuln-metrics/cvss // CVSS (Common Vulnerability Scoring System) scoring
https://nvd.nist.gov/vuln-metrics/cvss // NVD (National Vulnerability Database) Calculator
