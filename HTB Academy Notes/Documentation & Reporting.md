
14-08-2024 13:41 pm

Tags: [[Cybersecurity/Tags/Documentation & Reporting|Documentation & Reporting]]

References: https://academy.hackthebox.com/module/162/section/1533


# Documentation & Reporting

## Notetaking & Organization

Sample structure:
- Attack Path - paste as many screenshots or text with command inputs and outputs as possible
- Credentials - centralized place to keep all credentials found
- Findings - create a subfolder for each finding (whatever weakness you find in the system)
- Vulnerability Scan Research - basic vulnerabilities research notes
- Service Enumeration Research - basic notes on investigated services
- Web App Research - web app notes
- AD Enumeration Research - step by step AD enumeration that is performed
- OSINT - open source intel notes
- Administrative Information - centralized location to store contact information for other project stakeholders like Project Managers (PMs) or client Points of Contact (POCs), unique objectives/flags defined in the Rules of Engagement (RoE), and other items that you find yourself often referencing throughout the project. It can also be used as a running to-do list.
- Scoping Information - in order to store anything that will be testes
- Activity Log - everything that you did in detail with ss and text
- Payload Log - track of payloads used

Note: ==tmux logging== is used for terminal logging and is recommended.

==SEE [[Logging TUTORIAL]] for basic logging!==

## Types of Assessment Reports

1) Vulnerability Assessment = just assessing without exploiting (focus on confirming vulnerabilities and finding weaknesses)
2) Internal vs External Assessment = scans can be done on the company network internally or externally by an anonymous user

## Penetration Testing

- **Black Box**: The tester has minimal information, like just the company name or a basic network connection.
- **Grey Box**: The tester knows some details, such as specific IP addresses or network ranges.
- **White Box**: The tester has full access to information, including credentials, source code, and configurations.

## Components of a report

- **Executive Summary**: A high-level overview of the assessment, including key findings, overall risk level, and general recommendations. This section is for non-technical stakeholders and should be brief but informative.

- **Scope and Methodology**: Details about what was tested, how it was tested, and any limitations. This helps the client understand the boundaries of the assessment and the methods used.

- **Findings and Recommendations**:
    - **High-Level Findings**: Summarize the most critical vulnerabilities, prioritizing those that pose the greatest risk.
    - **Detailed Findings**: For each vulnerability, include a description, evidence, impact, and remediation advice. Each finding should be clearly explained with supporting data (like screenshots or command outputs) but avoid overwhelming the client with excessive technical details.

- **Attack Chain**: If multiple findings are interconnected, this section illustrates how they were used together to achieve a compromise. It helps the client understand the severity and impact of seemingly minor issues when combined.

- **Conclusion and Next Steps**: Summarize the overall security posture and provide actionable steps for remediation. This section should leave the client with a clear path forward.

## Writing an Attack Chain (https://academy.hackthebox.com/module/162/section/1535)

- **Start with a Summary**: Provide an overview of the attack chain.
- **Detail Each Step**: Walk through the exploitation process step-by-step, using supporting evidence like command outputs and screenshots.
- **Highlight Severity**: Show how the combination of findings escalated the overall risk.

## Executive Summary

- **Purpose of the Assessment**: Briefly explain why the penetration test was conducted, such as assessing current security defenses or meeting compliance requirements.

- **High-Level Findings**: Summarize the most significant vulnerabilities discovered during the assessment. Focus on the issues that pose the greatest risk to the organization, emphasizing those that could lead to severe consequences like data breaches or system compromises.

- **Overall Risk Assessment**: Provide a general assessment of the organization's security posture, often expressed as a risk level (e.g., high, medium, low). This gives executives a quick snapshot of where the organization stands.

- **Business Impact**: Highlight the potential impact of the identified vulnerabilities on the organization’s operations, reputation, and compliance. This section should relate the technical findings to business risks, helping non-technical stakeholders understand the implications.

- **Recommendations**: Offer high-level recommendations for remediation, prioritizing the most critical actions that should be taken to mitigate risks. This might include specific technical fixes, policy changes, or areas where additional investment is needed.

- **Strategic Considerations**: Discuss how the findings could influence strategic decisions, such as budgeting for security initiatives or revising cybersecurity policies. This is particularly important for stakeholders who might use the report to justify or request funding for security improvements.

- **Next Steps**: Outline the proposed actions following the assessment, such as detailed remediation efforts, follow-up testing, or additional security evaluations.

## How to Write Up a Finding

- in the "Findings" section we write what we found including each detail
- this is the "meat" of the report

Here is a list of what a finding MUST include:
- Description of the finding and what platform(s) the vulnerability affects
- Impact if the finding is left unresolved
- Affected systems, networks, environments, or applications
- Recommendation for how to address the problem
- Reference links with additional information about the finding and resolving it
- Steps to reproduce the issue and the evidence that you collected
Optional:
- CVE
- OWASP, MITRE IDs
- CVSS or similar score
- Ease of exploitation and probability of attack
- Any other information that might help learn about and mitigate the attack

Note: Findings should be presented in a way that allows recreation of exploits for the client.

### Effective Remediation Recommendations

#### Example 1

- `Bad`: Reconfigure your registry settings to harden against X.
    
- `Good`: To fully remediate this finding, the following registry hives should be updated with the specified values. Note that changes to critical components like the registry should be approached with caution and tested in a small group prior to making large-scale changes.
    
    - `[list the full path to the affected registry hives]`
        - Change value X to value Y

Note: Don't forget to include references.

## Apps for Automated Writing

|**Free**|**Paid**|
|---|---|
|[Ghostwriter](https://github.com/GhostManager/Ghostwriter)|[AttackForge](https://attackforge.com/)|
|[Dradis](https://dradisframework.com/ce/)|[PlexTrac](https://plextrac.com/)|
|[Security Risk Advisors VECTR](https://github.com/SecurityRiskAdvisors/VECTR)|[Rootshell Prism](https://www.rootshellsecurity.net/why-prism/)|
|[WriteHat](https://github.com/blacklanternsecurity/writehat)||










# Useful Links:

https://plextrac.com/ //FAST PENTEST REPORTS