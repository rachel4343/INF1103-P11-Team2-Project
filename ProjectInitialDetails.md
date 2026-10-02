INF1103 Project Initial Details

1. Problem Statement and Target Users
Phishing emails are a common cybersecurity threat because attackers use social engineering techniques such as urgency, impersonation, misleading links and requests for sensitive information to deceive users into taking unsafe actions. In an organisation, employees may report suspicious emails with different levels of detail. IT or cybersecurity personnel must then manually examine and prioritise these reports, which can be time-consuming when many reports are received. Inconsistent prioritisation may also delay attention to potentially high-risk cases.
Our proposed application, PhishGuard – AI-Powered Phishing Detector, aims to provide an initial screening and prioritisation of suspicious-email reports. The system will analyse the information submitted by a user, extract relevant phishing indicators and produce a structured assessment.
The application has two primary user groups, employees who receive suspicious emails and need a simple way to report relevant information and cybersecurity personnel who is responsible for reviewing suspicious-email reports. They can use the system's structured assessments and priority levels to identify urgent cases and manage reports more consistently.

2. User Inputs
Employees will submit structured information about a suspicious email, including:
Employees
Input 	Description
Sender's email address/display name	Identifies apparent sender and assist in analysing spoofing or impersonation indicators.
Email subject 	Provides context on the claimed purpose of the email.
Email body	Main text used to analyse tactics like urgency, threats etc.
URLs	Links to be verified for malicious sites or phishing pages.
Attachments	Attachments for identifying potential malware or risks.
Reason for suspicion	Employee's personal judgement on the situation.
Actions taken	Whether the employee clicked, opened, or entered sensitive information.

IT/Cybersecurity Personnel
Input 	Description
Report status update 	Current investigation stage.
Priority override 	Expert adjustment to the system-assigned priority where necessary.
Investigation notes 	To record findings and actions taken.
Assigned reviewer 	Person responsible for handling the case.
The I/O Manager will collect and validate these inputs before passing the complete record to the AI Manager.

3. Use of AI
Every submitted phishing report will be sent to an AI API. The AI will interpret the email’s content and context to identify potential indicators such as impersonation, pressure tactics, requests for sensitive information, and suspicious links or malicious attachments.
Unlike simple keyword matching, the AI will consider relationships between multiple indicators and variations in wording. For example, an email that impersonates a trusted organisation, creates an account and directs the user to a login page, with many high-risk indicators.
The AI will return a structured JSON assessment containing fields such as threat level, attack type, confidence, impersonation indicator, urgency-manipulation indicator, credential-request indicator, suspicious-link indicator, attachment-risk indicator, recommended action and supporting explanation.
The AI Manager will construct the prompt, parse the response and validate it against a predefined schema. Malformed responses will be rejected and retried where appropriate. API failures will be handled gracefully and may result in manual review rather than causing the application to crash. Finally, the AI passes its complete assessment to the Logic Manager 
AI is essential because phishing emails can use different wordings and subtle social-engineering techniques that cannot always be identified through simple keyword matching. AI allows PhishGuard to interpret unstructured email content and convert it into structured security indicators.

4. Business Rules
The Logic Manager will apply deterministic business rules to the validated AI-generated fields. This ensures that the reports are prioritised consistently based on multiple phishing indicators rather than simply displaying AI’s raw assessment.
Examples include:
•	If threat_level == "critical" and confidence >= 0.85, the report is assigned Critical priority and recommended for Immediate Security Investigation.
•	If credential_request == true, suspicious_link == true, and confidence >= 0.80, the report is assigned Urgent Security Review.
•	If impersonation == true, urgency_manipulation == true, and threat_level == "high", the report is assigned High-Priority Review.
•	If threat_level == "medium" and confidence >= 0.75, the report is assigned a Security Review.
•	If threat_level == "low", confidence >= 0.90, and no suspicious link is detected, the report is assigned Low Priority and recommended for Routine review.
•	If AI confidence is below the required threshold, required AI fields are missing or response is invalid after retry, the report is assigned Manual Review Required.
•	If conflicting indicators are detected, the system will prioritise the higher-risk outcome to reduce the possibility of overlooking a potential malicious email.
The final record will contain the original report, validated AI analysis, final priority, recommended handling and review status. Records will be stored in JSON to persist between program runs. The Data Manager will support filtering reports by fields such as threat level, attack type and review status, while handling missing or corrupted files safely. 
The application will use a fully procedural architecture consisting of an I/O Manager, AI Manager, Logic Manager and Data Manager. It will contain no classes and will be designed to run in Docker.

GitHub Repository URL: https://github.com/rachel4343/INF1103-P11-Team2-Project.git