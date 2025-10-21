# FedRAMP 20x GRC-as-Code Persistent Validation Engine (KSI_Engine)

This project serves as a FedRAMP 20x GRC-as-Code continuous compliance engine, specifically designed to function as a Persistent Validation (PVA) producer. It demonstrates a "build-first" GRC Engineering approach to achieve in-depth continuous assurance and streamline evidence collection for a FedRAMP 20x Moderate authorization level.

## Project Overview & FedRAMP 20x Alignment

This engine provides **Persistent Validation for KSI-SVC-04 (Configuration Management)** by automating the continuous checking of AWS S3 buckets, which are treated as machine-based information resources. To meet FedRAMP 20x Moderate standards, the engine operates on a **3-day continuous cycle**, ensuring that configuration settings are validated at least once every three days.

The core of the project is an AWS Lambda function, deployed and scheduled via Terraform, that:
- Iterates through all S3 buckets in a specified AWS region.
- Checks each bucket's Public Access Block configuration and default encryption status against defined pass/fail criteria.
- Generates a machine-readable JSON object (Continuous Compliance Evidence - CCE) for **every check (pass or fail)**, providing a complete audit trail for the downstream risk system (Vanguard_Agent).

This GRC-as-Code approach directly implements the requirements of **KSI-SVC-04 (Manage configuration of machine-based information resources using automation)** by using Python and Terraform to programmatically enforce and validate security configurations.

## NIST 800-53 CM-6 Mapping & Automated Remediation Path

This project directly addresses the following requirements of NIST 800-53 CM-6:

- **CM-6:** The organization establishes and enforces configuration settings for information technology products and systems.
- **CM-6 (1):** The organization automates the management and enforcement of configuration settings.

### Closed-Loop GRC & Automated Enforcement (KSI-CNA-08)

This engine demonstrates a full, closed-loop GRC process by linking **Continuous Evaluation (KSI-SVC-01)** to an **Automated Remediation Path**. When a `FAIL` status is detected for a compliance check:
1.  The CCE payload is transmitted to the `Vanguard_Agent` for risk analysis.
2.  Simultaneously, a message is sent to an SQS queue (`remediation_trigger_queue`).

This SQS message serves as the trigger for a downstream automated remediation playbook (e.g., another Lambda function or a CI/CD pipeline) to apply the fix defined in the `remediation_playbooks` directory. This entire workflow satisfies the requirements for **KSI-CNA-08 (Automated Enforcement)**, ensuring that deviations from the established configuration baseline are not just detected, but are actively corrected in an automated fashion.

## GRC Engineering Review Statement

As a GRC Engineering best practice, all AI-generated logic within this engine is subject to continuous human review to ensure the completeness and accuracy of the compliance evidence produced. This ensures that the automation is trustworthy and that the data feeding our risk management decisions is of the highest integrity.

## Getting Started

1. **Deploy the infrastructure:** Use the provided Terraform script (`main.tf`) to deploy the Lambda function, the required IAM role, and the EventBridge rule that schedules execution every 3 days.
2. **Monitor the output:** The Lambda function will output a stream of CCE records (JSON format) to its execution logs. This output is designed to be ingested by an external GRC platform or risk management system.
