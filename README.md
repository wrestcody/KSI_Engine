# FedRAMP 20x GRC-as-Code Persistent Validation Engine (KSI_Engine)

This project is the `KSI_Engine`, a FedRAMP 20x GRC-as-Code engine that serves as a **PVA Producer**. It embodies an **engineer-to-engineer** philosophy to achieve in-depth **Mission Assurance** by streamlining evidence collection and enabling **Automated Enforcement** for a FedRAMP 20x Moderate authorization.

## Project Overview & FedRAMP 20x Alignment

This engine provides **Persistent Validation (PVA) for KSI-SVC-04 (Configuration Management)** by performing automated validation of AWS S3 bucket configurations. To meet FedRAMP 20x Moderate standards, this **PVA** is executed on a **3-day continuous cycle**.

The core of the project is an AWS Lambda function that:
- Performs **Persistent Validation (PVA)** on each bucket's Public Access Block and default encryption status.
- Generates a machine-readable JSON CCE payload for every validation, providing a complete audit trail.

This GRC-as-Code approach directly implements the requirements of **KSI-SVC-04** by using Python and Terraform to manage and validate machine-based resources with automation.

## NIST CM-6 Mapping & Automated Enforcement Path

This project directly addresses the requirements of NIST 800-53 CM-6 through its PVA capabilities.

### Closed-Loop GRC & Automated Enforcement (KSI-CNA-08)

This engine demonstrates a full, closed-loop GRC process. When a `FAIL` status is detected during **Persistent Validation (PVA)**:
1. The CCE payload is transmitted to the `Vanguard_Agent` for risk analysis.
2. Simultaneously, a message is sent to an SQS queue (`remediation_trigger_queue`).

This SQS message is the **trigger for Automated Enforcement**. It initiates a downstream playbook to apply the required configuration, ensuring that deviations are not just detected, but are actively and automatically corrected. This workflow satisfies the requirements for **KSI-CNA-08 (Automated Enforcement)**.

## GRC Engineering Review Statement

As a GRC Engineering best practice, all AI-generated logic within this engine is subject to continuous human review to ensure the completeness and accuracy of the compliance evidence produced. This ensures the automation is trustworthy and that the data feeding our risk management decisions is of the highest integrity.

## Getting Started

1. **Deploy the infrastructure:** Use the provided Terraform script (`main.tf`) to deploy the Lambda function and all supporting resources.
2. **Observe the PVA Output:** The Lambda function will output a stream of CCE records to its execution logs. This output is designed to be ingested by a downstream GRC platform.
