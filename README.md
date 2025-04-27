# Azure Security Analyzer

A Python tool to analyze security configurations of Azure cloud resources.

## Features

- Assess Azure Secure Score
- Analyze Network Security Groups (NSGs)
- Check Storage Account security
- Evaluate Virtual Machine configurations
- Audit SQL Database security settings

## Prerequisites

- Python 3.6+
- Azure subscription
- Required Python packages:

```bash
pip install azure-identity azure-mgmt-security azure-mgmt-network \
azure-mgmt-storage azure-mgmt-compute azure-mgmt-sql pandas
