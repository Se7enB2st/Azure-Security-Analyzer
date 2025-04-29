# Azure Security Analyzer

A Python tool to analyze security configurations of Azure cloud resources.

## Features

- **Core Security Analysis**
  - Assess Azure Secure Score
  - Analyze Network Security Groups (NSGs)
  - Check Storage Account security
  - Evaluate Virtual Machine configurations
  - Audit SQL Database security settings
  - Azure AD Security Analysis
    - Conditional Access Policies
    - MFA Status
    - User Account Status
  - Role-Based Access Control (RBAC)
    - Role Assignment Analysis
    - Permission Level Assessment
    - Over-Privileged Account Detection
  - Security Center Integration
    - Security Recommendations
    - Severity-based Analysis
    - Resource-specific Security Status
  - Firewall Security
    - Azure Firewall Configuration
    - Threat Intelligence Settings
    - Network Traffic Analysis

- **Enhanced Security Measurements**
  - Key Vault Security Analysis
    - Soft delete configuration
    - Purge protection status
    - Network ACLs
  - Resource Protection
    - Resource lock analysis
    - Critical resource identification
  - Network Security
    - Detailed NSG rule analysis
    - Risky rule identification
    - Inbound/Outbound traffic analysis
  - Storage Security
    - Versioning status
    - Soft delete configuration
    - TLS and access settings

## Prerequisites

- Python 3.6+
- Azure subscription
- Required Python packages (see Installation)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/se7enb2st/azure-security-analyzer.git
cd azure-security-analyzer
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Configuration

1. Create a Service Principal in Azure:
   - Go to Azure Portal → Azure Active Directory → App Registrations
   - Create a new registration
   - Note down the Application (client) ID and Directory (tenant) ID
   - Create a new client secret in Certificates & secrets
   - Note down the client secret value

2. Set up your Azure credentials:
   - Create a `.env` file with your Azure credentials:
     ```
     AZURE_TENANT_ID=your_tenant_id
     AZURE_CLIENT_ID=your_client_id
     AZURE_CLIENT_SECRET=your_client_secret
     AZURE_SUBSCRIPTION_ID=your_subscription_id
     ```

3. Grant necessary permissions to the Service Principal:
   - Go to Azure Portal → Subscriptions → Your Subscription → Access Control (IAM)
   - Add role assignment:
     - Role: Reader
     - Select your Service Principal
     - Save

## Usage

Run the analyzer:
```bash
python main.py
```

The tool will:
- Analyze security configurations across your Azure resources
- Display a progress bar during analysis
- Show a summary of findings
- Save detailed results to a JSON file
- Log operations to `security_analysis.log`

### Analysis Output

The tool provides:
1. **Progress Tracking**
   - Real-time progress bar
   - Status updates for each analysis
2. **Comprehensive Security Reports**
   - Azure AD Security Status
   - RBAC Analysis
   - Security Center Recommendations
   - Firewall Configuration Analysis
   - Resource Security Status
3. **Detailed Logging**
   - Operation tracking
   - Error reporting
   - Security findings

## Security Features

- **Input Validation**
  - Sanitization of resource names
  - Validation of subscription IDs
  - Secure credential handling

- **Rate Limiting**
  - API call throttling
  - Request queuing
  - Error handling

- **Sensitive Data Protection**
  - Secure credential storage
  - Environment variable usage
  - Log sanitization

- **Error Handling**
  - Graceful failure recovery
  - Detailed error logging
  - Retry mechanisms

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.


```bash
pip install azure-identity azure-mgmt-security azure-mgmt-network \
azure-mgmt-storage azure-mgmt-compute azure-mgmt-sql pandas
