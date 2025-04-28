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
   - Copy `config.example.py` to `config.py`
   - Fill in your Azure credentials in `config.py`:
     - AZURE_TENANT_ID
     - AZURE_CLIENT_ID
     - AZURE_CLIENT_SECRET
     - AZURE_SUBSCRIPTION_ID

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
- Display results in the console
- Save detailed results to a JSON file
- Log operations to `security_analysis.log`

## Security Considerations

- Never commit your `config.py` file to version control
- Keep your Azure credentials secure
- Regularly rotate your client secrets
- Use the minimum required permissions for the Service Principal
- Review the generated logs and results files for sensitive information

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request


```bash
pip install azure-identity azure-mgmt-security azure-mgmt-network \
azure-mgmt-storage azure-mgmt-compute azure-mgmt-sql pandas
