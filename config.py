import os
from azure.identity import DefaultAzureCredential

# Azure credentials
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID')
AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
AZURE_SUBSCRIPTION_ID = os.getenv('AZURE_SUBSCRIPTION_ID')

def get_credentials():
    """Get Azure credentials using DefaultAzureCredential"""
    return DefaultAzureCredential()

def get_subscription_id():
    """Get Azure subscription ID"""
    return AZURE_SUBSCRIPTION_ID 