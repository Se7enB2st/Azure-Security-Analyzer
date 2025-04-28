from azure.mgmt.security import SecurityCenter
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.sql import SqlManagementClient
import pandas as pd
import re
import time
from config import get_credentials, get_subscription_id
from typing import Dict, Any
import os

class AzureSecurityAnalyzer:
    def __init__(self):
        self._validate_credentials()
        self.credentials = get_credentials()
        self.subscription_id = get_subscription_id()
        self.security_client = SecurityCenter(self.credentials, self.subscription_id)
        self.network_client = NetworkManagementClient(self.credentials, self.subscription_id)
        self.storage_client = StorageManagementClient(self.credentials, self.subscription_id)
        self.compute_client = ComputeManagementClient(self.credentials, self.subscription_id)
        self.sql_client = SqlManagementClient(self.credentials, self.subscription_id)
        self._last_api_call = 0
        self._api_call_delay = 1  # 1 second delay between API calls

    def _rate_limit(self):
        """Simple rate limiter to prevent too many API calls"""
        current_time = time.time()
        time_since_last_call = current_time - self._last_api_call
        if time_since_last_call < self._api_call_delay:
            time.sleep(self._api_call_delay - time_since_last_call)
        self._last_api_call = time.time()

    def _validate_credentials(self) -> None:
        """Validate Azure credentials before initialization"""
        required_vars = ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_SUBSCRIPTION_ID']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

    def _sanitize_resource_name(self, name: str) -> str:
        """Sanitize resource names to prevent injection attacks"""
        if not isinstance(name, str):
            raise ValueError("Resource name must be a string")
        # Remove any potentially dangerous characters
        return re.sub(r'[^a-zA-Z0-9-_]', '', name)

    def _validate_subscription_id(self, subscription_id: str) -> bool:
        """Validate Azure subscription ID format"""
        return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', subscription_id))

    def analyze_secure_score(self) -> pd.DataFrame:
        """Analyze Azure Secure Score"""
        try:
            self._rate_limit()
            secure_scores = self.security_client.secure_scores.list()
            scores = []
            for score in secure_scores:
                if not isinstance(score.score.current, (int, float)) or not isinstance(score.score.max, (int, float)):
                    continue
                scores.append({
                    'Score': score.score.current,
                    'Max Score': score.score.max,
                    'Percentage': (score.score.current / score.score.max) * 100
                })
            return pd.DataFrame(scores)
        except Exception as e:
            print(f"Error analyzing secure score: {str(e)}")
            return pd.DataFrame()

    def analyze_nsgs(self) -> pd.DataFrame:
        """Analyze Network Security Groups"""
        try:
            self._rate_limit()
            nsgs = self.network_client.network_security_groups.list_all()
            nsg_data = []
            for nsg in nsgs:
                if not hasattr(nsg, 'name') or not hasattr(nsg, 'location'):
                    continue
                nsg_data.append({
                    'Name': self._sanitize_resource_name(nsg.name),
                    'Location': self._sanitize_resource_name(nsg.location),
                    'Rules Count': len(nsg.security_rules) if nsg.security_rules else 0
                })
            return pd.DataFrame(nsg_data)
        except Exception as e:
            print(f"Error analyzing NSGs: {str(e)}")
            return pd.DataFrame()

    def analyze_storage_accounts(self) -> pd.DataFrame:
        """Analyze Storage Account Security"""
        try:
            self._rate_limit()
            storage_accounts = self.storage_client.storage_accounts.list()
            storage_data = []
            for account in storage_accounts:
                if not hasattr(account, 'name') or not hasattr(account, 'location'):
                    continue
                storage_data.append({
                    'Name': self._sanitize_resource_name(account.name),
                    'Location': self._sanitize_resource_name(account.location),
                    'Https Only': account.enable_https_traffic_only,
                    'Blob Public Access': account.allow_blob_public_access,
                    'Minimum TLS Version': account.minimum_tls_version if hasattr(account, 'minimum_tls_version') else 'Unknown'
                })
            return pd.DataFrame(storage_data)
        except Exception as e:
            print(f"Error analyzing storage accounts: {str(e)}")
            return pd.DataFrame()

    def analyze_vms(self) -> pd.DataFrame:
        """Analyze Virtual Machine Security"""
        try:
            self._rate_limit()
            vms = self.compute_client.virtual_machines.list_all()
            vm_data = []
            for vm in vms:
                if not hasattr(vm, 'name') or not hasattr(vm, 'location'):
                    continue
                vm_data.append({
                    'Name': self._sanitize_resource_name(vm.name),
                    'Location': self._sanitize_resource_name(vm.location),
                    'OS Type': vm.storage_profile.os_disk.os_type.value if vm.storage_profile.os_disk else 'Unknown',
                    'Encryption Status': vm.storage_profile.os_disk.encryption_settings.enabled if hasattr(vm.storage_profile.os_disk, 'encryption_settings') else 'Unknown'
                })
            return pd.DataFrame(vm_data)
        except Exception as e:
            print(f"Error analyzing VMs: {str(e)}")
            return pd.DataFrame()

    def analyze_sql_databases(self) -> pd.DataFrame:
        """Analyze SQL Database Security"""
        try:
            self._rate_limit()
            servers = self.sql_client.servers.list()
            sql_data = []
            for server in servers:
                if not hasattr(server, 'name') or not hasattr(server, 'location'):
                    continue
                databases = self.sql_client.databases.list_by_server(server.resource_group_name, server.name)
                for db in databases:
                    sql_data.append({
                        'Server': self._sanitize_resource_name(server.name),
                        'Database': self._sanitize_resource_name(db.name),
                        'Location': self._sanitize_resource_name(server.location),
                        'TDE Status': db.transparent_data_encryption.status if hasattr(db, 'transparent_data_encryption') else 'Unknown',
                        'Auditing Status': db.auditing_state if hasattr(db, 'auditing_state') else 'Unknown'
                    })
            return pd.DataFrame(sql_data)
        except Exception as e:
            print(f"Error analyzing SQL databases: {str(e)}")
            return pd.DataFrame()

    def run_all_analyses(self) -> Dict[str, pd.DataFrame]:
        """Run all security analyses and return combined results"""
        if not self._validate_subscription_id(self.subscription_id):
            raise ValueError("Invalid subscription ID format")
            
        results = {
            'Secure Score': self.analyze_secure_score(),
            'Network Security Groups': self.analyze_nsgs(),
            'Storage Accounts': self.analyze_storage_accounts(),
            'Virtual Machines': self.analyze_vms(),
            'SQL Databases': self.analyze_sql_databases()
        }
        return results 