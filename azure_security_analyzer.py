from azure.mgmt.security import SecurityCenter
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.sql import SqlManagementClient
import pandas as pd
from config import get_credentials, get_subscription_id

class AzureSecurityAnalyzer:
    def __init__(self):
        self.credentials = get_credentials()
        self.subscription_id = get_subscription_id()
        self.security_client = SecurityCenter(self.credentials, self.subscription_id)
        self.network_client = NetworkManagementClient(self.credentials, self.subscription_id)
        self.storage_client = StorageManagementClient(self.credentials, self.subscription_id)
        self.compute_client = ComputeManagementClient(self.credentials, self.subscription_id)
        self.sql_client = SqlManagementClient(self.credentials, self.subscription_id)

    def analyze_secure_score(self):
        """Analyze Azure Secure Score"""
        try:
            secure_scores = self.security_client.secure_scores.list()
            scores = []
            for score in secure_scores:
                scores.append({
                    'Score': score.score.current,
                    'Max Score': score.score.max,
                    'Percentage': (score.score.current / score.score.max) * 100
                })
            return pd.DataFrame(scores)
        except Exception as e:
            print(f"Error analyzing secure score: {str(e)}")
            return pd.DataFrame()

    def analyze_nsgs(self):
        """Analyze Network Security Groups"""
        try:
            nsgs = self.network_client.network_security_groups.list_all()
            nsg_data = []
            for nsg in nsgs:
                nsg_data.append({
                    'Name': nsg.name,
                    'Location': nsg.location,
                    'Rules Count': len(nsg.security_rules) if nsg.security_rules else 0
                })
            return pd.DataFrame(nsg_data)
        except Exception as e:
            print(f"Error analyzing NSGs: {str(e)}")
            return pd.DataFrame()

    def analyze_storage_accounts(self):
        """Analyze Storage Account Security"""
        try:
            storage_accounts = self.storage_client.storage_accounts.list()
            storage_data = []
            for account in storage_accounts:
                storage_data.append({
                    'Name': account.name,
                    'Location': account.location,
                    'Https Only': account.enable_https_traffic_only,
                    'Blob Public Access': account.allow_blob_public_access
                })
            return pd.DataFrame(storage_data)
        except Exception as e:
            print(f"Error analyzing storage accounts: {str(e)}")
            return pd.DataFrame()

    def analyze_vms(self):
        """Analyze Virtual Machine Security"""
        try:
            vms = self.compute_client.virtual_machines.list_all()
            vm_data = []
            for vm in vms:
                vm_data.append({
                    'Name': vm.name,
                    'Location': vm.location,
                    'OS Type': vm.storage_profile.os_disk.os_type.value if vm.storage_profile.os_disk else 'Unknown'
                })
            return pd.DataFrame(vm_data)
        except Exception as e:
            print(f"Error analyzing VMs: {str(e)}")
            return pd.DataFrame()

    def analyze_sql_databases(self):
        """Analyze SQL Database Security"""
        try:
            servers = self.sql_client.servers.list()
            sql_data = []
            for server in servers:
                databases = self.sql_client.databases.list_by_server(server.resource_group_name, server.name)
                for db in databases:
                    sql_data.append({
                        'Server': server.name,
                        'Database': db.name,
                        'Location': server.location,
                        'TDE Status': db.transparent_data_encryption.status if hasattr(db, 'transparent_data_encryption') else 'Unknown'
                    })
            return pd.DataFrame(sql_data)
        except Exception as e:
            print(f"Error analyzing SQL databases: {str(e)}")
            return pd.DataFrame()

    def run_all_analyses(self):
        """Run all security analyses and return combined results"""
        results = {
            'Secure Score': self.analyze_secure_score(),
            'Network Security Groups': self.analyze_nsgs(),
            'Storage Accounts': self.analyze_storage_accounts(),
            'Virtual Machines': self.analyze_vms(),
            'SQL Databases': self.analyze_sql_databases()
        }
        return results 