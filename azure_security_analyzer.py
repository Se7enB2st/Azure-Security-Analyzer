from azure.mgmt.security import SecurityCenter
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.graphrbac import GraphRbacManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient
import pandas as pd
import re
import time
from config import get_credentials, get_subscription_id, get_timeout, retry_with_backoff
from typing import Dict, Any
import os
import logging

logger = logging.getLogger(__name__)

class AzureSecurityAnalyzer:
    def __init__(self):
        self._validate_credentials()
        self.credentials = get_credentials()
        self.subscription_id = get_subscription_id()
        self.timeout = get_timeout()
        
        # Initialize clients with timeout
        self.security_client = SecurityCenter(
            self.credentials, 
            self.subscription_id,
            timeout=self.timeout
        )
        self.network_client = NetworkManagementClient(
            self.credentials, 
            self.subscription_id,
            timeout=self.timeout
        )
        self.storage_client = StorageManagementClient(
            self.credentials, 
            self.subscription_id,
            timeout=self.timeout
        )
        self.compute_client = ComputeManagementClient(
            self.credentials, 
            self.subscription_id,
            timeout=self.timeout
        )
        self.sql_client = SqlManagementClient(
            self.credentials, 
            self.subscription_id,
            timeout=self.timeout
        )
        self.keyvault_client = KeyVaultManagementClient(
            self.credentials,
            self.subscription_id,
            timeout=self.timeout
        )
        self.resource_client = ResourceManagementClient(
            self.credentials,
            self.subscription_id,
            timeout=self.timeout
        )
        self.auth_client = AuthorizationManagementClient(
            self.credentials,
            self.subscription_id,
            timeout=self.timeout
        )
        self.graph_client = GraphRbacManagementClient(
            self.credentials,
            os.getenv('AZURE_TENANT_ID'),
            timeout=self.timeout
        )
        
        # Initialize Policy Insights client
        self.policy_client = PolicyInsightsClient(
            self.credentials,
            self.subscription_id,
            timeout=self.timeout
        )
        
        # Initialize Policy client for definitions and assignments
        self.policy_management_client = PolicyClient(
            self.credentials,
            self.subscription_id,
            timeout=self.timeout
        )
        
        # Initialize MSI client for managed identities
        self.msi_client = ManagedServiceIdentityClient(
            self.credentials,
            self.subscription_id,
            timeout=self.timeout
        )
        
        self._last_api_call = 0
        self._api_call_delay = 1  # 1 second delay between API calls
        
        # Validate permissions
        self._validate_permissions()

    def _validate_permissions(self) -> None:
        """Validate that the service principal has required permissions"""
        try:
            # Try to list resources to check permissions
            retry_with_backoff(self.security_client.secure_scores.list)
            logger.info("Successfully validated security permissions")
        except Exception as e:
            logger.error(f"Permission validation failed: {str(e)}")
            raise ValueError("Service principal does not have required permissions. Please ensure it has at least Reader role.")

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
            secure_scores = retry_with_backoff(self.security_client.secure_scores.list)
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
            logger.error(f"Error analyzing secure score: {str(e)}")
            return pd.DataFrame()

    def analyze_nsgs(self) -> pd.DataFrame:
        """Analyze Network Security Groups"""
        try:
            self._rate_limit()
            nsgs = retry_with_backoff(self.network_client.network_security_groups.list_all)
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
            logger.error(f"Error analyzing NSGs: {str(e)}")
            return pd.DataFrame()

    def analyze_storage_accounts(self) -> pd.DataFrame:
        """Analyze Storage Account Security"""
        try:
            self._rate_limit()
            storage_accounts = retry_with_backoff(self.storage_client.storage_accounts.list)
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
            logger.error(f"Error analyzing storage accounts: {str(e)}")
            return pd.DataFrame()

    def analyze_vms(self) -> pd.DataFrame:
        """Analyze Virtual Machine Security"""
        try:
            self._rate_limit()
            vms = retry_with_backoff(self.compute_client.virtual_machines.list_all)
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
            logger.error(f"Error analyzing VMs: {str(e)}")
            return pd.DataFrame()

    def analyze_sql_databases(self) -> pd.DataFrame:
        """Analyze SQL Database Security"""
        try:
            self._rate_limit()
            servers = retry_with_backoff(self.sql_client.servers.list)
            sql_data = []
            for server in servers:
                if not hasattr(server, 'name') or not hasattr(server, 'location'):
                    continue
                databases = retry_with_backoff(
                    self.sql_client.databases.list_by_server,
                    server.resource_group_name,
                    server.name
                )
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
            logger.error(f"Error analyzing SQL databases: {str(e)}")
            return pd.DataFrame()

    def analyze_key_vaults(self) -> pd.DataFrame:
        """Analyze Key Vault security settings"""
        try:
            self._rate_limit()
            vaults = retry_with_backoff(self.keyvault_client.vaults.list)
            vault_data = []
            for vault in vaults:
                if not hasattr(vault, 'name') or not hasattr(vault, 'location'):
                    continue
                vault_data.append({
                    'Name': self._sanitize_resource_name(vault.name),
                    'Location': self._sanitize_resource_name(vault.location),
                    'Soft Delete Enabled': vault.properties.enable_soft_delete if hasattr(vault.properties, 'enable_soft_delete') else False,
                    'Purge Protection': vault.properties.enable_purge_protection if hasattr(vault.properties, 'enable_purge_protection') else False,
                    'Network ACLs': bool(vault.properties.network_acls) if hasattr(vault.properties, 'network_acls') else False
                })
            return pd.DataFrame(vault_data)
        except Exception as e:
            logger.error(f"Error analyzing Key Vaults: {str(e)}")
            return pd.DataFrame()

    def analyze_resource_locks(self) -> pd.DataFrame:
        """Analyze resource locks for critical resources"""
        try:
            self._rate_limit()
            locks = retry_with_backoff(self.resource_client.management_locks.list_at_subscription_level)
            lock_data = []
            for lock in locks:
                if not hasattr(lock, 'name') or not hasattr(lock, 'level'):
                    continue
                lock_data.append({
                    'Name': self._sanitize_resource_name(lock.name),
                    'Level': lock.level,
                    'Notes': lock.notes if hasattr(lock, 'notes') else ''
                })
            return pd.DataFrame(lock_data)
        except Exception as e:
            logger.error(f"Error analyzing resource locks: {str(e)}")
            return pd.DataFrame()

    def analyze_network_security(self) -> pd.DataFrame:
        """Analyze network security settings"""
        try:
            self._rate_limit()
            # Get network security groups
            nsgs = retry_with_backoff(self.network_client.network_security_groups.list_all)
            security_data = []
            
            for nsg in nsgs:
                if not hasattr(nsg, 'name') or not hasattr(nsg, 'location'):
                    continue
                
                # Analyze NSG rules
                inbound_rules = [r for r in nsg.security_rules if r.direction.lower() == 'inbound'] if nsg.security_rules else []
                outbound_rules = [r for r in nsg.security_rules if r.direction.lower() == 'outbound'] if nsg.security_rules else []
                
                # Check for risky rules
                risky_inbound = sum(1 for r in inbound_rules if r.access.lower() == 'allow' and r.destination_port_range == '*')
                risky_outbound = sum(1 for r in outbound_rules if r.access.lower() == 'allow' and r.destination_port_range == '*')
                
                security_data.append({
                    'Name': self._sanitize_resource_name(nsg.name),
                    'Location': self._sanitize_resource_name(nsg.location),
                    'Total Rules': len(nsg.security_rules) if nsg.security_rules else 0,
                    'Inbound Rules': len(inbound_rules),
                    'Outbound Rules': len(outbound_rules),
                    'Risky Inbound Rules': risky_inbound,
                    'Risky Outbound Rules': risky_outbound
                })
            
            return pd.DataFrame(security_data)
        except Exception as e:
            logger.error(f"Error analyzing network security: {str(e)}")
            return pd.DataFrame()

    def analyze_storage_security(self) -> pd.DataFrame:
        """Analyze storage account security settings"""
        try:
            self._rate_limit()
            storage_accounts = retry_with_backoff(self.storage_client.storage_accounts.list)
            storage_data = []
            
            for account in storage_accounts:
                if not hasattr(account, 'name') or not hasattr(account, 'location'):
                    continue
                
                # Get blob service properties
                blob_service = retry_with_backoff(
                    self.storage_client.blob_services.get_service_properties,
                    account.resource_group_name,
                    account.name
                )
                
                storage_data.append({
                    'Name': self._sanitize_resource_name(account.name),
                    'Location': self._sanitize_resource_name(account.location),
                    'Https Only': account.enable_https_traffic_only,
                    'Blob Public Access': account.allow_blob_public_access,
                    'Minimum TLS Version': account.minimum_tls_version if hasattr(account, 'minimum_tls_version') else 'Unknown',
                    'Versioning Enabled': blob_service.is_versioning_enabled if hasattr(blob_service, 'is_versioning_enabled') else False,
                    'Soft Delete Enabled': blob_service.delete_retention_policy.enabled if hasattr(blob_service, 'delete_retention_policy') else False
                })
            
            return pd.DataFrame(storage_data)
        except Exception as e:
            logger.error(f"Error analyzing storage security: {str(e)}")
            return pd.DataFrame()

    def analyze_azure_ad_security(self) -> pd.DataFrame:
        """Analyze Azure AD security settings"""
        try:
            self._rate_limit()
            ad_data = []
            
            # Get conditional access policies
            policies = retry_with_backoff(self.graph_client.conditional_access_policies.list)
            for policy in policies:
                ad_data.append({
                    'Type': 'Conditional Access Policy',
                    'Name': policy.display_name,
                    'State': policy.state,
                    'Users Included': len(policy.conditions.users.include_users) if hasattr(policy.conditions, 'users') else 0,
                    'Users Excluded': len(policy.conditions.users.exclude_users) if hasattr(policy.conditions, 'users') else 0,
                    'Applications Included': len(policy.conditions.applications.include_applications) if hasattr(policy.conditions, 'applications') else 0
                })
            
            # Get MFA status
            mfa_status = retry_with_backoff(self.graph_client.users.list)
            for user in mfa_status:
                ad_data.append({
                    'Type': 'MFA Status',
                    'Name': user.display_name,
                    'MFA Enabled': user.mfa_enabled if hasattr(user, 'mfa_enabled') else False,
                    'Account Enabled': user.account_enabled
                })
            
            return pd.DataFrame(ad_data)
        except Exception as e:
            logger.error(f"Error analyzing Azure AD security: {str(e)}")
            return pd.DataFrame()

    def analyze_role_assignments(self) -> pd.DataFrame:
        """Analyze role assignments and permissions"""
        try:
            self._rate_limit()
            role_data = []
            
            # Get all role assignments
            assignments = retry_with_backoff(self.auth_client.role_assignments.list)
            for assignment in assignments:
                role_data.append({
                    'Principal Name': assignment.principal_name,
                    'Role Name': assignment.role_definition_name,
                    'Scope': assignment.scope,
                    'Assignment Type': assignment.type
                })
            
            return pd.DataFrame(role_data)
        except Exception as e:
            logger.error(f"Error analyzing role assignments: {str(e)}")
            return pd.DataFrame()

    def analyze_network_security_center(self) -> pd.DataFrame:
        """Analyze Azure Security Center recommendations"""
        try:
            self._rate_limit()
            security_data = []
            
            # Get security recommendations
            recommendations = retry_with_backoff(self.security_client.recommendations.list)
            for rec in recommendations:
                security_data.append({
                    'Name': rec.name,
                    'Severity': rec.severity,
                    'Status': rec.status,
                    'Resource Type': rec.resource_type,
                    'Recommendation': rec.description
                })
            
            return pd.DataFrame(security_data)
        except Exception as e:
            logger.error(f"Error analyzing Security Center: {str(e)}")
            return pd.DataFrame()

    def analyze_firewall_rules(self) -> pd.DataFrame:
        """Analyze Azure Firewall rules"""
        try:
            self._rate_limit()
            firewall_data = []
            
            # Get Azure Firewall rules
            firewalls = retry_with_backoff(self.network_client.azure_firewalls.list_all)
            for firewall in firewalls:
                if hasattr(firewall, 'ip_configurations'):
                    for config in firewall.ip_configurations:
                        firewall_data.append({
                            'Name': firewall.name,
                            'Location': firewall.location,
                            'Public IP': config.public_ip_address if hasattr(config, 'public_ip_address') else 'None',
                            'Private IP': config.private_ip_address if hasattr(config, 'private_ip_address') else 'None',
                            'Threat Intel Mode': firewall.threat_intel_mode if hasattr(firewall, 'threat_intel_mode') else 'Alert'
                        })
            
            return pd.DataFrame(firewall_data)
        except Exception as e:
            logger.error(f"Error analyzing firewall rules: {str(e)}")
            return pd.DataFrame()

    def analyze_policy_compliance(self) -> pd.DataFrame:
        """Analyze Azure Policy compliance across resources"""
        try:
            self._rate_limit()
            policy_states = retry_with_backoff(
                self.policy_client.policy_states.list_query_results_for_subscription,
                policy_states_resource='latest',
                subscription_id=self.subscription_id
            )
            
            compliance_data = []
            for state in policy_states:
                if not hasattr(state, 'compliance_state') or not hasattr(state, 'resource_id'):
                    continue
                    
                resource_id = state.resource_id
                resource_name = resource_id.split('/')[-1]
                resource_type = resource_id.split('/')[6]  # Resource type is typically at this index
                
                compliance_data.append({
                    'Resource Name': self._sanitize_resource_name(resource_name),
                    'Resource Type': self._sanitize_resource_name(resource_type),
                    'Compliance State': state.compliance_state,
                    'Policy Definition ID': state.policy_definition_id,
                    'Policy Assignment ID': state.policy_assignment_id,
                    'Timestamp': state.timestamp.isoformat() if hasattr(state, 'timestamp') else 'Unknown'
                })
            
            return pd.DataFrame(compliance_data)
        except Exception as e:
            logger.error(f"Error analyzing policy compliance: {str(e)}")
            return pd.DataFrame()

    def analyze_policy_assignments(self) -> pd.DataFrame:
        """Analyze Azure Policy assignments"""
        try:
            self._rate_limit()
            assignments = retry_with_backoff(
                self.policy_management_client.policy_assignments.list
            )
            
            assignment_data = []
            for assignment in assignments:
                if not hasattr(assignment, 'name') or not hasattr(assignment, 'display_name'):
                    continue
                
                # Get enforcement mode and parameters
                enforcement_mode = getattr(assignment, 'enforcement_mode', 'Default')
                parameters = getattr(assignment, 'parameters', {})
                
                # Get scope information
                scope = assignment.scope
                scope_type = 'Subscription' if '/subscriptions/' in scope else 'Resource Group' if '/resourceGroups/' in scope else 'Management Group'
                
                assignment_data.append({
                    'Assignment Name': self._sanitize_resource_name(assignment.name),
                    'Display Name': assignment.display_name,
                    'Policy Definition ID': assignment.policy_definition_id,
                    'Scope': scope,
                    'Scope Type': scope_type,
                    'Enforcement Mode': enforcement_mode,
                    'Parameters Count': len(parameters),
                    'Description': getattr(assignment, 'description', ''),
                    'Created By': getattr(assignment, 'created_by', 'Unknown'),
                    'Created On': getattr(assignment, 'created_on', 'Unknown')
                })
            
            return pd.DataFrame(assignment_data)
        except Exception as e:
            logger.error(f"Error analyzing policy assignments: {str(e)}")
            return pd.DataFrame()

    def analyze_policy_definitions(self) -> pd.DataFrame:
        """Analyze Azure Policy definitions"""
        try:
            self._rate_limit()
            definitions = retry_with_backoff(
                self.policy_management_client.policy_definitions.list
            )
            
            definition_data = []
            for definition in definitions:
                if not hasattr(definition, 'name') or not hasattr(definition, 'display_name'):
                    continue
                
                # Get policy type and mode
                policy_type = getattr(definition, 'policy_type', 'Unknown')
                policy_mode = getattr(definition, 'mode', 'Unknown')
                
                # Get metadata
                metadata = getattr(definition, 'metadata', {})
                category = metadata.get('category', 'Unknown')
                version = metadata.get('version', 'Unknown')
                
                # Get parameters
                parameters = getattr(definition, 'parameters', {})
                
                definition_data.append({
                    'Definition Name': self._sanitize_resource_name(definition.name),
                    'Display Name': definition.display_name,
                    'Policy Type': policy_type,
                    'Policy Mode': policy_mode,
                    'Category': category,
                    'Version': version,
                    'Parameters Count': len(parameters),
                    'Description': getattr(definition, 'description', ''),
                    'Effect': getattr(definition, 'policy_rule', {}).get('then', {}).get('effect', 'Unknown')
                })
            
            return pd.DataFrame(definition_data)
        except Exception as e:
            logger.error(f"Error analyzing policy definitions: {str(e)}")
            return pd.DataFrame()

    def analyze_service_principals(self) -> pd.DataFrame:
        """Analyze Azure Service Principals"""
        try:
            self._rate_limit()
            # Get all service principals
            sps = retry_with_backoff(self.graph_client.service_principals.list)
            
            sp_data = []
            for sp in sps:
                if not hasattr(sp, 'app_id') or not hasattr(sp, 'display_name'):
                    continue
                
                # Get app roles and oauth2 permissions
                app_roles = getattr(sp, 'app_roles', [])
                oauth2_permissions = getattr(sp, 'oauth2_permissions', [])
                
                # Get key credentials and password credentials
                key_creds = getattr(sp, 'key_credentials', [])
                password_creds = getattr(sp, 'password_credentials', [])
                
                # Get owners
                owners = []
                try:
                    owner_list = retry_with_backoff(
                        self.graph_client.service_principals.list_owners,
                        sp.object_id
                    )
                    owners = [owner.display_name for owner in owner_list]
                except Exception:
                    pass
                
                sp_data.append({
                    'Display Name': sp.display_name,
                    'App ID': sp.app_id,
                    'Object ID': sp.object_id,
                    'Enabled': sp.account_enabled,
                    'App Roles Count': len(app_roles),
                    'OAuth2 Permissions Count': len(oauth2_permissions),
                    'Key Credentials Count': len(key_creds),
                    'Password Credentials Count': len(password_creds),
                    'Owners Count': len(owners),
                    'Created On': getattr(sp, 'created_date_time', 'Unknown'),
                    'Last Password Change': max(
                        [cred.end_date_time for cred in password_creds],
                        default='Never'
                    ),
                    'Last Key Rotation': max(
                        [cred.end_date_time for cred in key_creds],
                        default='Never'
                    )
                })
            
            return pd.DataFrame(sp_data)
        except Exception as e:
            logger.error(f"Error analyzing service principals: {str(e)}")
            return pd.DataFrame()

    def analyze_managed_identities(self) -> pd.DataFrame:
        """Analyze Azure Managed Identities"""
        try:
            self._rate_limit()
            # Get all user-assigned managed identities
            user_assigned_identities = retry_with_backoff(
                self.msi_client.user_assigned_identities.list_by_subscription
            )
            
            identity_data = []
            
            # Process user-assigned identities
            for identity in user_assigned_identities:
                if not hasattr(identity, 'name') or not hasattr(identity, 'location'):
                    continue
                
                # Get associated resources
                associated_resources = []
                try:
                    resources = retry_with_backoff(
                        self.resource_client.resources.list,
                        filter=f"identity.userAssignedIdentities/contains(keys, '{identity.name}')"
                    )
                    associated_resources = [resource.name for resource in resources]
                except Exception:
                    pass
                
                identity_data.append({
                    'Name': self._sanitize_resource_name(identity.name),
                    'Type': 'User-Assigned',
                    'Location': self._sanitize_resource_name(identity.location),
                    'Resource Group': identity.id.split('/')[4],
                    'Associated Resources Count': len(associated_resources),
                    'Principal ID': getattr(identity, 'principal_id', 'Unknown'),
                    'Client ID': getattr(identity, 'client_id', 'Unknown'),
                    'Tenant ID': getattr(identity, 'tenant_id', 'Unknown')
                })
            
            # Get system-assigned identities from VMs
            vms = retry_with_backoff(self.compute_client.virtual_machines.list_all)
            for vm in vms:
                if hasattr(vm, 'identity') and vm.identity and vm.identity.type == 'SystemAssigned':
                    identity_data.append({
                        'Name': self._sanitize_resource_name(vm.name),
                        'Type': 'System-Assigned',
                        'Location': self._sanitize_resource_name(vm.location),
                        'Resource Group': vm.id.split('/')[4],
                        'Associated Resources Count': 1,
                        'Principal ID': vm.identity.principal_id,
                        'Client ID': vm.identity.client_id,
                        'Tenant ID': vm.identity.tenant_id
                    })
            
            return pd.DataFrame(identity_data)
        except Exception as e:
            logger.error(f"Error analyzing managed identities: {str(e)}")
            return pd.DataFrame()

    def run_all_analyses(self) -> Dict[str, pd.DataFrame]:
        """Run all security analyses"""
        if not self._validate_subscription_id(self.subscription_id):
            raise ValueError("Invalid subscription ID format")
            
        analyses = {
            'Secure Score': self.analyze_secure_score(),
            'NSGs': self.analyze_nsgs(),
            'Storage Accounts': self.analyze_storage_accounts(),
            'Virtual Machines': self.analyze_vms(),
            'SQL Databases': self.analyze_sql_databases(),
            'Key Vaults': self.analyze_key_vaults(),
            'Resource Locks': self.analyze_resource_locks(),
            'Network Security': self.analyze_network_security(),
            'Storage Security': self.analyze_storage_security(),
            'Azure AD Security': self.analyze_azure_ad_security(),
            'Role Assignments': self.analyze_role_assignments(),
            'Security Center': self.analyze_network_security_center(),
            'Firewall Rules': self.analyze_firewall_rules(),
            'Policy Compliance': self.analyze_policy_compliance(),
            'Policy Assignments': self.analyze_policy_assignments(),
            'Policy Definitions': self.analyze_policy_definitions(),
            'Service Principals': self.analyze_service_principals(),
            'Managed Identities': self.analyze_managed_identities()
        }
        return analyses 