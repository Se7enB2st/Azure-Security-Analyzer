import os
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from typing import Optional
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _load_env_vars() -> None:
    """Load environment variables from .env file"""
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)
    else:
        logger.warning(".env file not found. Using system environment variables.")

def _validate_env_vars() -> None:
    """Validate required environment variables"""
    required_vars = ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_SUBSCRIPTION_ID']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

def get_credentials() -> DefaultAzureCredential:
    """Get Azure credentials using DefaultAzureCredential with fallback to ClientSecretCredential"""
    try:
        # First try DefaultAzureCredential which supports multiple authentication methods
        return DefaultAzureCredential()
    except Exception as e:
        logger.warning(f"DefaultAzureCredential failed: {str(e)}. Falling back to ClientSecretCredential.")
        try:
            # Fallback to ClientSecretCredential if DefaultAzureCredential fails
            return ClientSecretCredential(
                tenant_id=os.getenv('AZURE_TENANT_ID'),
                client_id=os.getenv('AZURE_CLIENT_ID'),
                client_secret=os.getenv('AZURE_CLIENT_SECRET')
            )
        except Exception as e:
            logger.error(f"Failed to get Azure credentials: {str(e)}")
            raise

def get_subscription_id() -> str:
    """Get Azure subscription ID with validation"""
    subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
    if not subscription_id:
        raise ValueError("AZURE_SUBSCRIPTION_ID environment variable is not set")
    return subscription_id

# Initialize environment variables
_load_env_vars()
try:
    _validate_env_vars()
except ValueError as e:
    logger.error(str(e))
    raise 