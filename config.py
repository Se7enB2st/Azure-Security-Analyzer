import os
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from typing import Optional
import logging
from dotenv import load_dotenv
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Default configuration values
DEFAULT_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

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

def get_timeout() -> int:
    """Get API timeout in seconds"""
    return int(os.getenv('API_TIMEOUT', DEFAULT_TIMEOUT))

def get_max_retries() -> int:
    """Get maximum number of retries for API calls"""
    return int(os.getenv('MAX_RETRIES', MAX_RETRIES))

def get_retry_delay() -> int:
    """Get delay between retries in seconds"""
    return int(os.getenv('RETRY_DELAY', RETRY_DELAY))

def retry_with_backoff(func, *args, **kwargs):
    """Retry a function with exponential backoff"""
    max_retries = get_max_retries()
    retry_delay = get_retry_delay()
    
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            logger.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)
            retry_delay *= 2  # Exponential backoff

# Initialize environment variables
_load_env_vars()
try:
    _validate_env_vars()
except ValueError as e:
    logger.error(str(e))
    raise 