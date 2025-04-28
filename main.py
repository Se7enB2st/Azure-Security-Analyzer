from azure_security_analyzer import AzureSecurityAnalyzer
import os
import logging
import sys
from typing import Dict, Any
import json
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def save_results_to_file(results: Dict[str, Any], filename: str = None) -> None:
    """Save analysis results to a JSON file"""
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'security_analysis_{timestamp}.json'
    
    try:
        # Convert DataFrames to dictionaries
        serializable_results = {}
        for key, df in results.items():
            serializable_results[key] = df.to_dict(orient='records')
        
        with open(filename, 'w') as f:
            json.dump(serializable_results, f, indent=4)
        logger.info(f"Results saved to {filename}")
    except Exception as e:
        logger.error(f"Failed to save results: {str(e)}")

def main():
    try:
        # Load environment variables
        logger.info("Starting Azure Security Analysis")
        
        # Initialize the analyzer
        analyzer = AzureSecurityAnalyzer()
        logger.info("Azure Security Analyzer initialized successfully")
        
        # Run all analyses
        logger.info("Running security analyses...")
        results = analyzer.run_all_analyses()
        
        # Print results
        print("\n=== Azure Security Analysis Results ===\n")
        
        for analysis_name, df in results.items():
            print(f"\n{analysis_name}:")
            if not df.empty:
                print(df.to_string())
            else:
                print("No data available or error occurred during analysis")
        
        # Save results to file
        save_results_to_file(results)
        
        logger.info("Security analysis completed successfully")
        
    except Exception as e:
        logger.error(f"Error during security analysis: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 