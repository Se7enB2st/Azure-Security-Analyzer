from azure_security_analyzer import AzureSecurityAnalyzer
import os
import logging
import sys
from typing import Dict, Any
import json
from datetime import datetime
import re
import pandas as pd
from tqdm import tqdm

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

def _contains_sensitive_data(text: str) -> bool:
    """Check if text contains potentially sensitive data"""
    sensitive_patterns = [
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone numbers
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
        r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',  # SSN-like patterns
        r'\b[A-Za-z0-9]{32,}\b',  # Long strings that might be hashes or keys
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, text):
            return True
    return False

def _sanitize_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize results by removing or masking sensitive data"""
    sanitized = {}
    for key, df in results.items():
        if df.empty:
            sanitized[key] = df
            continue
            
        # Convert DataFrame to dictionary for processing
        data = df.to_dict(orient='records')
        sanitized_data = []
        
        for record in data:
            sanitized_record = {}
            for k, v in record.items():
                if isinstance(v, str) and _contains_sensitive_data(v):
                    sanitized_record[k] = '[REDACTED]'
                else:
                    sanitized_record[k] = v
            sanitized_data.append(sanitized_record)
            
        sanitized[key] = pd.DataFrame(sanitized_data)
    
    return sanitized

def generate_summary(results: Dict[str, pd.DataFrame]) -> Dict[str, Any]:
    """Generate a summary of the analysis results"""
    summary = {}
    for analysis_name, df in results.items():
        if df.empty:
            summary[analysis_name] = {
                'status': 'Failed',
                'items_analyzed': 0
            }
            continue
            
        summary[analysis_name] = {
            'status': 'Success',
            'items_analyzed': len(df),
            'key_metrics': {}
        }
        
        # Add specific metrics based on analysis type
        if analysis_name == 'Secure Score':
            if 'Percentage' in df.columns:
                summary[analysis_name]['key_metrics']['average_score'] = df['Percentage'].mean()
        elif analysis_name == 'Network Security Groups':
            if 'Rules Count' in df.columns:
                summary[analysis_name]['key_metrics']['average_rules'] = df['Rules Count'].mean()
        elif analysis_name == 'Storage Accounts':
            if 'Https Only' in df.columns:
                summary[analysis_name]['key_metrics']['https_enabled'] = df['Https Only'].sum()
            if 'Blob Public Access' in df.columns:
                summary[analysis_name]['key_metrics']['public_access'] = df['Blob Public Access'].sum()
        elif analysis_name == 'Virtual Machines':
            if 'Encryption Status' in df.columns:
                summary[analysis_name]['key_metrics']['encrypted'] = df['Encryption Status'].value_counts().to_dict()
        elif analysis_name == 'SQL Databases':
            if 'TDE Status' in df.columns:
                summary[analysis_name]['key_metrics']['tde_enabled'] = df['TDE Status'].value_counts().to_dict()
    
    return summary

def save_results_to_file(results: Dict[str, Any], summary: Dict[str, Any], filename: str = None) -> None:
    """Save analysis results and summary to a JSON file"""
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'security_analysis_{timestamp}.json'
    
    try:
        # Sanitize results before saving
        sanitized_results = _sanitize_results(results)
        
        # Convert DataFrames to dictionaries
        serializable_results = {}
        for key, df in sanitized_results.items():
            serializable_results[key] = df.to_dict(orient='records')
        
        # Combine results and summary
        output = {
            'timestamp': datetime.now().isoformat(),
            'summary': summary,
            'detailed_results': serializable_results
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=4)
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
        
        # Run all analyses with progress bar
        logger.info("Running security analyses...")
        analyses = [
            'Secure Score',
            'Network Security Groups',
            'Storage Accounts',
            'Virtual Machines',
            'SQL Databases'
        ]
        
        results = {}
        with tqdm(total=len(analyses), desc="Analyzing", unit="analysis") as pbar:
            for analysis in analyses:
                try:
                    if analysis == 'Secure Score':
                        results[analysis] = analyzer.analyze_secure_score()
                    elif analysis == 'Network Security Groups':
                        results[analysis] = analyzer.analyze_nsgs()
                    elif analysis == 'Storage Accounts':
                        results[analysis] = analyzer.analyze_storage_accounts()
                    elif analysis == 'Virtual Machines':
                        results[analysis] = analyzer.analyze_vms()
                    elif analysis == 'SQL Databases':
                        results[analysis] = analyzer.analyze_sql_databases()
                except Exception as e:
                    logger.error(f"Error in {analysis}: {str(e)}")
                    results[analysis] = pd.DataFrame()
                pbar.update(1)
        
        # Generate and display summary
        summary = generate_summary(results)
        print("\n=== Analysis Summary ===")
        for analysis, stats in summary.items():
            print(f"\n{analysis}:")
            print(f"  Status: {stats['status']}")
            print(f"  Items Analyzed: {stats['items_analyzed']}")
            if 'key_metrics' in stats:
                print("  Key Metrics:")
                for metric, value in stats['key_metrics'].items():
                    print(f"    {metric}: {value}")
        
        # Save results to file
        save_results_to_file(results, summary)
        
        logger.info("Security analysis completed successfully")
        
    except Exception as e:
        logger.error(f"Error during security analysis: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 