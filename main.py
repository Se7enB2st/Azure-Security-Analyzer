from azure_security_analyzer import AzureSecurityAnalyzer
import os
from dotenv import load_dotenv

def main():
    # Load environment variables
    load_dotenv()
    
    # Initialize the analyzer
    analyzer = AzureSecurityAnalyzer()
    
    # Run all analyses
    results = analyzer.run_all_analyses()
    
    # Print results
    print("\n=== Azure Security Analysis Results ===\n")
    
    for analysis_name, df in results.items():
        print(f"\n{analysis_name}:")
        if not df.empty:
            print(df.to_string())
        else:
            print("No data available or error occurred during analysis")

if __name__ == "__main__":
    main() 