from scanner import SecurityScanner

def main():
    try:
        scanner = SecurityScanner()
        
        print("AI-Powered Security Scanner")
        print("=" * 50)
        
        instruction = input("Enter security testing instruction (e.g., 'Scan for open ports and discover directories'): ").strip()
        target = input("Enter target domain/IP: ").strip()
        
        print("\nExecuting security workflow...")
        result = scanner.run_security_scan(instruction, target)
        
        # Show execution summary
        print("\n=== Execution Summary ===")
        for i, task in enumerate(result["tasks"], 1):
            print(f"\nTask {i}: {task['tool'].upper()}")
            print(f"Status: {task['status'].upper()}")
            if task.get('command'):
                print(f"Command: {task['command']}")
            if task.get('error'):
                print(f"Error: {task['error']}")
            if task.get('result', {}).get('output'):
                print("\nOutput:")
                print("-" * 50)
                print(task['result']['output'].strip())
                print("-" * 50)
        
        # Show analysis results
        if result.get("analysis"):
            print("\n=== Security Analysis ===")
            
            print("\nFindings:")
            for finding in result["analysis"]["findings"]:
                severity_color = {
                    "high": "\033[91m",    # Red
                    "medium": "\033[93m",   # Yellow
                    "low": "\033[92m",      # Green
                    "unknown": "\033[0m"    # Default
                }.get(finding["severity"].lower(), "\033[0m")
                
                print(f"\n{severity_color}[{finding['severity'].upper()}] {finding['type']}\033[0m")
                print(f"Description: {finding['description']}")
            
            if result["analysis"].get("recommendations"):
                print("\nRecommendations:")
                for rec in result["analysis"]["recommendations"]:
                    print(f"→ {rec}")
            
            risk = result["analysis"]["risk_assessment"]
            risk_color = {
                "high": "\033[91m",
                "medium": "\033[93m",
                "low": "\033[92m",
                "unknown": "\033[0m"
            }.get(risk.lower(), "\033[0m")
            
            print(f"\nRisk Assessment: {risk_color}{risk.upper()}\033[0m")
            
        return 0 if not result["errors"] else 1
        
    except Exception as e:
        print(f"\nCritical Error: {str(e)}")
        return 1

if __name__ == "__main__":
    exit(main())