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
        
        if result["errors"]:
            print("\n=== Errors ===")
            for error in result["errors"]:
                print(f"- {error}")
            return 1
        
        print("\n=== Execution Summary ===")
        for i, task in enumerate(result["tasks"]):
            print(f"\nTask {i+1}: {task['tool']}")
            print(f"Status: {task['status']}")
            if task['result']:
                print("Output:")
                print(task['result']['output'])
        
    except Exception as e:
        print(f"\nError: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())