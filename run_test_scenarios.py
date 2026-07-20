import os
import glob
from security_vulnerability import SecurityVulnerabilityAgent

def main():
    agent = SecurityVulnerabilityAgent()
    
    # Get all .py files in test_scenarios directory
    test_files = glob.glob("test_scenarios/*.py")
    
    for test_file in test_files:
        print("=" * 70)
        print(f"ANALYZING: {test_file}")
        print("=" * 70)
        
        with open(test_file, 'r', encoding='utf-8') as f:
            source_code = f.read()
            
        findings = agent.analyze(source_code, language="python", filename=os.path.basename(test_file))
        
        if not findings:
            print("No vulnerabilities found.")
        else:
            for f in findings:
                print(f"[{f.severity.value.upper()}] {f.type.value} (Line {f.line_number})")
                print(f"Details: {f.description}")
                print("-" * 70)
                
if __name__ == "__main__":
    main()
