import subprocess
import os
import shlex
import re
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langgraph.graph import StateGraph, END
from typing import TypedDict, Annotated
import json
from dotenv import load_dotenv

load_dotenv()

# Define state types
class ScanState(TypedDict):
    command: str
    scan_result: Optional[Dict[str, Any]]
    analysis: Optional[Dict[str, Any]]
    errors: List[str]
    current_node: str

@dataclass
class ScanResult:
    timestamp: str
    command: str
    output: str
    analysis: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class SecurityScanner:
    def __init__(self):
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            raise ValueError("Groq API key not found in environment variables")
        
        self.llm = ChatGroq(
            api_key=api_key,
            model_name="llama-3.3-70b-versatile",
            temperature=0.2
        )
        
        # Initialize workflow graph
        self.workflow = self._create_workflow()
        
        # Initialize other components
        self._setup_components()

    def _setup_components(self):
        """Setup LangChain components"""
        self.parser = JsonOutputParser(pydantic_object={
            "type": "object",
            "properties": {
                "open_ports": {"type": "array"},
                "vulnerabilities": {"type": "array"},
                "recommendations": {"type": "array"},
                "risk_level": {"type": "string"},
                "summary": {"type": "string"}
            }
        })
        
        self.analysis_prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a cybersecurity expert analyzing Nmap scan results."),
            ("user", """
            Analyze this Nmap scan:
            Command: {command}
            Timestamp: {timestamp}
            Output: {output}
            
            Provide a security analysis in JSON format with:
            - open_ports: Array of detected open ports
            - vulnerabilities: Array of potential vulnerabilities
            - recommendations: Array of security recommendations
            - risk_level: Overall risk assessment (Low/Medium/High)
            - summary: Brief analysis summary
            """)
        ])
        
        self.analysis_chain = self.analysis_prompt | self.llm | self.parser

    def _create_workflow(self) -> StateGraph:
        """Create the workflow graph"""
        workflow = StateGraph(ScanState)

        # Add nodes
        workflow.add_node("validate", self.validate_nmap_command)
        workflow.add_node("scan", self.run_nmap_command)
        workflow.add_node("analyze", self.analyze_scan)

        # Define edge conditions as separate functions
        def route_after_validate(state: ScanState) -> str:
            if state["errors"]:
                return END
            return "scan"

        def route_after_scan(state: ScanState) -> str:
            if state["errors"] or not state["scan_result"]:
                return END
            return "analyze"

        def route_after_analyze(state: ScanState) -> str:
            return END

        # Add edges with routing functions
        workflow.add_conditional_edges(
            "validate",
            route_after_validate,
            {
                "scan": "scan",
                END: END
            }
        )
        workflow.add_conditional_edges(
            "scan",
            route_after_scan,
            {
                "analyze": "analyze",
                END: END
            }
        )
        workflow.add_conditional_edges(
            "analyze",
            route_after_analyze,
            {
                END: END
            }
        )

        # Set entry point
        workflow.set_entry_point("validate")

        return workflow.compile()

    def handle_error(self, state: ScanState, error: Exception) -> ScanState:
        """Handle errors in the workflow"""
        state["errors"].append(str(error))
        return state

    def validate_nmap_command(self, state: ScanState) -> ScanState:
        """Validate the Nmap command"""
        state["current_node"] = "validate"
        try:
            allowed_patterns = [
                r'^nmap\s+(-[A-Za-z]+\s+)*[\w\.-]+$',
                r'^nmap\s+-p\s*\d+(?:,\d+)*\s+[\w\.-]+$'
            ]
            if not any(re.match(pattern, state["command"]) for pattern in allowed_patterns):
                state["errors"].append("Invalid or potentially unsafe nmap command")
        except Exception as e:
            state["errors"].append(f"Validation error: {str(e)}")
        return state

    def run_nmap_command(self, state: ScanState) -> ScanState:
        """Execute the Nmap command"""
        state["current_node"] = "scan"
        try:
            args = shlex.split(state["command"])
            process = subprocess.run(
                args,
                capture_output=True,
                text=True,
                shell=False,
                timeout=300
            )
            
            state["scan_result"] = {
                "timestamp": datetime.now().isoformat(),
                "command": state["command"],
                "output": process.stdout,
                "error": process.stderr if process.returncode != 0 else None
            }
            
            if process.returncode != 0:
                state["errors"].append(f"Nmap command failed: {process.stderr}")
                
        except Exception as e:
            state["errors"].append(f"Scan error: {str(e)}")
            
        return state

    def analyze_scan(self, state: ScanState) -> ScanState:
        """Analyze the scan results"""
        state["current_node"] = "analyze"
        try:
            if state["scan_result"] and not state["errors"]:
                analysis = self.analysis_chain.invoke({
                    "command": state["scan_result"]["command"],
                    "timestamp": state["scan_result"]["timestamp"],
                    "output": state["scan_result"]["output"]
                })
                state["analysis"] = analysis
                
        except Exception as e:
            state["errors"].append(f"Analysis error: {str(e)}")
            
        return state

    def run_scan(self, command: str) -> Dict[str, Any]:
        """Run the complete scanning workflow"""
        initial_state = ScanState(
            command=command,
            scan_result=None,
            analysis=None,
            errors=[],
            current_node="validate"
        )
        
        final_state = self.workflow.invoke(initial_state)
        return final_state

def main():
    try:
        scanner = SecurityScanner()
        
        print("Network Security Scanner (LangChain + LangGraph + Groq)")
        print("=" * 50)
        
        command = input("Enter Nmap command (e.g., 'nmap -sV google.com'): ").strip()
        
        print("\nExecuting security workflow...")
        result = scanner.run_scan(command)
        
        if result["errors"]:
            print("\n=== Errors ===")
            for error in result["errors"]:
                print(f"- {error}")
            return 1
        
        print("\n=== Scan Details ===")
        print(f"Timestamp: {result['scan_result']['timestamp']}")
        print(f"Command: {result['scan_result']['command']}")
        
        print("\n=== Scan Output ===")
        print(result['scan_result']['output'])
        
        print("\n=== AI Analysis ===")
        print(json.dumps(result['analysis'], indent=2))
        
    except Exception as e:
        print(f"\nError: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())