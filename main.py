import subprocess
import os
import shlex
import re
from typing import Optional, Dict, Any, List, Union
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

class TaskInfo(TypedDict):
    tool: str  # nmap, gobuster, etc.
    params: Dict[str, Any]
    status: str  # pending, running, completed, failed
    result: Optional[Dict[str, Any]]
    retries: int

class ScanState(TypedDict):
    instruction: str  # High-level security instruction
    target: str  # Main target domain/IP
    tasks: List[TaskInfo]  # Ordered list of tasks
    current_task_index: int
    discovered_targets: List[str]  # Additional targets discovered during scanning
    errors: List[str]
    current_node: str
    analysis: Optional[Dict[str, Any]]

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
        
        self.workflow = self._create_workflow()
        self._setup_components()

    def _setup_components(self):
        """Setup task planning and analysis components"""
        self.task_planner_prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a security testing planner. Break down security tasks into specific steps."),
            ("user", """
            Create a detailed plan for this security testing instruction:
            Instruction: {instruction}
            Target: {target}
            
            Break it down into specific tasks in JSON format:
            {{
                "tasks": [
                    {{
                        "tool": "tool_name",
                        "params": {{"param1": "value1"}},
                        "description": "task description"
                    }}
                ]
            }}
            
            Available tools: nmap, gobuster
            """)
        ])

        self.task_planner_chain = self.task_planner_prompt | self.llm | JsonOutputParser()

    def _create_workflow(self) -> StateGraph:
        """Create the security testing workflow"""
        workflow = StateGraph(ScanState)

        # Add nodes for each stage
        workflow.add_node("plan", self._plan_tasks)
        workflow.add_node("execute", self._execute_current_task)
        workflow.add_node("analyze", self._analyze_results)
        workflow.add_node("update", self._update_task_list)

        # Define routing logic
        def route_after_plan(state: ScanState) -> str:
            return "execute" if state["tasks"] else END

        def route_after_execute(state: ScanState) -> str:
            if state["errors"]:
                return END
            return "analyze"

        def route_after_analyze(state: ScanState) -> str:
            return "update"

        def route_after_update(state: ScanState) -> str:
            if state["current_task_index"] < len(state["tasks"]) - 1:
                state["current_task_index"] += 1
                return "execute"
            return END

        # Add conditional edges
        workflow.add_conditional_edges(
            "plan",
            route_after_plan,
            {
                "execute": "execute",
                END: END
            }
        )
        workflow.add_conditional_edges(
            "execute",
            route_after_execute,
            {
                "analyze": "analyze",
                END: END
            }
        )
        workflow.add_conditional_edges(
            "analyze",
            route_after_analyze,
            {
                "update": "update"
            }
        )
        workflow.add_conditional_edges(
            "update",
            route_after_update,
            {
                "execute": "execute",
                END: END
            }
        )

        workflow.set_entry_point("plan")
        return workflow.compile()

    def _plan_tasks(self, state: ScanState) -> ScanState:
        """Plan tasks based on high-level instruction"""
        try:
            plan = self.task_planner_chain.invoke({
                "instruction": state["instruction"],
                "target": state["target"]
            })
            
            state["tasks"] = [
                TaskInfo(
                    tool=task["tool"],
                    params=task["params"],
                    status="pending",
                    result=None,
                    retries=0
                ) for task in plan["tasks"]
            ]
            
        except Exception as e:
            state["errors"].append(f"Task planning error: {str(e)}")
            
        return state

    def _execute_current_task(self, state: ScanState) -> ScanState:
        """Execute the current task"""
        current_task = state["tasks"][state["current_task_index"]]
        current_task["status"] = "running"

        try:
            if current_task["tool"] == "nmap":
                result = self._run_nmap(current_task["params"])
            elif current_task["tool"] == "gobuster":
                result = self._run_gobuster(current_task["params"])
            else:
                raise ValueError(f"Unknown tool: {current_task['tool']}")

            current_task["result"] = result
            current_task["status"] = "completed"

        except Exception as e:
            current_task["status"] = "failed"
            if current_task["retries"] < 3:
                current_task["retries"] += 1
                current_task["status"] = "pending"
            else:
                state["errors"].append(f"Task execution failed: {str(e)}")

        return state

    def _run_nmap(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute nmap scan"""
        command = f"nmap {params.get('flags', '-sV')} {params['target']}"
        process = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=300
        )
        return {
            "output": process.stdout,
            "error": process.stderr if process.returncode != 0 else None
        }

    def _run_gobuster(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute gobuster scan"""
        command = f"gobuster dir -u {params['target']} -w {params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')}"
        process = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=300
        )
        return {
            "output": process.stdout,
            "error": process.stderr if process.returncode != 0 else None
        }

    def _analyze_results(self, state: ScanState) -> ScanState:
        """Analyze the results of the current task and identify new targets"""
        current_task = state["tasks"][state["current_task_index"]]
        
        # Only analyze if the task completed successfully.
        if current_task["status"] != "completed":
            return state
            
        try:
            # Create analysis prompt with escaped JSON structure
            analysis_prompt = ChatPromptTemplate.from_messages([
                ("system", "You are a security expert analyzing scan results."),
                ("user", """
                Analyze these {tool} scan results and provide insights in JSON format:
                Tool: {tool}
                Target: {target}
                Output: {output}
                
                Provide analysis in JSON format:
                {{
                    "findings": [
                        {{
                            "type": "finding_type",
                            "description": "description",
                            "severity": "low|medium|high"
                        }}
                    ],
                    "new_targets": [],
                    "recommendations": []
                }}
                """)
            ])
            
            # Create analysis chain
            analysis_chain = analysis_prompt | self.llm | JsonOutputParser()
            
            # Run analysis
            analysis = analysis_chain.invoke({
                "tool": current_task["tool"],
                "target": state["target"],
                "output": current_task["result"]["output"]
            })
            
            # Update state with analysis
            current_task["analysis"] = analysis
            
            # Add any new discovered targets
            if "new_targets" in analysis:
                state["discovered_targets"].extend([
                    target for target in analysis["new_targets"]
                    if target not in state["discovered_targets"]
                ])
                
        except Exception as e:
            state["errors"].append(f"Analysis error: {str(e)}")
            
        return state

    def _update_task_list(self, state: ScanState) -> ScanState:
        """Update task list based on analysis results"""
        current_task = state["tasks"][state["current_task_index"]]
        
        if not current_task.get("analysis"):
            return state
            
        try:
            # For each discovered target in the current analysis,
            # add a new task only if not already scheduled.
            new_targets = current_task["analysis"].get("new_targets", [])
            for target in new_targets:
                # Skip if the target is the original one.
                if target.lower() == state["target"].lower():
                    continue
                
                # Check if a task for this target already exists.
                already_scheduled = any(
                    task["params"].get("target", "").lower() == target.lower()
                    for task in state["tasks"]
                )
                if already_scheduled:
                    continue

                # Add new task based on the tool used in the current task.
                if current_task["tool"] == "nmap":
                    state["tasks"].append({
                        "tool": "nmap",
                        "params": {"target": target, "flags": "-sV"},
                        "status": "pending",
                        "result": None,
                        "retries": 0
                    })
                elif current_task["tool"] == "gobuster":
                    state["tasks"].append({
                        "tool": "gobuster",
                        "params": {"target": target},
                        "status": "pending",
                        "result": None,
                        "retries": 0
                    })
                    
        except Exception as e:
            state["errors"].append(f"Task update error: {str(e)}")
            
        return state

    def run_security_scan(self, instruction: str, target: str) -> Dict[str, Any]:
        """Run the complete security scanning workflow"""
        initial_state = ScanState(
            instruction=instruction,
            target=target,
            tasks=[],
            current_task_index=0,
            discovered_targets=[target],
            errors=[],
            current_node="plan",
            analysis=None
        )
        
        final_state = self.workflow.invoke(initial_state)
        return final_state

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