import os
from typing import Dict, Any
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langgraph.graph import StateGraph, END
from dotenv import load_dotenv
from tasks import ScanState, TaskInfo
from utils import run_command

load_dotenv()

class SecurityScanner:
    def __init__(self):
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            raise ValueError("Groq API key not found in environment variables")
        
        self.llm = ChatGroq(
            api_key=api_key,
            model_name="deepseek-r1-distill-llama-70b",
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
                        "params": {{"target": "{target}"}},
                        "description": "task description"
                    }}
                ]
            }}
            
            Available tools: nmap, gobuster
            """)
        ])

        self.task_planner_chain = self.task_planner_prompt | self.llm | JsonOutputParser()

    def _create_workflow(self) -> StateGraph:
        """Create a three-step security testing workflow"""
        workflow = StateGraph(ScanState)

        # Add three core nodes
        workflow.add_node("plan", self._plan_tasks)
        workflow.add_node("execute", self._execute_current_task)
        workflow.add_node("analyze", self._analyze_results)

        # Simple three-step routing
        def route_after_plan(state: ScanState) -> str:
            return "execute" if state.get("tasks") else END

        def route_after_execute(state: ScanState) -> str:
            if state.get("errors"):
                return END
            if state["current_task_index"] >= len(state["tasks"]):
                return "analyze"
            return "execute"

        def route_after_analyze(state: ScanState) -> str:
            return END

        # Add edges for three-step flow
        workflow.add_conditional_edges("plan", route_after_plan, {"execute": "execute", END: END})
        workflow.add_conditional_edges("execute", route_after_execute, {"execute": "execute", "analyze": "analyze", END: END})
        workflow.add_conditional_edges("analyze", route_after_analyze, {END: END})

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
            # Execute the task
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
            state["errors"].append(f"Task execution failed: {str(e)}")
        
        # Move to next task
        state["current_task_index"] += 1
        return state

    def _analyze_results(self, state: ScanState) -> ScanState:
        """Analyze all completed tasks results"""
        try:
            analysis_prompt = ChatPromptTemplate.from_messages([
                ("system", "You are a security expert. Analyze these scan results:"),
                ("user", """Analyze the following security scan results:
{scan_results}

Provide a security analysis in JSON format with the following structure:
{{
    "findings": [
        {{
            "type": "finding_type",
            "description": "detailed description",
            "severity": "high/medium/low"
        }}
    ],
    "recommendations": [
        "detailed recommendation 1",
        "detailed recommendation 2"
    ],
    "risk_assessment": "high/medium/low"
}}""")
            ])

            # Prepare scan results summary
            scan_results = []
            for task in state["tasks"]:
                if task["status"] == "completed" and task.get("result"):
                    scan_results.append(
                        f"Tool: {task['tool']}\n"
                        f"Target: {task['params'].get('target', 'unknown')}\n"
                        f"Output:\n{task['result'].get('output', '')}\n"
                    )

            # Run analysis through LLM
            analysis_chain = analysis_prompt | self.llm | JsonOutputParser()
            analysis = analysis_chain.invoke({
                "scan_results": "\n".join(scan_results)
            })
            
            # Store analysis in state
            state["analysis"] = analysis

        except Exception as e:
            state["errors"].append(f"Analysis error: {str(e)}")

        return state

    def _run_nmap(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute nmap scan"""
        command = f"nmap {params.get('flags', '-sV')} {params['target']}"
        return run_command(command)

    def _run_gobuster(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute gobuster scan"""
        command = f"gobuster dir -u {params['target']} -w {params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')}"
        return run_command(command)

    def run_security_scan(self, instruction: str, target: str) -> Dict[str, Any]:
        """Run the security scanning workflow"""
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
        
        try:
            final_state = self.workflow.invoke(initial_state)
            return final_state
        except Exception as e:
            return ScanState(
                instruction=instruction,
                target=target,
                tasks=[],
                current_task_index=0,
                discovered_targets=[target],
                errors=[f"Workflow error: {str(e)}"],
                current_node="error",
                analysis=None
            )