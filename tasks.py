from typing import TypedDict, Dict, Any, List, Optional

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