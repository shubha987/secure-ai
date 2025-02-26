# Secure-AI Architecture

This document explains the architecture and workflow of the Secure-AI security scanner.

## System Overview

Secure-AI implements a three-phase security scanning workflow:
1. **Planning**: Breaking down security objectives into specific executable tasks
2. **Execution**: Running the planned security tools and commands
3. **Analysis**: Interpreting results and providing actionable recommendations

## Core Components

### SecurityScanner Class

The `SecurityScanner` class is the main entry point for the application, handling the overall scanning process.

### LangGraph Workflow

The system uses LangGraph's `StateGraph` to create a directed workflow that defines the scanning process. The workflow consists of:

- **States**: Represented by the `ScanState` class
- **Nodes**: Functions that transform the state
- **Edges**: Transitions between nodes based on conditional logic

### Data Model

The main state class `ScanState` maintains the state of the security scan, including:

- `instruction`: The high-level security objective
- `target`: The target system to scan
- `tasks`: List of specific security tasks to execute
- `current_task_index`: Index of the currently executing task
- `discovered_targets`: List of discovered targets during scanning
- `errors`: Errors encountered during scanning
- `current_node`: Current workflow position
- `analysis`: Final analysis results

Each task is represented by a `TaskInfo` structure containing:
- `tool`: The security tool to use (e.g., nmap, gobuster)
- `params`: Parameters for the tool
- `status`: Current status (pending, running, completed, failed)
- `result`: Output from the tool
- `retries`: Number of retry attempts

## Workflow Process

### 1. Planning Phase

The planning phase uses a large language model (Deepseek-r1-distill-llama-70b via Groq) to:
- Process the high-level security instruction
- Determine appropriate security tools to use
- Create a list of specific tasks with parameters

### 2. Execution Phase

For each planned task:
- Identifies the appropriate tool to run (nmap, gobuster)
- Constructs and executes the command
- Captures the output and updates task state
- Handles errors and retries as needed

### 3. Analysis Phase

When all tasks are complete:
- Aggregates results from all completed tasks
- Uses the LLM to analyze the security findings
- Generates security recommendations and risk assessment
- Formats the output in a structured format

## Component Interaction Diagram
```sh
User Request → SecurityScanner → LangGraph
 Workflow ↓ ┌────────┴────────┐ ↓ ↓ 
Plan Tasks → Execute Tasks → Analyze Results ↑ ↓ 
        └────┘ (repeat for each task)

```

## Supported Security Tools

Currently, Secure-AI supports:

1. **nmap**: For port scanning and service discovery
2. **gobuster**: For directory discovery and web enumeration

## Extension Points

The architecture is designed to be modular and extensible:

1. **Adding New Tools**: Implement new tool execution methods in the `SecurityScanner` class
2. **Enhancing Analysis**: Modify the analysis prompt to extract more detailed insights
3. **Custom Workflows**: Create more complex workflows by adding nodes and conditional edges