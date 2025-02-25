import subprocess
from typing import Dict, Any

def run_command(command: str) -> Dict[str, Any]:
    """Execute a shell command and return the output"""
    try:
        # Run command with timeout
        process = subprocess.Popen(
            command.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
        
        # Combine stdout and stderr if there's an error
        output = stdout
        if process.returncode != 0:
            output = f"{stdout}\nError: {stderr}"
        
        # Return empty output if nothing was captured
        if not output.strip():
            output = "No output generated"
            
        return {
            "output": output,
            "returncode": process.returncode,
            "command": command
        }
        
    except subprocess.TimeoutExpired:
        return {
            "output": "Command timed out after 300 seconds",
            "returncode": -1,
            "error": "timeout",
            "command": command
        }
    except Exception as e:
        return {
            "output": f"Command failed: {str(e)}",
            "returncode": -1,
            "error": str(e),
            "command": command
        }