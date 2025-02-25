import subprocess
import shlex
from typing import Dict, Any

def run_command(command: str) -> Dict[str, Any]:
    """Run a shell command and return the output and error."""
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