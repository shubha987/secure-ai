# Secure-AI

An AI-powered security scanning tool that helps break down cybersecurity tasks and automates security scanning for target systems.

## Overview

Secure-AI leverages large language models to plan, execute, and analyze security tests against target systems. It provides an intelligent workflow that breaks down high-level security instructions into specific executable tasks, runs appropriate security tools, and delivers meaningful security analysis.

## Features

- **AI-Powered Security Planning**: Automatically plans security tasks based on high-level instructions
- **Automated Scanning**: Executes security tools like nmap and gobuster
- **Intelligent Analysis**: Analyzes scan results and provides actionable recommendations
- **Flexible Workflow**: Modular design allows for easy extension with additional security tools

## Getting Started

### Prerequisites
- Python 3.11
- Git
- nmap
- gobuster
- dirb wordlists

### Installation

1. ** `Fork` the repository https://github.com/shubha987/secure-ai.git

2. **Clone the repository**
```sh
    git clone https://github.com/yourusername/secure-ai.git
    cd secure-ai
```

3. **Create a virtual environment**
```sh
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

4. **Install the required packages**
```sh
    pip install -r requirements.txt
```

5. **Set up environment variables**
    Create a [.env](http://_vscodecontentref_/0) file in the project root and add your API key:
```sh
    GROQ_API_KEY=your_groq_api_key
```

## Usage

Run a security scan using the CLI:
```sh
    cd src
    python main.py"
```
The tool will:

1. Plan specific security tasks to execute
2. Run appropriate security tools (nmap, gobuster)
3. Analyze the results
4. Provide security findings and recommendations

## Architecture
For detailed information about the system architecture and workflow, see [Architecture.md](Architecture.md).

Contributing
Contributions are welcome! See [Contributing.md](contributing.md) for guidelines.

License
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

Contact
Shubha Ruidas -  shubharuidas123@gmail.com

