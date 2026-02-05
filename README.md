# Fort (Fortress) - AI-Native Secure Code Execution

Fort is an AI-native secure code execution sandbox that combines LLM-powered code analysis with Docker container isolation. It provides a 5-phase pipeline for safely executing untrusted code.

## Features

- **AI-Powered Analysis**: Uses LLMs to understand code intent, detect languages, and identify security risks
- **40+ Security Patterns**: Static analysis for command injection, reverse shells, crypto mining, and more
- **Docker Isolation**: Runs code in minimal containers with resource limits, network isolation, and read-only filesystems
- **Defense in Depth**: Multiple validation layers - static analysis, LLM review, policy enforcement, sandbox isolation

## Installation

```bash
go install github.com/AbelJSeba/sandbox/cmd/fort@latest
```

Or build from source:

```bash
git clone https://github.com/AbelJSeba/sandbox.git
cd sandbox
go build -o fort ./cmd/fort
```

## Requirements

- Go 1.22+
- Docker (for container execution)
- OpenAI API key (for LLM-powered analysis)

## Quick Start

Set your OpenAI API key:

```bash
export OPENAI_API_KEY=your-key-here
```

Execute Python code:

```bash
fort -code 'print("Hello, World!")'
```

Analyze code without executing:

```bash
fort -mode analyze -file script.py
```

Quick security validation (static only, no LLM):

```bash
fort -mode quick-validate -code 'import os; os.system("rm -rf /")'
```

## Usage

```
Usage of fort:
  -mode string
        Mode: execute, analyze, validate, quick-validate (default "execute")
  -file string
        Path to code file (or - for stdin)
  -code string
        Inline code to execute
  -lang string
        Language hint (python, go, js, etc.)
  -purpose string
        Description of what the code should do
  -timeout int
        Execution timeout in seconds (default 60)
  -memory int
        Memory limit in MB (default 256)
  -allow-network
        Allow network access
  -json
        Output results as JSON
  -no-validate
        Skip security validation (DANGEROUS)
  -verbose
        Verbose output
  -model string
        LLM model to use (default "gpt-4")
  -banner
        Show banner (default true)
```

## Pipeline Phases

1. **Analysis**: Detect language, runtime, dependencies, and potential risks
2. **Synthesis**: Generate secure Dockerfile and execution configuration
3. **Validation**: Multi-layer security validation (static + LLM)
4. **Build**: Create minimal container image
5. **Execution**: Run code in isolated container

## Security Features

### Container Isolation
- Non-root user execution
- Read-only root filesystem
- Network disabled by default
- Resource limits (memory, CPU, PIDs)
- Capability dropping
- gVisor support (optional)

### Code Validation
- Command injection detection
- Reverse shell pattern detection
- Crypto mining indicator detection
- File system access control
- Network access control
- Obfuscation detection

## Library Usage

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/AbelJSeba/sandbox/pkg/fort"
)

func main() {
    config := fort.DefaultAgentConfig()
    config.LLMAPIKey = "your-openai-key"

    agent, err := fort.NewAgent(config)
    if err != nil {
        panic(err)
    }
    defer agent.Close()

    req := &fort.Request{
        ID:            "exec-1",
        CreatedAt:     time.Now(),
        SourceType:    fort.SourceInline,
        SourceContent: `print("Hello from Fort!")`,
        Language:      "python",
    }

    execution, err := agent.Execute(context.Background(), req)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Success: %v\n", execution.Result.Success)
    fmt.Printf("Output: %s\n", execution.Result.Stdout)
}
```

## Quick Validation (No LLM)

For fast security checks without LLM calls:

```go
safe, findings := fort.QuickValidate(code, nil)
if !safe {
    for _, f := range findings {
        fmt.Printf("[%s] %s\n", f.Severity, f.Description)
    }
}
```

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or PR.
