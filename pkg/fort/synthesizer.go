package fort

import (
	"context"
	"fmt"
	"strings"
)

// Synthesizer generates container configurations
type Synthesizer struct {
	llm LLMClient
}

// NewSynthesizer creates a new Synthesizer
func NewSynthesizer(llm LLMClient) *Synthesizer {
	return &Synthesizer{llm: llm}
}

// Synthesize generates container configuration from analysis
func (s *Synthesizer) Synthesize(ctx context.Context, req *Request, analysis *AnalysisResult) (*SynthesisResult, error) {
	// Try LLM synthesis first
	result, err := s.llm.Synthesize(ctx, req.SourceContent, analysis)
	if err != nil {
		// Fall back to template-based synthesis
		return s.templateSynthesize(analysis), nil
	}

	// Validate and enhance LLM result
	s.validateAndEnhance(result, analysis)

	return result, nil
}

// templateSynthesize generates configuration using templates
func (s *Synthesizer) templateSynthesize(analysis *AnalysisResult) *SynthesisResult {
	lang := strings.ToLower(analysis.DetectedLanguage)

	switch lang {
	case "python", "py":
		return s.pythonTemplate(analysis)
	case "javascript", "js", "node":
		return s.nodeTemplate(analysis)
	case "go", "golang":
		return s.goTemplate(analysis)
	case "rust":
		return s.rustTemplate(analysis)
	case "ruby", "rb":
		return s.rubyTemplate(analysis)
	case "shell", "bash", "sh":
		return s.shellTemplate(analysis)
	default:
		// Default to Python as it's most common
		return s.pythonTemplate(analysis)
	}
}

func (s *Synthesizer) pythonTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM python:3.11-slim-bookworm

# Security: Create non-root user
RUN groupadd -r executor && useradd -r -g executor executor

# Install minimal dependencies
RUN pip install --no-cache-dir --upgrade pip

WORKDIR /app

# Copy code
COPY main.py .

# Set ownership
RUN chown -R executor:executor /app

USER executor

CMD ["python", "main.py"]
`

	return &SynthesisResult{
		BaseImage:           "python:3.11-slim-bookworm",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"python", "main.py"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 256,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  60,
	}
}

func (s *Synthesizer) nodeTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM node:20-slim

# Security: Create non-root user
RUN groupadd -r executor && useradd -r -g executor executor

WORKDIR /app

# Copy code
COPY index.js .

# Set ownership
RUN chown -R executor:executor /app

USER executor

CMD ["node", "index.js"]
`

	return &SynthesisResult{
		BaseImage:           "node:20-slim",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"node", "index.js"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 256,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  60,
	}
}

func (s *Synthesizer) goTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY main.go .
RUN CGO_ENABLED=0 go build -o app main.go

FROM alpine:3.19

# Security: Create non-root user
RUN addgroup -S executor && adduser -S executor -G executor

WORKDIR /app
COPY --from=builder /build/app .

RUN chown -R executor:executor /app

USER executor

CMD ["./app"]
`

	return &SynthesisResult{
		BaseImage:           "golang:1.22-alpine",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"./app"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 128,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  60,
	}
}

func (s *Synthesizer) rustTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM rust:1.75-slim AS builder

WORKDIR /build
COPY main.rs .
RUN rustc -o app main.rs

FROM debian:bookworm-slim

RUN groupadd -r executor && useradd -r -g executor executor

WORKDIR /app
COPY --from=builder /build/app .

RUN chown -R executor:executor /app

USER executor

CMD ["./app"]
`

	return &SynthesisResult{
		BaseImage:           "rust:1.75-slim",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"./app"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 256,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  120,
	}
}

func (s *Synthesizer) rubyTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM ruby:3.2-slim

RUN groupadd -r executor && useradd -r -g executor executor

WORKDIR /app
COPY main.rb .

RUN chown -R executor:executor /app

USER executor

CMD ["ruby", "main.rb"]
`

	return &SynthesisResult{
		BaseImage:           "ruby:3.2-slim",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"ruby", "main.rb"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 256,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  60,
	}
}

func (s *Synthesizer) shellTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM alpine:3.19

RUN addgroup -S executor && adduser -S executor -G executor

WORKDIR /app
COPY script.sh .
RUN chmod +x script.sh && chown -R executor:executor /app

USER executor

CMD ["/bin/sh", "script.sh"]
`

	return &SynthesisResult{
		BaseImage:           "alpine:3.19",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"/bin/sh", "script.sh"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 64,
		RecommendedCPU:      0.5,
		RecommendedTimeout:  30,
	}
}

// validateAndEnhance validates and enhances LLM-generated synthesis
func (s *Synthesizer) validateAndEnhance(result *SynthesisResult, analysis *AnalysisResult) {
	// Ensure Dockerfile has non-root user
	if !strings.Contains(result.Dockerfile, "USER ") {
		result.Dockerfile = s.addNonRootUser(result.Dockerfile)
	}

	// Set reasonable defaults if missing
	if result.RecommendedMemoryMB == 0 {
		result.RecommendedMemoryMB = 256
	}
	if result.RecommendedCPU == 0 {
		result.RecommendedCPU = 1.0
	}
	if result.RecommendedTimeout == 0 {
		result.RecommendedTimeout = 60
	}

	// Ensure work directory is set
	if result.WorkDir == "" {
		result.WorkDir = "/app"
	}

	// Ensure run command is set
	if len(result.RunCommand) == 0 {
		result.RunCommand = s.inferRunCommand(analysis.DetectedLanguage)
	}
}

func (s *Synthesizer) addNonRootUser(dockerfile string) string {
	// Find CMD or ENTRYPOINT line
	lines := strings.Split(dockerfile, "\n")
	var result []string
	userAdded := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if (strings.HasPrefix(trimmed, "CMD") || strings.HasPrefix(trimmed, "ENTRYPOINT")) && !userAdded {
			result = append(result, "USER executor")
			userAdded = true
		}
		result = append(result, line)
	}

	// Add user creation after FROM if not already present
	if !strings.Contains(dockerfile, "useradd") && !strings.Contains(dockerfile, "adduser") {
		finalResult := []string{}
		for i, line := range result {
			finalResult = append(finalResult, line)
			if strings.HasPrefix(strings.TrimSpace(line), "FROM") && i == 0 {
				finalResult = append(finalResult, "RUN groupadd -r executor && useradd -r -g executor executor || addgroup -S executor && adduser -S executor -G executor")
			}
		}
		return strings.Join(finalResult, "\n")
	}

	return strings.Join(result, "\n")
}

func (s *Synthesizer) inferRunCommand(language string) []string {
	lang := strings.ToLower(language)
	switch lang {
	case "python", "py":
		return []string{"python", "main.py"}
	case "javascript", "js", "node":
		return []string{"node", "index.js"}
	case "go", "golang":
		return []string{"./app"}
	case "rust":
		return []string{"./app"}
	case "ruby", "rb":
		return []string{"ruby", "main.rb"}
	case "shell", "bash", "sh":
		return []string{"/bin/sh", "script.sh"}
	default:
		return []string{"python", "main.py"}
	}
}

// GetSourceFilename returns the appropriate filename for the language
func GetSourceFilename(language string, runCommand []string) string {
	lang := strings.ToLower(language)

	// Check run command first
	if len(runCommand) > 1 {
		lastArg := runCommand[len(runCommand)-1]
		if strings.Contains(lastArg, ".") {
			return lastArg
		}
	}

	switch {
	case strings.Contains(lang, "python"):
		return "main.py"
	case strings.Contains(lang, "node") || strings.Contains(lang, "javascript"):
		return "index.js"
	case strings.Contains(lang, "go"):
		return "main.go"
	case strings.Contains(lang, "rust"):
		return "main.rs"
	case strings.Contains(lang, "ruby"):
		return "main.rb"
	case strings.Contains(lang, "shell") || strings.Contains(lang, "bash"):
		return "script.sh"
	default:
		return "main.py"
	}
}

// GetLanguageForFilename returns the language based on filename
func GetLanguageForFilename(filename string) string {
	ext := ""
	if idx := strings.LastIndex(filename, "."); idx != -1 {
		ext = filename[idx:]
	}

	switch ext {
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".go":
		return "go"
	case ".rs":
		return "rust"
	case ".rb":
		return "ruby"
	case ".sh":
		return "shell"
	case ".java":
		return "java"
	case ".c":
		return "c"
	case ".cpp", ".cc", ".cxx":
		return "cpp"
	default:
		return ""
	}
}

// FormatDockerfile formats a Dockerfile template with values
func FormatDockerfile(template string, values map[string]string) string {
	result := template
	for k, v := range values {
		result = strings.ReplaceAll(result, fmt.Sprintf("{{%s}}", k), v)
	}
	return result
}
