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
	// Try LLM synthesis first - it understands the project better
	result, err := s.llm.Synthesize(ctx, req.SourceContent, analysis)
	if err != nil {
		// Fall back to template-based synthesis
		return s.templateSynthesize(analysis), nil
	}

	// Validate and enhance LLM result
	s.validateAndEnhance(result, analysis)

	return result, nil
}

// SynthesizeProject generates container config for multi-file projects
func (s *Synthesizer) SynthesizeProject(ctx context.Context, project *Project, analysis *ProjectAnalysis) (*SynthesisResult, error) {
	// Build comprehensive project context for LLM
	projectContext := buildProjectContext(project, analysis)

	// Use LLM to generate optimal Dockerfile
	result, err := s.llm.SynthesizeProject(ctx, projectContext, analysis.AnalysisResult)
	if err != nil {
		// Fall back to template with project awareness
		return s.templateSynthesizeProject(project, analysis), nil
	}

	s.validateAndEnhance(result, analysis.AnalysisResult)
	return result, nil
}

func buildProjectContext(project *Project, analysis *ProjectAnalysis) string {
	var sb strings.Builder

	sb.WriteString("PROJECT ANALYSIS:\n")
	sb.WriteString(fmt.Sprintf("- Language: %s\n", analysis.DetectedLanguage))
	sb.WriteString(fmt.Sprintf("- Runtime: %s\n", analysis.DetectedRuntime))
	sb.WriteString(fmt.Sprintf("- Type: %s\n", project.ProjectType))
	sb.WriteString(fmt.Sprintf("- Files: %d\n", project.FileCount))

	if len(analysis.DetectedFrameworks) > 0 {
		sb.WriteString(fmt.Sprintf("- Frameworks: %s\n", strings.Join(analysis.DetectedFrameworks, ", ")))
	}

	if analysis.RecommendedEntry != "" {
		sb.WriteString(fmt.Sprintf("- Entry point: %s\n", analysis.RecommendedEntry))
	}

	if len(project.BuildFiles) > 0 {
		sb.WriteString(fmt.Sprintf("- Build files: %s\n", strings.Join(project.BuildFiles, ", ")))
	}

	// List dependencies
	if len(project.Dependencies) > 0 {
		sb.WriteString("\nDEPENDENCIES:\n")
		for _, dep := range project.Dependencies {
			ver := dep.Version
			if ver == "" {
				ver = "latest"
			}
			sb.WriteString(fmt.Sprintf("  - %s@%s (%s)\n", dep.Name, ver, dep.Language))
		}
	}

	// Include key file contents
	sb.WriteString("\nKEY FILES:\n")
	for _, f := range project.Files {
		// Include build files and entry points
		isBuildFile := false
		for _, bf := range project.BuildFiles {
			if f.Path == bf {
				isBuildFile = true
				break
			}
		}
		isEntry := f.Path == analysis.RecommendedEntry

		if isBuildFile || isEntry {
			content := f.Content
			if len(content) > 3000 {
				content = content[:3000] + "\n... (truncated)"
			}
			sb.WriteString(fmt.Sprintf("\n--- %s ---\n%s\n", f.Path, content))
		}
	}

	// File listing
	sb.WriteString("\nALL FILES:\n")
	for _, f := range project.Files {
		sb.WriteString(fmt.Sprintf("  %s (%d bytes)\n", f.Path, f.Size))
	}

	return sb.String()
}

func (s *Synthesizer) templateSynthesizeProject(project *Project, analysis *ProjectAnalysis) *SynthesisResult {
	// Use enhanced templates that understand project structure
	lang := strings.ToLower(analysis.DetectedLanguage)

	// Start with base template
	result := s.templateSynthesize(analysis.AnalysisResult)

	// Enhance based on project structure
	if len(project.BuildFiles) > 0 {
		result.Dockerfile = s.enhanceDockerfileForProject(result.Dockerfile, project, lang)
	}

	// Update run command based on detected entry point
	if analysis.RecommendedEntry != "" {
		result.RunCommand = s.inferRunCommand(lang)
		if len(result.RunCommand) > 0 {
			result.RunCommand[len(result.RunCommand)-1] = analysis.RecommendedEntry
		}
	}

	return result
}

func (s *Synthesizer) enhanceDockerfileForProject(dockerfile string, project *Project, lang string) string {
	// Add COPY . . for multi-file projects instead of single file copy
	lines := strings.Split(dockerfile, "\n")
	var result []string

	for _, line := range lines {
		// Replace single file COPY with full project COPY
		if strings.HasPrefix(strings.TrimSpace(line), "COPY main.") ||
			strings.HasPrefix(strings.TrimSpace(line), "COPY index.") ||
			strings.HasPrefix(strings.TrimSpace(line), "COPY script.") {
			result = append(result, "COPY . .")
		} else {
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

// templateSynthesize generates configuration using templates
func (s *Synthesizer) templateSynthesize(analysis *AnalysisResult) *SynthesisResult {
	lang := strings.ToLower(analysis.DetectedLanguage)

	switch lang {
	case "python", "py":
		return s.pythonTemplate(analysis)
	case "javascript", "js", "node":
		return s.nodeTemplate(analysis)
	case "typescript", "ts":
		return s.typescriptTemplate(analysis)
	case "go", "golang":
		return s.goTemplate(analysis)
	case "rust":
		return s.rustTemplate(analysis)
	case "ruby", "rb":
		return s.rubyTemplate(analysis)
	case "java":
		return s.javaTemplate(analysis)
	case "c":
		return s.cTemplate(analysis)
	case "cpp", "c++", "cxx":
		return s.cppTemplate(analysis)
	case "php":
		return s.phpTemplate(analysis)
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

func (s *Synthesizer) javaTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /build
COPY . .

# If Maven project
RUN if [ -f "pom.xml" ]; then \
        apk add --no-cache maven && \
        mvn package -DskipTests; \
    elif [ -f "build.gradle" ] || [ -f "build.gradle.kts" ]; then \
        apk add --no-cache gradle && \
        gradle build -x test; \
    else \
        mkdir -p target && \
        javac -d target *.java; \
    fi

FROM eclipse-temurin:21-jre-alpine

RUN addgroup -S executor && adduser -S executor -G executor

WORKDIR /app

# Copy compiled artifacts
COPY --from=builder /build/target/*.jar /app/ 2>/dev/null || true
COPY --from=builder /build/target/*.class /app/ 2>/dev/null || true

RUN chown -R executor:executor /app

USER executor

CMD ["java", "-jar", "app.jar"]
`

	return &SynthesisResult{
		BaseImage:           "eclipse-temurin:21-jdk-alpine",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"java", "-jar", "app.jar"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 512,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  120,
	}
}

func (s *Synthesizer) cTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM alpine:3.19 AS builder

RUN apk add --no-cache gcc musl-dev make

WORKDIR /build
COPY . .

# Build using Makefile if present, otherwise compile directly
RUN if [ -f "Makefile" ]; then \
        make; \
    else \
        gcc -o app *.c -O2 -Wall; \
    fi

FROM alpine:3.19

RUN addgroup -S executor && adduser -S executor -G executor

WORKDIR /app
COPY --from=builder /build/app .

RUN chown -R executor:executor /app

USER executor

CMD ["./app"]
`

	return &SynthesisResult{
		BaseImage:           "alpine:3.19",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"./app"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 64,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  60,
	}
}

func (s *Synthesizer) cppTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM alpine:3.19 AS builder

RUN apk add --no-cache g++ make cmake

WORKDIR /build
COPY . .

# Build using CMake if present, Makefile, or compile directly
RUN if [ -f "CMakeLists.txt" ]; then \
        mkdir -p build && cd build && cmake .. && make; \
    elif [ -f "Makefile" ]; then \
        make; \
    else \
        g++ -o app *.cpp -O2 -Wall -std=c++17; \
    fi

FROM alpine:3.19

RUN apk add --no-cache libstdc++
RUN addgroup -S executor && adduser -S executor -G executor

WORKDIR /app
COPY --from=builder /build/app . 2>/dev/null || \
     COPY --from=builder /build/build/app . 2>/dev/null || true

RUN chown -R executor:executor /app

USER executor

CMD ["./app"]
`

	return &SynthesisResult{
		BaseImage:           "alpine:3.19",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"./app"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 128,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  60,
	}
}

func (s *Synthesizer) phpTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM php:8.3-cli-alpine

RUN addgroup -S executor && adduser -S executor -G executor

# Install composer if composer.json exists
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

WORKDIR /app
COPY . .

# Install dependencies if composer.json exists
RUN if [ -f "composer.json" ]; then \
        composer install --no-dev --optimize-autoloader; \
    fi

RUN chown -R executor:executor /app

USER executor

CMD ["php", "index.php"]
`

	return &SynthesisResult{
		BaseImage:           "php:8.3-cli-alpine",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"php", "index.php"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 256,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  60,
	}
}

func (s *Synthesizer) typescriptTemplate(analysis *AnalysisResult) *SynthesisResult {
	dockerfile := `FROM node:20-slim AS builder

WORKDIR /build
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build 2>/dev/null || npx tsc

FROM node:20-slim

RUN groupadd -r executor && useradd -r -g executor executor

WORKDIR /app
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/package*.json ./

RUN chown -R executor:executor /app

USER executor

CMD ["node", "dist/index.js"]
`

	return &SynthesisResult{
		BaseImage:           "node:20-slim",
		Dockerfile:          dockerfile,
		RunCommand:          []string{"node", "dist/index.js"},
		WorkDir:             "/app",
		RecommendedMemoryMB: 256,
		RecommendedCPU:      1.0,
		RecommendedTimeout:  60,
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
	case ".py", ".pyw":
		return "python"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".jsx":
		return "javascript"
	case ".go":
		return "go"
	case ".rs":
		return "rust"
	case ".rb":
		return "ruby"
	case ".sh", ".bash":
		return "shell"
	case ".java":
		return "java"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp", ".hxx":
		return "cpp"
	case ".php":
		return "php"
	case ".cs":
		return "csharp"
	case ".swift":
		return "swift"
	case ".kt", ".kts":
		return "kotlin"
	case ".scala":
		return "scala"
	case ".ex", ".exs":
		return "elixir"
	case ".erl", ".hrl":
		return "erlang"
	case ".hs":
		return "haskell"
	case ".ml", ".mli":
		return "ocaml"
	case ".r", ".R":
		return "r"
	case ".jl":
		return "julia"
	case ".lua":
		return "lua"
	case ".pl", ".pm":
		return "perl"
	case ".sql":
		return "sql"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".xml":
		return "xml"
	case ".md", ".markdown":
		return "markdown"
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
