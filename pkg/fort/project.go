package fort

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ProjectFile represents a file in a multi-file project
type ProjectFile struct {
	Path     string `json:"path"`
	Content  string `json:"content"`
	Size     int64  `json:"size"`
	IsDir    bool   `json:"is_dir"`
	Language string `json:"language,omitempty"`
}

// Project represents a multi-file project
type Project struct {
	Files        []ProjectFile     `json:"files"`
	RootPath     string            `json:"root_path"`
	TotalSize    int64             `json:"total_size"`
	FileCount    int               `json:"file_count"`
	Languages    map[string]int    `json:"languages"`     // language -> file count
	BuildFiles   []string          `json:"build_files"`   // Detected build system files
	ConfigFiles  []string          `json:"config_files"`  // Config files found
	EntryPoints  []string          `json:"entry_points"`  // Potential entry points
	Dependencies []ProjectDep      `json:"dependencies"`  // Detected dependencies
	ProjectType  string            `json:"project_type"`  // library, application, service, script
	Metadata     map[string]string `json:"metadata"`      // Extracted metadata (name, version, etc.)
}

// ProjectDep represents a project dependency
type ProjectDep struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Source   string `json:"source"` // file it was detected from
	Language string `json:"language"`
	Dev      bool   `json:"dev,omitempty"` // dev dependency
}

// ProjectAnalysis is the LLM-enhanced analysis of a project
type ProjectAnalysis struct {
	*AnalysisResult
	Project           *Project `json:"project"`
	RecommendedEntry  string   `json:"recommended_entry"`
	BuildCommands     []string `json:"build_commands"`
	RunCommand        []string `json:"run_command"`
	SetupInstructions string   `json:"setup_instructions"`
	ProjectSummary    string   `json:"project_summary"`
}

// Common build/config file patterns
var buildFilePatterns = map[string]string{
	"Makefile":         "make",
	"makefile":         "make",
	"CMakeLists.txt":   "cmake",
	"package.json":     "npm",
	"package-lock.json": "npm",
	"yarn.lock":        "yarn",
	"pnpm-lock.yaml":   "pnpm",
	"go.mod":           "go",
	"go.sum":           "go",
	"Cargo.toml":       "cargo",
	"Cargo.lock":       "cargo",
	"requirements.txt": "pip",
	"Pipfile":          "pipenv",
	"Pipfile.lock":     "pipenv",
	"pyproject.toml":   "poetry",
	"poetry.lock":      "poetry",
	"setup.py":         "setuptools",
	"setup.cfg":        "setuptools",
	"pom.xml":          "maven",
	"build.gradle":     "gradle",
	"build.gradle.kts": "gradle",
	"Gemfile":          "bundler",
	"Gemfile.lock":     "bundler",
	"composer.json":    "composer",
	"composer.lock":    "composer",
	"mix.exs":          "mix",
	"rebar.config":     "rebar",
	"Dockerfile":       "docker",
	"docker-compose.yml": "docker-compose",
	".dockerignore":    "docker",
}

// Entry point patterns by language
var entryPointPatterns = map[string][]*regexp.Regexp{
	"python": {
		regexp.MustCompile(`(?m)^if\s+__name__\s*==\s*['"]__main__['"]\s*:`),
		regexp.MustCompile(`(?m)^def\s+main\s*\(`),
		regexp.MustCompile(`(?m)^class\s+\w+App`),
	},
	"javascript": {
		regexp.MustCompile(`(?m)^(module\.)?exports\s*=`),
		regexp.MustCompile(`(?m)^export\s+default`),
		regexp.MustCompile(`(?m)app\.listen\s*\(`),
		regexp.MustCompile(`(?m)createServer\s*\(`),
	},
	"go": {
		regexp.MustCompile(`(?m)^func\s+main\s*\(\s*\)`),
		regexp.MustCompile(`(?m)^package\s+main\b`),
	},
	"rust": {
		regexp.MustCompile(`(?m)^fn\s+main\s*\(\s*\)`),
	},
	"java": {
		regexp.MustCompile(`(?m)public\s+static\s+void\s+main\s*\(`),
		regexp.MustCompile(`(?m)@SpringBootApplication`),
	},
	"c": {
		regexp.MustCompile(`(?m)^int\s+main\s*\(`),
		regexp.MustCompile(`(?m)^void\s+main\s*\(`),
	},
	"cpp": {
		regexp.MustCompile(`(?m)^int\s+main\s*\(`),
	},
	"php": {
		regexp.MustCompile(`(?m)<\?php`),
		regexp.MustCompile(`(?m)^namespace\s+App\\`),
	},
	"ruby": {
		regexp.MustCompile(`(?m)^if\s+__FILE__\s*==\s*\$0`),
		regexp.MustCompile(`(?m)^require\s+['"]sinatra['"]/`),
		regexp.MustCompile(`(?m)^Rails\.application`),
	},
}

// ExtractProject extracts files from an archive (zip, tar, tar.gz)
func ExtractProject(data []byte, format string) (*Project, error) {
	project := &Project{
		Files:      make([]ProjectFile, 0),
		Languages:  make(map[string]int),
		Metadata:   make(map[string]string),
	}

	var err error
	switch format {
	case "zip":
		err = extractZip(data, project)
	case "tar":
		err = extractTar(bytes.NewReader(data), project)
	case "tar.gz", "tgz":
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gr.Close()
		err = extractTar(gr, project)
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", format)
	}

	if err != nil {
		return nil, err
	}

	// Analyze the extracted project
	analyzeProjectStructure(project)

	return project, nil
}

// ParseProjectFromFiles creates a Project from a map of filename -> content
func ParseProjectFromFiles(files map[string]string) *Project {
	project := &Project{
		Files:      make([]ProjectFile, 0, len(files)),
		Languages:  make(map[string]int),
		Metadata:   make(map[string]string),
	}

	for path, content := range files {
		lang := GetLanguageForFilename(path)
		project.Files = append(project.Files, ProjectFile{
			Path:     path,
			Content:  content,
			Size:     int64(len(content)),
			Language: lang,
		})
		project.TotalSize += int64(len(content))
		if lang != "" {
			project.Languages[lang]++
		}
	}

	project.FileCount = len(project.Files)
	analyzeProjectStructure(project)

	return project
}

func extractZip(data []byte, project *Project) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to read zip: %w", err)
	}

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		// Skip hidden files and common non-essential directories
		if shouldSkipFile(f.Name) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		content, err := io.ReadAll(io.LimitReader(rc, 1024*1024)) // 1MB limit per file
		rc.Close()
		if err != nil {
			continue
		}

		lang := GetLanguageForFilename(f.Name)
		project.Files = append(project.Files, ProjectFile{
			Path:     f.Name,
			Content:  string(content),
			Size:     int64(len(content)),
			Language: lang,
		})
		project.TotalSize += int64(len(content))
		if lang != "" {
			project.Languages[lang]++
		}
	}

	project.FileCount = len(project.Files)
	return nil
}

func extractTar(r io.Reader, project *Project) error {
	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		if shouldSkipFile(header.Name) {
			continue
		}

		content, err := io.ReadAll(io.LimitReader(tr, 1024*1024))
		if err != nil {
			continue
		}

		lang := GetLanguageForFilename(header.Name)
		project.Files = append(project.Files, ProjectFile{
			Path:     header.Name,
			Content:  string(content),
			Size:     int64(len(content)),
			Language: lang,
		})
		project.TotalSize += int64(len(content))
		if lang != "" {
			project.Languages[lang]++
		}
	}

	project.FileCount = len(project.Files)
	return nil
}

func shouldSkipFile(path string) bool {
	// Skip hidden files
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			// Allow some dotfiles
			if part != ".env.example" && part != ".gitignore" && part != ".dockerignore" {
				return true
			}
		}
	}

	// Skip common non-essential directories
	skipDirs := []string{"node_modules/", "vendor/", "__pycache__/", ".git/", "dist/", "build/", "target/", ".venv/", "venv/"}
	for _, dir := range skipDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}

	// Skip binary files by extension
	binaryExts := []string{".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".pyc", ".class", ".jar", ".war", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz"}
	ext := strings.ToLower(filepath.Ext(path))
	for _, bext := range binaryExts {
		if ext == bext {
			return true
		}
	}

	return false
}

func analyzeProjectStructure(project *Project) {
	// Find build files
	for _, f := range project.Files {
		basename := filepath.Base(f.Path)
		if _, ok := buildFilePatterns[basename]; ok {
			project.BuildFiles = append(project.BuildFiles, f.Path)
		}

		// Check for config files
		if strings.HasSuffix(basename, ".json") ||
			strings.HasSuffix(basename, ".yaml") ||
			strings.HasSuffix(basename, ".yml") ||
			strings.HasSuffix(basename, ".toml") ||
			strings.HasSuffix(basename, ".ini") ||
			strings.HasSuffix(basename, ".cfg") {
			project.ConfigFiles = append(project.ConfigFiles, f.Path)
		}
	}

	// Find entry points
	findEntryPoints(project)

	// Parse dependencies from known files
	parseDependencies(project)

	// Determine project type
	determineProjectType(project)

	// Find root path (common prefix)
	if len(project.Files) > 0 {
		project.RootPath = findCommonPrefix(project.Files)
	}
}

func findEntryPoints(project *Project) {
	type entryCandidate struct {
		path  string
		score int
	}
	candidates := make([]entryCandidate, 0)

	for _, f := range project.Files {
		if f.Language == "" {
			continue
		}

		score := 0
		basename := filepath.Base(f.Path)

		// Check filename patterns
		if basename == "main.py" || basename == "app.py" || basename == "__main__.py" {
			score += 10
		}
		if basename == "main.go" || basename == "cmd/main.go" {
			score += 10
		}
		if basename == "index.js" || basename == "app.js" || basename == "server.js" {
			score += 10
		}
		if basename == "main.rs" || basename == "lib.rs" {
			score += 10
		}
		if basename == "Main.java" || basename == "Application.java" {
			score += 10
		}
		if basename == "main.c" || basename == "main.cpp" {
			score += 10
		}
		if basename == "index.php" || basename == "app.php" {
			score += 10
		}

		// Check for entry point patterns in content
		patterns, ok := entryPointPatterns[f.Language]
		if ok {
			for _, p := range patterns {
				if p.MatchString(f.Content) {
					score += 5
				}
			}
		}

		// Prefer files in root or src directory
		if !strings.Contains(f.Path, "/") {
			score += 3
		}
		if strings.HasPrefix(f.Path, "src/") || strings.HasPrefix(f.Path, "cmd/") {
			score += 2
		}

		if score > 0 {
			candidates = append(candidates, entryCandidate{f.Path, score})
		}
	}

	// Sort by score descending
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	// Take top candidates
	for i, c := range candidates {
		if i >= 5 {
			break
		}
		project.EntryPoints = append(project.EntryPoints, c.path)
	}
}

func parseDependencies(project *Project) {
	for _, f := range project.Files {
		basename := filepath.Base(f.Path)

		switch basename {
		case "requirements.txt":
			parsePythonRequirements(f.Content, f.Path, project)
		case "package.json":
			parsePackageJSON(f.Content, f.Path, project)
		case "go.mod":
			parseGoMod(f.Content, f.Path, project)
		case "Cargo.toml":
			parseCargoToml(f.Content, f.Path, project)
		case "Gemfile":
			parseGemfile(f.Content, f.Path, project)
		case "composer.json":
			parseComposerJSON(f.Content, f.Path, project)
		case "pom.xml":
			parsePomXML(f.Content, f.Path, project)
		}
	}
}

func parsePythonRequirements(content, source string, project *Project) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Parse: package==version, package>=version, package
		re := regexp.MustCompile(`^([a-zA-Z0-9_-]+)([<>=!]+)?(.+)?$`)
		if m := re.FindStringSubmatch(line); m != nil {
			project.Dependencies = append(project.Dependencies, ProjectDep{
				Name:     m[1],
				Version:  strings.TrimSpace(m[3]),
				Source:   source,
				Language: "python",
			})
		}
	}
}

func parsePackageJSON(content, source string, project *Project) {
	var pkg struct {
		Name         string            `json:"name"`
		Version      string            `json:"version"`
		Dependencies map[string]string `json:"dependencies"`
		DevDeps      map[string]string `json:"devDependencies"`
		Scripts      map[string]string `json:"scripts"`
		Main         string            `json:"main"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return
	}

	project.Metadata["name"] = pkg.Name
	project.Metadata["version"] = pkg.Version
	if pkg.Main != "" {
		project.Metadata["main"] = pkg.Main
	}

	for name, ver := range pkg.Dependencies {
		project.Dependencies = append(project.Dependencies, ProjectDep{
			Name:     name,
			Version:  ver,
			Source:   source,
			Language: "javascript",
		})
	}
	for name, ver := range pkg.DevDeps {
		project.Dependencies = append(project.Dependencies, ProjectDep{
			Name:     name,
			Version:  ver,
			Source:   source,
			Language: "javascript",
			Dev:      true,
		})
	}
}

func parseGoMod(content, source string, project *Project) {
	lines := strings.Split(content, "\n")
	inRequire := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			project.Metadata["module"] = strings.TrimPrefix(line, "module ")
		}
		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if inRequire || strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				project.Dependencies = append(project.Dependencies, ProjectDep{
					Name:     parts[0],
					Version:  parts[1],
					Source:   source,
					Language: "go",
				})
			}
		}
	}
}

func parseCargoToml(content, source string, project *Project) {
	// Simple TOML parsing for dependencies
	lines := strings.Split(content, "\n")
	inDeps := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[dependencies]" {
			inDeps = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDeps = false
			continue
		}
		if inDeps && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			name := strings.TrimSpace(parts[0])
			version := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
			project.Dependencies = append(project.Dependencies, ProjectDep{
				Name:     name,
				Version:  version,
				Source:   source,
				Language: "rust",
			})
		}
	}
}

func parseGemfile(content, source string, project *Project) {
	re := regexp.MustCompile(`gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?`)
	matches := re.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		dep := ProjectDep{
			Name:     m[1],
			Source:   source,
			Language: "ruby",
		}
		if len(m) > 2 {
			dep.Version = m[2]
		}
		project.Dependencies = append(project.Dependencies, dep)
	}
}

func parseComposerJSON(content, source string, project *Project) {
	var pkg struct {
		Name    string            `json:"name"`
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return
	}
	project.Metadata["name"] = pkg.Name
	for name, ver := range pkg.Require {
		project.Dependencies = append(project.Dependencies, ProjectDep{
			Name:     name,
			Version:  ver,
			Source:   source,
			Language: "php",
		})
	}
}

func parsePomXML(content, source string, project *Project) {
	// Simple XML parsing for Maven dependencies
	re := regexp.MustCompile(`<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?`)
	matches := re.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		project.Dependencies = append(project.Dependencies, ProjectDep{
			Name:     m[1] + ":" + m[2],
			Version:  m[3],
			Source:   source,
			Language: "java",
		})
	}
}

func determineProjectType(project *Project) {
	// Check for indicators of project type
	for _, f := range project.BuildFiles {
		basename := filepath.Base(f)
		switch basename {
		case "setup.py", "pyproject.toml":
			project.ProjectType = "library"
			return
		case "Dockerfile", "docker-compose.yml":
			project.ProjectType = "service"
			return
		}
	}

	// Check package.json for type hints
	if name, ok := project.Metadata["main"]; ok && name != "" {
		project.ProjectType = "application"
		return
	}

	// Default based on entry points
	if len(project.EntryPoints) > 0 {
		project.ProjectType = "application"
	} else if len(project.Files) == 1 {
		project.ProjectType = "script"
	} else {
		project.ProjectType = "library"
	}
}

func findCommonPrefix(files []ProjectFile) string {
	if len(files) == 0 {
		return ""
	}
	if len(files) == 1 {
		dir := filepath.Dir(files[0].Path)
		if dir == "." {
			return ""
		}
		return dir
	}

	// Find common prefix
	prefix := filepath.Dir(files[0].Path)
	for _, f := range files[1:] {
		dir := filepath.Dir(f.Path)
		for !strings.HasPrefix(dir, prefix) && prefix != "" {
			prefix = filepath.Dir(prefix)
			if prefix == "." {
				prefix = ""
				break
			}
		}
	}
	return prefix
}

// ProjectAnalyzer analyzes multi-file projects using LLM
type ProjectAnalyzer struct {
	llm LLMClient
}

// NewProjectAnalyzer creates a new project analyzer
func NewProjectAnalyzer(llm LLMClient) *ProjectAnalyzer {
	return &ProjectAnalyzer{llm: llm}
}

// AnalyzeProject performs deep analysis of a multi-file project
func (pa *ProjectAnalyzer) AnalyzeProject(ctx context.Context, project *Project, purpose string) (*ProjectAnalysis, error) {
	// Build a summary of the project for the LLM
	projectSummary := pa.buildProjectSummary(project)

	// Call LLM with project summary as code content
	// The LLM will detect this is a project analysis request from the structure
	result, err := pa.llm.Analyze(ctx, projectSummary, "", purpose)
	if err != nil {
		// Fall back to heuristic analysis
		return pa.heuristicAnalysis(project), nil
	}

	analysis := &ProjectAnalysis{
		AnalysisResult: result,
		Project:        project,
	}

	// Extract additional fields from LLM response if available
	if len(project.EntryPoints) > 0 && result.RecommendedEntry == "" {
		analysis.RecommendedEntry = project.EntryPoints[0]
	} else {
		analysis.RecommendedEntry = result.RecommendedEntry
	}

	return analysis, nil
}

func (pa *ProjectAnalyzer) buildProjectSummary(project *Project) string {
	var sb strings.Builder

	sb.WriteString("PROJECT STRUCTURE:\n")
	sb.WriteString(fmt.Sprintf("- Total files: %d\n", project.FileCount))
	sb.WriteString(fmt.Sprintf("- Total size: %d bytes\n", project.TotalSize))

	if len(project.Languages) > 0 {
		sb.WriteString("- Languages: ")
		langs := make([]string, 0, len(project.Languages))
		for lang, count := range project.Languages {
			langs = append(langs, fmt.Sprintf("%s(%d)", lang, count))
		}
		sb.WriteString(strings.Join(langs, ", "))
		sb.WriteString("\n")
	}

	if len(project.BuildFiles) > 0 {
		sb.WriteString("- Build files: " + strings.Join(project.BuildFiles, ", ") + "\n")
	}

	if len(project.EntryPoints) > 0 {
		sb.WriteString("- Detected entry points: " + strings.Join(project.EntryPoints, ", ") + "\n")
	}

	if len(project.Dependencies) > 0 {
		sb.WriteString(fmt.Sprintf("- Dependencies: %d packages\n", len(project.Dependencies)))
	}

	sb.WriteString("\nFILE LISTING:\n")
	for _, f := range project.Files {
		lang := ""
		if f.Language != "" {
			lang = fmt.Sprintf(" [%s]", f.Language)
		}
		sb.WriteString(fmt.Sprintf("  %s (%d bytes)%s\n", f.Path, f.Size, lang))
	}

	// Include content of key files (limited)
	sb.WriteString("\nKEY FILE CONTENTS:\n")
	keyFiles := pa.selectKeyFiles(project)
	for _, f := range keyFiles {
		content := f.Content
		if len(content) > 2000 {
			content = content[:2000] + "\n... (truncated)"
		}
		sb.WriteString(fmt.Sprintf("\n--- %s ---\n%s\n", f.Path, content))
	}

	return sb.String()
}

func (pa *ProjectAnalyzer) selectKeyFiles(project *Project) []ProjectFile {
	var selected []ProjectFile
	maxFiles := 10
	maxTotalSize := 20000

	// Priority: build files, entry points, then others
	priority := make(map[string]int)
	for _, f := range project.BuildFiles {
		priority[f] = 100
	}
	for i, f := range project.EntryPoints {
		priority[f] = 50 - i
	}

	// Sort files by priority
	files := make([]ProjectFile, len(project.Files))
	copy(files, project.Files)
	sort.Slice(files, func(i, j int) bool {
		return priority[files[i].Path] > priority[files[j].Path]
	})

	totalSize := 0
	for _, f := range files {
		if len(selected) >= maxFiles || totalSize >= maxTotalSize {
			break
		}
		if f.Size > 5000 {
			continue // Skip very large files
		}
		selected = append(selected, f)
		totalSize += int(f.Size)
	}

	return selected
}

func (pa *ProjectAnalyzer) heuristicAnalysis(project *Project) *ProjectAnalysis {
	// Determine primary language
	primaryLang := ""
	maxCount := 0
	for lang, count := range project.Languages {
		if count > maxCount {
			maxCount = count
			primaryLang = lang
		}
	}

	analysis := &ProjectAnalysis{
		AnalysisResult: &AnalysisResult{
			DetectedLanguage: primaryLang,
			Complexity:       Complexity(determineComplexity(project)),
		},
		Project: project,
	}

	if len(project.EntryPoints) > 0 {
		analysis.RecommendedEntry = project.EntryPoints[0]
	}

	// Determine build and run commands based on build files
	analysis.BuildCommands, analysis.RunCommand = determineBuildAndRun(project, primaryLang)

	return analysis
}

func determineComplexity(project *Project) string {
	if project.FileCount <= 1 {
		return "trivial"
	}
	if project.FileCount <= 5 && len(project.Dependencies) <= 3 {
		return "simple"
	}
	if project.FileCount <= 20 && len(project.Dependencies) <= 10 {
		return "moderate"
	}
	if project.FileCount <= 50 {
		return "complex"
	}
	return "extreme"
}

func determineBuildAndRun(project *Project, lang string) ([]string, []string) {
	var build, run []string

	// Check for specific build systems
	for _, bf := range project.BuildFiles {
		basename := filepath.Base(bf)
		switch basename {
		case "package.json":
			build = append(build, "npm install")
			if project.Metadata["main"] != "" {
				run = []string{"node", project.Metadata["main"]}
			} else {
				run = []string{"npm", "start"}
			}
			return build, run
		case "requirements.txt":
			build = append(build, "pip install -r requirements.txt")
		case "go.mod":
			build = append(build, "go build -o app .")
			run = []string{"./app"}
			return build, run
		case "Cargo.toml":
			build = append(build, "cargo build --release")
			run = []string{"./target/release/app"}
			return build, run
		case "Makefile":
			build = append(build, "make")
		case "pom.xml":
			build = append(build, "mvn package")
			run = []string{"java", "-jar", "target/*.jar"}
			return build, run
		}
	}

	// Default run commands by language
	if len(run) == 0 && len(project.EntryPoints) > 0 {
		entry := project.EntryPoints[0]
		switch lang {
		case "python":
			run = []string{"python", entry}
		case "javascript":
			run = []string{"node", entry}
		case "go":
			run = []string{"go", "run", entry}
		case "ruby":
			run = []string{"ruby", entry}
		case "php":
			run = []string{"php", entry}
		}
	}

	return build, run
}
