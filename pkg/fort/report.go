package fort

import (
	"encoding/json"
	"time"
)

// AnalysisReport is a comprehensive structured analysis report
type AnalysisReport struct {
	// Metadata
	ReportID    string    `json:"report_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Version     string    `json:"version"`

	// Input
	Input ReportInput `json:"input"`

	// Code Analysis
	Code CodeAnalysis `json:"code"`

	// Security Assessment
	Security SecurityAssessment `json:"security"`

	// Capabilities Required
	Capabilities CapabilityRequirements `json:"capabilities"`

	// Dependencies
	Dependencies DependencyAnalysis `json:"dependencies"`

	// Execution Recommendations
	Execution ExecutionRecommendations `json:"execution"`

	// Overall Assessment
	Summary ReportSummary `json:"summary"`
}

// ReportInput captures the input that was analyzed
type ReportInput struct {
	SourceType   string `json:"source_type"`
	Language     string `json:"language_hint,omitempty"`
	Purpose      string `json:"purpose,omitempty"`
	CodeSize     int    `json:"code_size_bytes"`
	LineCount    int    `json:"line_count"`
	SHA256       string `json:"sha256"`
}

// CodeAnalysis contains code structure analysis
type CodeAnalysis struct {
	// Language detection
	DetectedLanguage string   `json:"detected_language"`
	LanguageVersion  string   `json:"language_version,omitempty"`
	Confidence       float64  `json:"confidence"`

	// Structure
	Frameworks      []string       `json:"frameworks"`
	EntryPoints     []EntryPoint   `json:"entry_points"`
	Functions       []FunctionInfo `json:"functions,omitempty"`
	Classes         []ClassInfo    `json:"classes,omitempty"`
	Imports         []ImportInfo   `json:"imports"`

	// Metrics
	Complexity      ComplexityMetrics `json:"complexity"`

	// Description
	Summary         string `json:"summary"`
	Purpose         string `json:"inferred_purpose"`
}

// EntryPoint describes a code entry point
type EntryPoint struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // main, function, class, script
	Location    string `json:"location"`
	Recommended bool   `json:"recommended"`
}

// FunctionInfo describes a function
type FunctionInfo struct {
	Name       string   `json:"name"`
	Parameters []string `json:"parameters,omitempty"`
	Returns    string   `json:"returns,omitempty"`
	Location   string   `json:"location"`
	IsAsync    bool     `json:"is_async,omitempty"`
}

// ClassInfo describes a class
type ClassInfo struct {
	Name       string   `json:"name"`
	Bases      []string `json:"bases,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	Location   string   `json:"location"`
}

// ImportInfo describes an import statement
type ImportInfo struct {
	Module   string `json:"module"`
	Alias    string `json:"alias,omitempty"`
	Items    []string `json:"items,omitempty"`
	Location string `json:"location"`
	IsStdLib bool   `json:"is_stdlib"`
}

// ComplexityMetrics contains code complexity metrics
type ComplexityMetrics struct {
	Level           string  `json:"level"` // trivial, simple, moderate, complex, extreme
	Score           int     `json:"score"` // 1-100
	CyclomaticEst   int     `json:"cyclomatic_estimate,omitempty"`
	LinesOfCode     int     `json:"lines_of_code"`
	CommentRatio    float64 `json:"comment_ratio"`
	EstimatedRuntime string `json:"estimated_runtime"`
}

// SecurityAssessment contains security analysis
type SecurityAssessment struct {
	// Overall
	Safe        bool      `json:"safe"`
	RiskLevel   string    `json:"risk_level"` // none, low, medium, high, critical
	RiskScore   int       `json:"risk_score"` // 0-100
	Confidence  float64   `json:"confidence"`

	// Findings
	Findings    []SecurityIssue `json:"findings"`

	// Patterns detected
	Patterns    PatternAnalysis `json:"patterns"`

	// Obfuscation
	Obfuscation ObfuscationAnalysis `json:"obfuscation"`

	// Recommendations
	Mitigations []string `json:"mitigations,omitempty"`
}

// SecurityIssue describes a security finding
type SecurityIssue struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"` // info, low, medium, high, critical
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Location    string   `json:"location,omitempty"`
	LineNumber  int      `json:"line_number,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Mitigated   bool     `json:"mitigated_by_sandbox"`
	Mitigation  string   `json:"mitigation,omitempty"`
}

// PatternAnalysis contains detected patterns
type PatternAnalysis struct {
	CommandExecution  []PatternMatch `json:"command_execution,omitempty"`
	CodeInjection     []PatternMatch `json:"code_injection,omitempty"`
	NetworkAccess     []PatternMatch `json:"network_access,omitempty"`
	FileSystemAccess  []PatternMatch `json:"filesystem_access,omitempty"`
	CryptoOperations  []PatternMatch `json:"crypto_operations,omitempty"`
	DataExfiltration  []PatternMatch `json:"data_exfiltration,omitempty"`
	PrivilegeEsc      []PatternMatch `json:"privilege_escalation,omitempty"`
	ReverseShell      []PatternMatch `json:"reverse_shell,omitempty"`
}

// PatternMatch describes a matched pattern
type PatternMatch struct {
	Pattern    string `json:"pattern"`
	Match      string `json:"match"`
	Location   string `json:"location"`
	LineNumber int    `json:"line_number"`
	Severity   string `json:"severity"`
}

// ObfuscationAnalysis contains obfuscation detection results
type ObfuscationAnalysis struct {
	IsObfuscated    bool    `json:"is_obfuscated"`
	Confidence      float64 `json:"confidence"`
	Entropy         float64 `json:"entropy"`
	Indicators      []string `json:"indicators,omitempty"`
	EncodingTypes   []string `json:"encoding_types,omitempty"`
}

// CapabilityRequirements describes what capabilities the code needs
type CapabilityRequirements struct {
	// Network
	Network NetworkCapability `json:"network"`

	// Filesystem
	Filesystem FilesystemCapability `json:"filesystem"`

	// Process
	Process ProcessCapability `json:"process"`

	// System
	System SystemCapability `json:"system"`

	// Resources
	Resources ResourceRequirements `json:"resources"`
}

// NetworkCapability describes network requirements
type NetworkCapability struct {
	Required     bool     `json:"required"`
	Outbound     bool     `json:"outbound"`
	Inbound      bool     `json:"inbound"`
	Protocols    []string `json:"protocols,omitempty"`  // http, https, tcp, udp, websocket
	Domains      []string `json:"domains,omitempty"`
	Ports        []int    `json:"ports,omitempty"`
	Evidence     []string `json:"evidence,omitempty"`
}

// FilesystemCapability describes filesystem requirements
type FilesystemCapability struct {
	ReadRequired   bool     `json:"read_required"`
	WriteRequired  bool     `json:"write_required"`
	ReadPaths      []string `json:"read_paths,omitempty"`
	WritePaths     []string `json:"write_paths,omitempty"`
	TempRequired   bool     `json:"temp_required"`
	Evidence       []string `json:"evidence,omitempty"`
}

// ProcessCapability describes process requirements
type ProcessCapability struct {
	SubprocessRequired bool     `json:"subprocess_required"`
	Commands           []string `json:"commands,omitempty"`
	ShellRequired      bool     `json:"shell_required"`
	Evidence           []string `json:"evidence,omitempty"`
}

// SystemCapability describes system requirements
type SystemCapability struct {
	EnvironmentVars []string `json:"environment_vars,omitempty"`
	SystemCalls     []string `json:"system_calls,omitempty"`
	Permissions     []string `json:"permissions,omitempty"`
	Evidence        []string `json:"evidence,omitempty"`
}

// ResourceRequirements describes resource needs
type ResourceRequirements struct {
	EstimatedMemoryMB  int     `json:"estimated_memory_mb"`
	EstimatedCPU       float64 `json:"estimated_cpu"`
	EstimatedTimeoutS  int     `json:"estimated_timeout_sec"`
	GPURequired        bool    `json:"gpu_required"`
	DiskSpaceMB        int     `json:"disk_space_mb,omitempty"`
}

// DependencyAnalysis contains dependency information
type DependencyAnalysis struct {
	Count           int                `json:"count"`
	Dependencies    []DependencyInfo   `json:"dependencies"`
	VulnerableCount int                `json:"vulnerable_count"`
	UnknownCount    int                `json:"unknown_count"`
	RiskScore       int                `json:"risk_score"` // 0-100
}

// DependencyInfo describes a dependency
type DependencyInfo struct {
	Name          string   `json:"name"`
	Version       string   `json:"version,omitempty"`
	Source        string   `json:"source"` // pip, npm, cargo, etc.
	Required      bool     `json:"required"`
	IsTransitive  bool     `json:"is_transitive"`
	RiskLevel     string   `json:"risk_level,omitempty"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities,omitempty"`
	License       string   `json:"license,omitempty"`
}

// VulnerabilityInfo describes a known vulnerability
type VulnerabilityInfo struct {
	ID          string `json:"id"` // CVE, GHSA, etc.
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
	FixedIn     string `json:"fixed_in,omitempty"`
}

// ExecutionRecommendations contains execution suggestions
type ExecutionRecommendations struct {
	Recommended     bool              `json:"recommended"`
	RequiresReview  bool              `json:"requires_review"`
	ReviewReasons   []string          `json:"review_reasons,omitempty"`

	// Container config
	BaseImage       string            `json:"base_image"`
	Runtime         string            `json:"runtime"` // runc, runsc (gVisor)

	// Limits
	MemoryMB        int               `json:"memory_mb"`
	CPULimit        float64           `json:"cpu_limit"`
	TimeoutSec      int               `json:"timeout_sec"`
	MaxPIDs         int               `json:"max_pids"`

	// Security
	NetworkPolicy   string            `json:"network_policy"` // none, restricted, allowed
	FilesystemMode  string            `json:"filesystem_mode"` // readonly, restricted, writable

	// Entry
	EntryPoint      string            `json:"entry_point"`
	Command         []string          `json:"command"`
	WorkDir         string            `json:"work_dir"`
	Environment     map[string]string `json:"environment,omitempty"`
}

// ReportSummary contains the overall assessment
type ReportSummary struct {
	Verdict         string   `json:"verdict"` // safe, caution, unsafe, blocked
	VerdictReason   string   `json:"verdict_reason"`
	Confidence      float64  `json:"confidence"`
	RiskFactors     []string `json:"risk_factors,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`

	// Scores
	SecurityScore   int      `json:"security_score"`   // 0-100 (higher = safer)
	ComplexityScore int      `json:"complexity_score"` // 0-100 (higher = more complex)
	TrustScore      int      `json:"trust_score"`      // 0-100 (higher = more trustworthy)
}

// ToJSON converts the report to JSON
func (r *AnalysisReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToJSONCompact converts the report to compact JSON
func (r *AnalysisReport) ToJSONCompact() ([]byte, error) {
	return json.Marshal(r)
}

// NewAnalysisReport creates a new report with defaults
func NewAnalysisReport(reportID string) *AnalysisReport {
	return &AnalysisReport{
		ReportID:    reportID,
		GeneratedAt: time.Now(),
		Version:     "1.0",
		Code: CodeAnalysis{
			Frameworks:  []string{},
			EntryPoints: []EntryPoint{},
			Imports:     []ImportInfo{},
		},
		Security: SecurityAssessment{
			Findings: []SecurityIssue{},
		},
		Dependencies: DependencyAnalysis{
			Dependencies: []DependencyInfo{},
		},
	}
}

// VerdictFromRisk determines verdict from risk level
func VerdictFromRisk(riskLevel string, requiresReview bool) string {
	switch riskLevel {
	case "none", "low":
		if requiresReview {
			return "caution"
		}
		return "safe"
	case "medium":
		return "caution"
	case "high":
		return "unsafe"
	case "critical":
		return "blocked"
	default:
		return "caution"
	}
}
