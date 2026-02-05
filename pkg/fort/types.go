package fort

import "time"

// SourceType defines how the code was provided
type SourceType string

const (
	SourceInline  SourceType = "inline"
	SourceFile    SourceType = "file"
	SourceArchive SourceType = "archive"
	SourceGit     SourceType = "git"
)

// ExecStatus tracks execution lifecycle
type ExecStatus string

const (
	StatusPending    ExecStatus = "pending"
	StatusAnalyzing  ExecStatus = "analyzing"
	StatusValidating ExecStatus = "validating"
	StatusBuilding   ExecStatus = "building"
	StatusExecuting  ExecStatus = "executing"
	StatusCompleted  ExecStatus = "completed"
	StatusFailed     ExecStatus = "failed"
	StatusRejected   ExecStatus = "rejected"
	StatusKilled     ExecStatus = "killed"
)

// Phase tracks execution pipeline stage
type Phase string

const (
	PhaseAnalysis   Phase = "analysis"
	PhaseSynthesis  Phase = "synthesis"
	PhaseValidation Phase = "validation"
	PhaseBuild      Phase = "build"
	PhaseExecution  Phase = "execution"
	PhaseComplete   Phase = "complete"
)

// RiskLevel indicates security risk severity
type RiskLevel string

const (
	RiskNone     RiskLevel = "none"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// Complexity indicates code complexity level
type Complexity string

const (
	ComplexityTrivial  Complexity = "trivial"
	ComplexitySimple   Complexity = "simple"
	ComplexityModerate Complexity = "moderate"
	ComplexityComplex  Complexity = "complex"
	ComplexityExtreme  Complexity = "extreme"
)

// Request represents a code execution request
type Request struct {
	ID            string            `json:"id"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	SubmittedBy   string            `json:"submitted_by"`
	SourceType    SourceType        `json:"source_type"`
	SourceContent string            `json:"source_content"`
	Language      string            `json:"language,omitempty"`
	Purpose       string            `json:"purpose,omitempty"`
	MaxTimeoutSec int               `json:"max_timeout_sec,omitempty"`
	MaxMemoryMB   int               `json:"max_memory_mb,omitempty"`
	MaxCPU        float64           `json:"max_cpu,omitempty"`
	AllowNetwork  bool              `json:"allow_network,omitempty"`
	SecurityPolicy SecurityPolicy   `json:"security_policy,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Status        ExecStatus        `json:"status"`
	CurrentPhase  Phase             `json:"current_phase"`
}

// SecurityPolicy defines execution security constraints
type SecurityPolicy struct {
	AllowNetwork       bool     `json:"allow_network"`
	AllowFileWrite     bool     `json:"allow_file_write"`
	AllowFileRead      bool     `json:"allow_file_read"`
	AllowedPaths       []string `json:"allowed_paths,omitempty"`
	BlockedPaths       []string `json:"blocked_paths,omitempty"`
	AllowedDomains     []string `json:"allowed_domains,omitempty"`
	BlockedDomains     []string `json:"blocked_domains,omitempty"`
	MaxMemoryMB        int      `json:"max_memory_mb,omitempty"`
	MaxCPU             float64  `json:"max_cpu,omitempty"`
	MaxTimeoutSec      int      `json:"max_timeout_sec,omitempty"`
	MaxOutputBytes     int      `json:"max_output_bytes,omitempty"`
	AllowedLanguages   []string `json:"allowed_languages,omitempty"`
	BlockedPatterns    []string `json:"blocked_patterns,omitempty"`
	RequireApproval    bool     `json:"require_approval,omitempty"`
	SandboxLevel       string   `json:"sandbox_level,omitempty"`
}

// DefaultSecurityPolicy returns a restrictive default policy
func DefaultSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		AllowNetwork:   false,
		AllowFileWrite: false,
		AllowFileRead:  true,
		MaxMemoryMB:    256,
		MaxCPU:         1.0,
		MaxTimeoutSec:  60,
		MaxOutputBytes: 100 * 1024,
		SandboxLevel:   "strict",
	}
}

// Execution tracks a complete execution lifecycle
type Execution struct {
	Request    Request          `json:"request"`
	Phases     []PhaseRecord    `json:"phases"`
	Analysis   *AnalysisResult  `json:"analysis,omitempty"`
	Synthesis  *SynthesisResult `json:"synthesis,omitempty"`
	Validation *ValidationResult `json:"validation,omitempty"`
	Result     *ExecResult      `json:"result,omitempty"`
}

// PhaseRecord tracks timing/status for each pipeline phase
type PhaseRecord struct {
	Phase     Phase      `json:"phase"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Success   bool       `json:"success"`
	Error     string     `json:"error,omitempty"`
}

// AnalysisResult contains code analysis output
type AnalysisResult struct {
	DetectedLanguage     string           `json:"detected_language"`
	DetectedRuntime      string           `json:"detected_runtime"`
	DetectedFrameworks   []string         `json:"detected_frameworks,omitempty"`
	InferredDependencies []Dependency     `json:"inferred_dependencies,omitempty"`
	Complexity           Complexity       `json:"complexity"`
	EstimatedRuntime     string           `json:"estimated_runtime"`
	PotentialRisks       []string         `json:"potential_risks,omitempty"`
	RequiresReview       bool             `json:"requires_review"`
	Summary              string           `json:"summary"`
	DetectedEntryPoints  []string         `json:"detected_entry_points,omitempty"`
	RecommendedEntry     string           `json:"recommended_entry,omitempty"`
}

// Dependency represents an inferred package dependency
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"`
}

// SynthesisResult contains container synthesis output
type SynthesisResult struct {
	BaseImage           string            `json:"base_image"`
	Dockerfile          string            `json:"dockerfile"`
	EntryScript         string            `json:"entry_script,omitempty"`
	SetupScript         string            `json:"setup_script,omitempty"`
	RunCommand          []string          `json:"run_command"`
	WorkDir             string            `json:"work_dir"`
	EnvironmentVars     map[string]string `json:"environment_vars,omitempty"`
	BuildArgs           []string          `json:"build_args,omitempty"`
	RecommendedMemoryMB int               `json:"recommended_memory_mb"`
	RecommendedCPU      float64           `json:"recommended_cpu"`
	RecommendedTimeout  int               `json:"recommended_timeout_sec"`
}

// ValidationResult contains security validation output
type ValidationResult struct {
	Safe             bool                `json:"safe"`
	RiskLevel        RiskLevel           `json:"risk_level"`
	Confidence       float64             `json:"confidence"`
	Findings         []SecurityFinding   `json:"findings,omitempty"`
	PolicyViolations []PolicyViolation   `json:"policy_violations,omitempty"`
	Recommendations  []string            `json:"recommendations,omitempty"`
	RejectionReason  string              `json:"rejection_reason,omitempty"`
	ReviewNotes      string              `json:"review_notes,omitempty"`
}

// SecurityFinding represents a detected security issue
type SecurityFinding struct {
	Category    string    `json:"category"`
	Severity    RiskLevel `json:"severity"`
	Description string    `json:"description"`
	Location    string    `json:"location,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	Mitigated   bool      `json:"mitigated,omitempty"`
	Mitigation  string    `json:"mitigation,omitempty"`
}

// PolicyViolation represents a security policy violation
type PolicyViolation struct {
	Policy      string `json:"policy"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// ExecResult contains execution output
type ExecResult struct {
	RequestID    string    `json:"request_id"`
	CompletedAt  time.Time `json:"completed_at"`
	Success      bool      `json:"success"`
	ExitCode     int       `json:"exit_code"`
	Stdout       string    `json:"stdout"`
	Stderr       string    `json:"stderr"`
	MemoryUsedMB int       `json:"memory_used_mb,omitempty"`
	CPUTimeMs    int64     `json:"cpu_time_ms,omitempty"`
	WallTimeMs   int64     `json:"wall_time_ms"`
	TimedOut     bool      `json:"timed_out,omitempty"`
	Killed       bool      `json:"killed,omitempty"`
	KillReason   string    `json:"kill_reason,omitempty"`
	ContainerID  string    `json:"container_id,omitempty"`
	ImageID      string    `json:"image_id,omitempty"`
}
