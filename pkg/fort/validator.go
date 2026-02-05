package fort

import (
	"context"
	"regexp"
	"strings"
)

// Validator performs security validation
type Validator struct {
	llm LLMClient
}

// NewValidator creates a new Validator
func NewValidator(llm LLMClient) *Validator {
	return &Validator{llm: llm}
}

// Validate performs security validation on code
func (v *Validator) Validate(ctx context.Context, req *Request, analysis *AnalysisResult, synthesis *SynthesisResult) (*ValidationResult, error) {
	policy := &req.SecurityPolicy
	if policy.MaxMemoryMB == 0 {
		defaultPolicy := DefaultSecurityPolicy()
		policy = &defaultPolicy
	}

	// Static analysis (fast, no LLM)
	staticFindings := v.staticAnalysis(req.SourceContent, policy)

	// LLM-based deep validation
	llmResult, err := v.llm.Validate(ctx, req.SourceContent, analysis, synthesis, policy)
	if err != nil {
		// If LLM fails, use static analysis only
		return v.staticOnlyResult(staticFindings, policy), nil
	}

	// Merge findings
	llmResult.Findings = append(staticFindings, llmResult.Findings...)

	// Recalculate safety based on all findings
	v.recalculateSafety(llmResult, policy)

	return llmResult, nil
}

// staticAnalysis performs pattern-based security checks
func (v *Validator) staticAnalysis(code string, policy *SecurityPolicy) []SecurityFinding {
	var findings []SecurityFinding

	patterns := []struct {
		pattern  *regexp.Regexp
		category string
		severity RiskLevel
		desc     string
	}{
		// Critical patterns
		{regexp.MustCompile(`(?i)reverse.?shell`), "network", RiskCritical, "Reverse shell pattern detected"},
		{regexp.MustCompile(`(?i)/dev/tcp/|nc\s+-[elp]|bash\s+-i\s*>&?\s*/dev/`), "network", RiskCritical, "Shell reverse connection pattern"},
		{regexp.MustCompile(`(?i)mkfifo|mknod.*p\s+`), "network", RiskCritical, "Named pipe creation (potential reverse shell)"},
		{regexp.MustCompile(`(?i)xmrig|minergate|cryptonight|stratum\+tcp`), "mining", RiskCritical, "Crypto mining indicator"},
		{regexp.MustCompile(`(?i)rm\s+(-rf?|--recursive).*(/\s*$|/etc|/var|/usr|/home|\$HOME)`), "filesystem", RiskCritical, "Dangerous recursive deletion"},
		{regexp.MustCompile(`(?i):(){ :|:& };:|fork.*bomb`), "resource", RiskCritical, "Fork bomb pattern"},

		// High severity
		{regexp.MustCompile(`(?i)subprocess\.(call|run|Popen).*shell\s*=\s*True`), "injection", RiskHigh, "Shell injection risk via subprocess"},
		{regexp.MustCompile(`(?i)os\.system\s*\([^)]*\$|os\.system\s*\([^)]*\+`), "injection", RiskHigh, "Command injection via os.system"},
		{regexp.MustCompile(`(?i)eval\s*\(\s*(request|input|raw_input|sys\.argv)`), "injection", RiskHigh, "Code injection via eval"},
		{regexp.MustCompile(`(?i)exec\s*\(\s*(request|input|compile)`), "injection", RiskHigh, "Code injection via exec"},
		{regexp.MustCompile(`(?i)/etc/passwd|/etc/shadow|/etc/sudoers`), "filesystem", RiskHigh, "Sensitive file access attempt"},
		{regexp.MustCompile(`(?i)\.ssh/|id_rsa|authorized_keys`), "filesystem", RiskHigh, "SSH key access attempt"},
		{regexp.MustCompile(`(?i)chmod\s+[0-7]*7[0-7]*[0-7]|chmod\s+777`), "permissions", RiskHigh, "Overly permissive file permissions"},
		{regexp.MustCompile(`(?i)setuid|setgid|chown\s+root`), "permissions", RiskHigh, "Privilege escalation attempt"},
		{regexp.MustCompile(`(?i)socket\.socket.*SOCK_RAW`), "network", RiskHigh, "Raw socket creation"},
		{regexp.MustCompile(`(?i)scapy|raw.*socket|packet.*craft`), "network", RiskHigh, "Packet crafting library"},

		// Medium severity
		{regexp.MustCompile(`(?i)pickle\.loads?|marshal\.loads?|yaml\.load\(`), "deserialization", RiskMedium, "Unsafe deserialization"},
		{regexp.MustCompile(`(?i)__import__|importlib\.import_module`), "injection", RiskMedium, "Dynamic import (potential code injection)"},
		{regexp.MustCompile(`(?i)ctypes|cffi|ffi`), "native", RiskMedium, "Native code interface"},
		{regexp.MustCompile(`(?i)multiprocessing\.Process|threading\.Thread`), "resource", RiskMedium, "Process/thread creation"},
		{regexp.MustCompile(`(?i)tempfile\.|/tmp/|/var/tmp/`), "filesystem", RiskMedium, "Temporary file usage"},
		{regexp.MustCompile(`(?i)sqlite3\.connect|psycopg2|mysql|pymongo`), "database", RiskMedium, "Database connection"},
		{regexp.MustCompile(`(?i)smtplib|sendmail|mail\s*\(`), "network", RiskMedium, "Email sending capability"},
		{regexp.MustCompile(`(?i)ftplib|paramiko|ssh|sftp`), "network", RiskMedium, "Remote file transfer"},

		// Low severity (informational)
		{regexp.MustCompile(`(?i)requests\.(get|post|put|delete)|urllib|http\.client`), "network", RiskLow, "HTTP request capability"},
		{regexp.MustCompile(`(?i)open\s*\([^)]*,\s*['"]w`), "filesystem", RiskLow, "File write operation"},
		{regexp.MustCompile(`(?i)base64\.(b64)?decode|binascii`), "encoding", RiskLow, "Base64 decoding"},
		{regexp.MustCompile(`(?i)hashlib|cryptography|Crypto\.|pycryptodome`), "crypto", RiskLow, "Cryptographic operations"},
		{regexp.MustCompile(`(?i)getenv|environ\[|os\.environ`), "environment", RiskLow, "Environment variable access"},
		{regexp.MustCompile(`(?i)logging\.(debug|info|warning|error)`), "logging", RiskLow, "Logging operations"},
	}

	for _, p := range patterns {
		if matches := p.pattern.FindAllString(code, -1); len(matches) > 0 {
			evidence := matches[0]
			if len(evidence) > 100 {
				evidence = evidence[:100] + "..."
			}

			// Check if mitigated by policy
			mitigated := false
			mitigation := ""
			if p.category == "network" && !policy.AllowNetwork {
				mitigated = true
				mitigation = "Network access is disabled in sandbox"
			}
			if p.category == "filesystem" && !policy.AllowFileWrite {
				mitigated = true
				mitigation = "File write access is disabled in sandbox"
			}

			findings = append(findings, SecurityFinding{
				Category:    p.category,
				Severity:    p.severity,
				Description: p.desc,
				Evidence:    evidence,
				Mitigated:   mitigated,
				Mitigation:  mitigation,
			})
		}
	}

	// Check for policy-specific violations
	if !policy.AllowNetwork {
		networkPatterns := regexp.MustCompile(`(?i)socket\.|requests\.|urllib|http\.client|aiohttp|httpx`)
		if networkPatterns.MatchString(code) {
			// Already caught above, but ensure it's flagged as violation
		}
	}

	return findings
}

// staticOnlyResult creates a validation result from static analysis only
func (v *Validator) staticOnlyResult(findings []SecurityFinding, policy *SecurityPolicy) *ValidationResult {
	result := &ValidationResult{
		Safe:       true,
		RiskLevel:  RiskNone,
		Confidence: 0.7, // Lower confidence without LLM
		Findings:   findings,
	}

	v.recalculateSafety(result, policy)
	return result
}

// recalculateSafety recalculates safety based on all findings
func (v *Validator) recalculateSafety(result *ValidationResult, policy *SecurityPolicy) {
	highestRisk := RiskNone
	var unmitigatedCritical, unmitigatedHigh int

	for _, f := range result.Findings {
		if f.Mitigated {
			continue
		}

		switch f.Severity {
		case RiskCritical:
			unmitigatedCritical++
			highestRisk = RiskCritical
		case RiskHigh:
			unmitigatedHigh++
			if highestRisk != RiskCritical {
				highestRisk = RiskHigh
			}
		case RiskMedium:
			if highestRisk != RiskCritical && highestRisk != RiskHigh {
				highestRisk = RiskMedium
			}
		case RiskLow:
			if highestRisk == RiskNone {
				highestRisk = RiskLow
			}
		}
	}

	result.RiskLevel = highestRisk

	// Determine safety
	if unmitigatedCritical > 0 {
		result.Safe = false
		result.RejectionReason = "Critical security issues detected"
	} else if unmitigatedHigh >= 3 {
		result.Safe = false
		result.RejectionReason = "Multiple high-severity security issues detected"
	} else if highestRisk == RiskCritical || highestRisk == RiskHigh {
		// Single high-risk finding might be acceptable depending on policy
		if policy.RequireApproval {
			result.Safe = false
			result.RejectionReason = "High-risk code requires manual approval"
		}
	}

	// Add recommendations based on findings
	v.addRecommendations(result)
}

// addRecommendations adds security recommendations based on findings
func (v *Validator) addRecommendations(result *ValidationResult) {
	categories := make(map[string]bool)
	for _, f := range result.Findings {
		categories[f.Category] = true
	}

	if categories["injection"] {
		result.Recommendations = append(result.Recommendations, "Avoid dynamic code execution (eval, exec). Use safer alternatives.")
	}
	if categories["network"] {
		result.Recommendations = append(result.Recommendations, "Network access detected. Ensure only trusted endpoints are contacted.")
	}
	if categories["filesystem"] {
		result.Recommendations = append(result.Recommendations, "File system operations detected. Use absolute paths and validate inputs.")
	}
	if categories["deserialization"] {
		result.Recommendations = append(result.Recommendations, "Use safe deserialization methods (e.g., json instead of pickle).")
	}
	if categories["permissions"] {
		result.Recommendations = append(result.Recommendations, "Avoid changing file permissions. Run with minimal privileges.")
	}
}

// CheckPolicyViolations checks code against security policy
func (v *Validator) CheckPolicyViolations(code string, policy *SecurityPolicy) []PolicyViolation {
	var violations []PolicyViolation

	// Check network access
	if !policy.AllowNetwork {
		networkPatterns := regexp.MustCompile(`(?i)socket\.|requests\.|urllib|http\.client|aiohttp|httpx|fetch\(`)
		if networkPatterns.MatchString(code) {
			violations = append(violations, PolicyViolation{
				Policy:      "network_access",
				Description: "Network access is not allowed but code contains network operations",
				Severity:    "high",
			})
		}
	}

	// Check file write
	if !policy.AllowFileWrite {
		writePatterns := regexp.MustCompile(`(?i)open\s*\([^)]*['"][wa]|\.write\s*\(|shutil\.(copy|move)|os\.(rename|remove)`)
		if writePatterns.MatchString(code) {
			violations = append(violations, PolicyViolation{
				Policy:      "file_write",
				Description: "File write is not allowed but code contains write operations",
				Severity:    "high",
			})
		}
	}

	// Check blocked patterns
	for _, pattern := range policy.BlockedPatterns {
		if regexp.MustCompile(pattern).MatchString(code) {
			violations = append(violations, PolicyViolation{
				Policy:      "blocked_pattern",
				Description: "Code matches blocked pattern: " + pattern,
				Severity:    "critical",
			})
		}
	}

	// Check language restrictions
	if len(policy.AllowedLanguages) > 0 {
		// This would require language detection
		// For now, skip this check as it's handled at analysis phase
	}

	return violations
}

// QuickValidate performs fast static-only validation
func QuickValidate(code string, policy *SecurityPolicy) (bool, []SecurityFinding) {
	if policy == nil {
		defaultPolicy := DefaultSecurityPolicy()
		policy = &defaultPolicy
	}

	v := &Validator{}
	findings := v.staticAnalysis(code, policy)

	// Determine if safe based on findings
	safe := true
	for _, f := range findings {
		if !f.Mitigated && (f.Severity == RiskCritical || f.Severity == RiskHigh) {
			safe = false
			break
		}
	}

	return safe, findings
}

// IsSafeForExecution performs a quick check if code is safe to execute
func IsSafeForExecution(code string) bool {
	safe, _ := QuickValidate(code, nil)
	return safe
}

// GetRiskLevel returns the highest risk level from findings
func GetRiskLevel(findings []SecurityFinding) RiskLevel {
	highest := RiskNone
	for _, f := range findings {
		if !f.Mitigated {
			switch f.Severity {
			case RiskCritical:
				return RiskCritical
			case RiskHigh:
				highest = RiskHigh
			case RiskMedium:
				if highest != RiskHigh {
					highest = RiskMedium
				}
			case RiskLow:
				if highest == RiskNone {
					highest = RiskLow
				}
			}
		}
	}
	return highest
}

// FilterFindingsBySeverity returns findings matching given severity
func FilterFindingsBySeverity(findings []SecurityFinding, severity RiskLevel) []SecurityFinding {
	var filtered []SecurityFinding
	for _, f := range findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// FormatFindings returns a human-readable summary of findings
func FormatFindings(findings []SecurityFinding) string {
	if len(findings) == 0 {
		return "No security issues found"
	}

	var sb strings.Builder
	sb.WriteString("Security findings:\n")

	for i, f := range findings {
		status := ""
		if f.Mitigated {
			status = " (mitigated)"
		}
		sb.WriteString(strings.Repeat(" ", 2))
		sb.WriteString(string(rune('1' + i)))
		sb.WriteString(". [")
		sb.WriteString(string(f.Severity))
		sb.WriteString("] ")
		sb.WriteString(f.Description)
		sb.WriteString(status)
		sb.WriteString("\n")
	}

	return sb.String()
}
