package fort

import (
	"context"
	"math"
	"regexp"
	"strings"
)

// Analyzer performs code analysis
type Analyzer struct {
	llm LLMClient
}

// NewAnalyzer creates a new Analyzer
func NewAnalyzer(llm LLMClient) *Analyzer {
	return &Analyzer{llm: llm}
}

// Analyze analyzes code and returns analysis results
func (a *Analyzer) Analyze(ctx context.Context, req *Request) (*AnalysisResult, error) {
	// Pre-analysis: Quick pattern-based checks
	preAnalysis := a.preAnalyze(req.SourceContent, req.Language)

	// LLM-based deep analysis
	result, err := a.llm.Analyze(ctx, req.SourceContent, req.Language, req.Purpose)
	if err != nil {
		return nil, err
	}

	// Merge pre-analysis findings
	result.PotentialRisks = append(result.PotentialRisks, preAnalysis.risks...)
	if preAnalysis.language != "" && result.DetectedLanguage == "" {
		result.DetectedLanguage = preAnalysis.language
	}

	// Override requires_review if we found critical patterns
	if preAnalysis.requiresReview {
		result.RequiresReview = true
	}

	return result, nil
}

type preAnalysisResult struct {
	language       string
	risks          []string
	requiresReview bool
}

// preAnalyze performs quick pattern-based analysis
func (a *Analyzer) preAnalyze(code, languageHint string) preAnalysisResult {
	result := preAnalysisResult{}

	// Detect language from patterns if not provided
	if languageHint == "" {
		result.language = detectLanguage(code)
	} else {
		result.language = languageHint
	}

	// Check for dangerous patterns
	dangerousPatterns := []struct {
		pattern *regexp.Regexp
		risk    string
	}{
		{regexp.MustCompile(`(?i)os\s*\.\s*system|subprocess|exec\s*\(`), "System command execution detected"},
		{regexp.MustCompile(`(?i)eval\s*\(|exec\s*\(`), "Dynamic code execution detected"},
		{regexp.MustCompile(`(?i)socket\s*\.\s*socket|connect\s*\(`), "Network socket usage detected"},
		{regexp.MustCompile(`(?i)(rm|del|remove)\s+(-rf?|/s)?\s*/`), "Dangerous file deletion pattern"},
		{regexp.MustCompile(`(?i)base64\.(b64)?decode|atob\s*\(`), "Base64 decoding (potential obfuscation)"},
		{regexp.MustCompile(`(?i)crypto|miner|hashrate|stratum`), "Potential crypto mining indicators"},
		{regexp.MustCompile(`(?i)/dev/tcp|nc\s+-|bash\s+-i`), "Potential reverse shell pattern"},
		{regexp.MustCompile(`(?i)chmod\s+[0-7]*7[0-7]*|chmod\s+\+x`), "Permission modification detected"},
		{regexp.MustCompile(`(?i)curl|wget|requests\.get|fetch\s*\(`), "Network request detected"},
		{regexp.MustCompile(`(?i)/etc/passwd|/etc/shadow|\.ssh/`), "Sensitive file access attempt"},
	}

	for _, dp := range dangerousPatterns {
		if dp.pattern.MatchString(code) {
			result.risks = append(result.risks, dp.risk)
		}
	}

	// Check for obfuscation indicators
	if isLikelyObfuscated(code) {
		result.risks = append(result.risks, "Code appears to be obfuscated")
		result.requiresReview = true
	}

	// Require review if multiple risks found
	if len(result.risks) >= 3 {
		result.requiresReview = true
	}

	return result
}

// detectLanguage attempts to detect programming language from code patterns
func detectLanguage(code string) string {
	patterns := map[string]*regexp.Regexp{
		"python":     regexp.MustCompile(`(?m)^(import\s+\w+|from\s+\w+\s+import|def\s+\w+\s*\(|class\s+\w+\s*[:\(])`),
		"javascript": regexp.MustCompile(`(?m)^(const|let|var|function|import\s+.*\s+from|export\s+(default\s+)?)`),
		"typescript": regexp.MustCompile(`(?m)^(interface\s+\w+|type\s+\w+\s*=|:\s*(string|number|boolean|any)\s*[;,\)])`),
		"go":         regexp.MustCompile(`(?m)^(package\s+\w+|func\s+\w+|import\s+\(|type\s+\w+\s+struct)`),
		"rust":       regexp.MustCompile(`(?m)^(fn\s+\w+|use\s+\w+|impl\s+\w+|let\s+mut\s+)`),
		"ruby":       regexp.MustCompile(`(?m)^(require\s+['"]|def\s+\w+|class\s+\w+\s*<?\s*\w*$|end$)`),
		"java":       regexp.MustCompile(`(?m)^(public\s+class|private\s+|import\s+java\.)`),
		"cpp":        regexp.MustCompile(`(?m)^(#include\s*<|using\s+namespace|int\s+main\s*\()`),
		"c":          regexp.MustCompile(`(?m)^(#include\s*<|int\s+main\s*\(|void\s+\w+\s*\()`),
		"shell":      regexp.MustCompile(`(?m)^(#!/bin/(ba)?sh|#!/usr/bin/env\s+(ba)?sh|\$\{?\w+\}?=)`),
	}

	maxScore := 0
	detected := ""
	for lang, pattern := range patterns {
		matches := pattern.FindAllString(code, -1)
		if len(matches) > maxScore {
			maxScore = len(matches)
			detected = lang
		}
	}

	return detected
}

// isLikelyObfuscated checks if code appears to be obfuscated
func isLikelyObfuscated(code string) bool {
	// Check for high entropy (compressed/encoded data)
	entropy := calculateEntropy(code)
	if entropy > 5.5 {
		return true
	}

	// Check for excessive hex/base64 strings
	hexPattern := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	if len(hexPattern.FindAllString(code, -1)) > 20 {
		return true
	}

	// Check for very long single lines (minified/obfuscated)
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		if len(line) > 500 && !strings.HasPrefix(strings.TrimSpace(line), "//") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			return true
		}
	}

	return false
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}
