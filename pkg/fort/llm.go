package fort

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sashabaranov/go-openai"
)

// LLMClient abstracts LLM interactions for code analysis
type LLMClient interface {
	Analyze(ctx context.Context, code, language, purpose string) (*AnalysisResult, error)
	Synthesize(ctx context.Context, code string, analysis *AnalysisResult) (*SynthesisResult, error)
	Validate(ctx context.Context, code string, analysis *AnalysisResult, synthesis *SynthesisResult, policy *SecurityPolicy) (*ValidationResult, error)
}

// OpenAILLMClient implements LLMClient using OpenAI API
type OpenAILLMClient struct {
	client  *openai.Client
	model   string
	baseURL string
}

// NewOpenAILLMClient creates an OpenAI-based LLM client
func NewOpenAILLMClient(apiKey, model string) *OpenAILLMClient {
	return &OpenAILLMClient{
		client: openai.NewClient(apiKey),
		model:  model,
	}
}

// NewOpenAILLMClientWithBaseURL creates an OpenAI-compatible LLM client with custom base URL
func NewOpenAILLMClientWithBaseURL(apiKey, model, baseURL string) *OpenAILLMClient {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = baseURL
	return &OpenAILLMClient{
		client:  openai.NewClientWithConfig(config),
		model:   model,
		baseURL: baseURL,
	}
}

// Analyze performs code analysis using LLM
func (c *OpenAILLMClient) Analyze(ctx context.Context, code, language, purpose string) (*AnalysisResult, error) {
	systemPrompt := `You are an expert code analyzer. Analyze the provided code and return a JSON object with these fields:
- detected_language: the programming language
- detected_runtime: the runtime environment (e.g., python3.11, node18, go1.21)
- detected_frameworks: list of detected frameworks/libraries
- inferred_dependencies: list of {name, version, source} objects for required packages
- complexity: one of "trivial", "simple", "moderate", "complex", "extreme"
- estimated_runtime: human-readable estimate like "< 1 second", "1-5 seconds", etc.
- potential_risks: list of security/safety concerns
- requires_review: boolean if human review is recommended
- summary: brief description of what the code does
- detected_entry_points: list of possible entry points (main functions, etc.)
- recommended_entry: the recommended entry point to execute

Return ONLY valid JSON, no markdown or explanation.`

	userPrompt := fmt.Sprintf("Analyze this code:\n\n```\n%s\n```", code)
	if language != "" {
		userPrompt += fmt.Sprintf("\n\nLanguage hint: %s", language)
	}
	if purpose != "" {
		userPrompt += fmt.Sprintf("\n\nIntended purpose: %s", purpose)
	}

	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userPrompt},
		},
		Temperature: 0.1,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no response from LLM")
	}

	var result AnalysisResult
	content := resp.Choices[0].Message.Content
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return &result, nil
}

// Synthesize generates container configuration using LLM
func (c *OpenAILLMClient) Synthesize(ctx context.Context, code string, analysis *AnalysisResult) (*SynthesisResult, error) {
	systemPrompt := `You are an expert at creating minimal, secure Docker containers for code execution.
Generate a JSON object with these fields:
- base_image: minimal base image (prefer alpine/slim variants, e.g., python:3.11-slim-bookworm)
- dockerfile: complete Dockerfile content with security best practices (non-root user, minimal packages)
- entry_script: optional shell script to run the code
- setup_script: optional script for any pre-execution setup
- run_command: array of command and arguments to execute the code
- work_dir: working directory in container
- environment_vars: map of environment variables
- build_args: list of build arguments
- recommended_memory_mb: suggested memory limit
- recommended_cpu: suggested CPU limit (1.0 = 1 core)
- recommended_timeout_sec: suggested timeout

Security requirements:
- Use non-root user
- Minimize installed packages
- Set appropriate file permissions
- Don't expose unnecessary ports

Return ONLY valid JSON, no markdown.`

	analysisJSON, _ := json.Marshal(analysis)
	userPrompt := fmt.Sprintf("Generate container config for this code:\n\n```\n%s\n```\n\nAnalysis:\n%s", code, string(analysisJSON))

	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userPrompt},
		},
		Temperature: 0.1,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no response from LLM")
	}

	var result SynthesisResult
	content := resp.Choices[0].Message.Content
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return &result, nil
}

// Validate performs security validation using LLM
func (c *OpenAILLMClient) Validate(ctx context.Context, code string, analysis *AnalysisResult, synthesis *SynthesisResult, policy *SecurityPolicy) (*ValidationResult, error) {
	systemPrompt := `You are an expert security analyst. Review the code for security issues.
Return a JSON object with these fields:
- safe: boolean indicating if the code is safe to execute
- risk_level: one of "none", "low", "medium", "high", "critical"
- confidence: 0.0-1.0 confidence in your assessment
- findings: list of {category, severity, description, location, evidence, mitigated, mitigation}
- policy_violations: list of {policy, description, severity} for policy violations
- recommendations: list of security recommendations
- rejection_reason: if not safe, explain why (empty string if safe)
- review_notes: any additional notes for human reviewers

Categories to check:
- Command injection, code injection
- File system access violations
- Network access violations
- Crypto mining indicators
- Data exfiltration attempts
- Reverse shells
- Privilege escalation
- Resource abuse

Return ONLY valid JSON, no markdown.`

	analysisJSON, _ := json.Marshal(analysis)
	policyJSON, _ := json.Marshal(policy)
	userPrompt := fmt.Sprintf("Validate this code:\n\n```\n%s\n```\n\nAnalysis:\n%s\n\nPolicy:\n%s", code, string(analysisJSON), string(policyJSON))

	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userPrompt},
		},
		Temperature: 0.1,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no response from LLM")
	}

	var result ValidationResult
	content := resp.Choices[0].Message.Content
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return &result, nil
}
