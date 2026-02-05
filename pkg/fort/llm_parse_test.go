package fort

import "testing"

func TestParseAnalysisResult_ObjectRiskShape(t *testing.T) {
	content := `{
		"detected_language":"python",
		"detected_runtime":"python3.11",
		"detected_frameworks":["requests"],
		"inferred_dependencies":[{"name":"requests","version":"2.31.0","source":"pip"}],
		"complexity":{"level":"moderate","estimated_runtime":"< 1 second"},
		"potential_risks":{"network":"external calls","injection":"dynamic input usage"},
		"requires_review":true,
		"summary":"test",
		"detected_entry_points":[{"name":"main"}]
	}`

	result, err := parseAnalysisResult(content)
	if err != nil {
		t.Fatalf("parseAnalysisResult returned error: %v", err)
	}
	if result.DetectedLanguage != "python" {
		t.Fatalf("unexpected language: %s", result.DetectedLanguage)
	}
	if len(result.PotentialRisks) == 0 {
		t.Fatalf("expected parsed risks from object shape")
	}
	if result.RecommendedEntry == "" {
		t.Fatalf("expected recommended entry to be inferred from entry points")
	}
	if result.Complexity != ComplexityModerate {
		t.Fatalf("unexpected complexity: %s", result.Complexity)
	}
}
