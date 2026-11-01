package llm

import (
	"testing"
)

func TestExtractFallbackToolCalls(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		wantName     string
		wantMinCalls int
	}{
		{
			name: "Anthropic XML code_comment",
			content: "```xml\n<code_comment>\n    {\n        \"comments\": [\n            {\n                \"line\": 1,\n                \"text\": \"The variable 'x' is exported but not used anywhere in the module.\"\n            }\n        ]\n    }\n</code_comment>\n```",
			wantName:     "code_comment",
			wantMinCalls: 1,
		},
		{
			name: "OpenAI JSON code_comment",
			content: "```json\n{\n  \"name\": \"code_comment\",\n  \"arguments\": {\n    \"comments\": [\n      {\n        \"content\": \"Improve clarity\",\n        \"existing_code\": \"const x = 1;\"\n      }\n    ]\n  }\n}\n```",
			wantName:     "code_comment",
			wantMinCalls: 1,
		},
		{
			name: "task_done XML",
			content: "<task_done>{\"state\": \"DONE\"}</task_done>",
			wantName:     "task_done",
			wantMinCalls: 1,
		},
		{
			name: "task_done empty XML",
			content: "<task_done></task_done>",
			wantName:     "task_done",
			wantMinCalls: 1,
		},
		{
			name: "Raw JSON task_done",
			content: `{"name": "task_done", "state": "DONE"}`,
			wantName:     "task_done",
			wantMinCalls: 1,
		},
		{
			name: "hermes tool_call tag",
			content: "<tool_call>\n{\"name\": \"task_done\", \"arguments\": {\"state\": \"DONE\"}}\n</tool_call>",
			wantName:     "task_done",
			wantMinCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFallbackToolCalls(tt.content)
			if len(got) < tt.wantMinCalls {
				t.Fatalf("expected at least %d calls, got %d", tt.wantMinCalls, len(got))
			}
			if got[0].Function.Name != tt.wantName {
				t.Errorf("expected tool name %s, got %s", tt.wantName, got[0].Function.Name)
			}
		})
	}
}
