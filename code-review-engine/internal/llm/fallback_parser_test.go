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
		{
			name: "Natural language Task Done",
			content: "### Final Thoughts\nThere are no critical or high issues identified in this file.\n### Task Done\nNo further issues were identified in this file. Moving on.",
			wantName:     "task_done",
			wantMinCalls: 1,
		},
		{
			name: "Function current_comment alias",
			content: "```json\n{\n  \"function\": \"current_comment\",\n  \"arguments\": {\n    \"comments\": [{\"content\": \"Leak\", \"existing_code\": \"malloc()\"}]\n  }\n}\n```",
			wantName:     "code_comment",
			wantMinCalls: 1,
		},
		{
			name: "Markdown findings with task_done fence at the end",
			content: "Let's review the code:\n\n### Finding 1: Stack Buffer Overflow\n**Location**:\n```c\nstrcpy(buf, input);\n```\n**Severity**: High\n**Description**: Unbounded copy.\n\n### Finding 2: Command Injection\n```c\nsystem(cmd);\n```\n**Severity**: Critical\n\nCalling `task_done` to complete.\n```json\n{\n  \"name\": \"task_done\",\n  \"arguments\": {\"comment\": \"DONE\"}\n}\n```",
			wantName:     "code_comment",
			wantMinCalls: 1,
		},
		{
			name: "Session 84cc68cf malformed JSON with semicolons and braces in C code",
			content: "```json\n{\n  \"name\": \"code_comment\",\n  \"arguments\": {\n    \"comments\": [\n       {\n           \"comment\": \"Critical Stack Buffer Overflow (CWE-120)\",\n           \"existing_code\": \"void process_user_input(const char *user_payload) {\\n    char stack_buffer[64];\\n    strcpy(stack_buffer, user_payload);\\n}\",\n           \"category\": \"security\",\n           \"severity\": \"critical\",\n           \"path\": \"<current_file_path>\"\n       },\n       {\n           \"comment\": \"Critical Remote file Injection (CWE-78)\";\n           \"existingcode\": \"int execute_system_command(const char *domain_name) {\\n    system(command_buffer);\\n}\",\n           \"category\": \"security\",\n           \"severity\": \"critical\",\n           \"path\": \"<current_file_path>\"\n       }\n     ]\n   }\n}\n}\n```",
			wantName:     "code_comment",
			wantMinCalls: 1,
		},
		{
			name: "Session 14be6cdc function: code_comment with invalid escape in string",
			content: "```json\n{\n  \"function\": \"code_comment\",\n  \"arguments\": {\n    \"comments\": [\n       {\n           \"comment\": \"Critical Stack Buffer Overflow (CWE-120)\",\n           \"existing_code\": \"void process_user_input(const char *user_payload) {\\n    strcpy(stack_buffer, user_payload);\\n}\",\n           \"category\": \"security\",\n           \"severity\": \"critical\",\n           \"path\": \"<current_file_path>\"\n       }\n     ]\n   }\n}\n```",
			wantName:     "code_comment",
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
