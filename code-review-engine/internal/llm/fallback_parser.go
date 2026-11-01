package llm

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	xmlToolCallRegex = regexp.MustCompile(`(?s)<(tool_call|response|code_comment|task_done|file_read|file_find|file_read_diff|code_search)>\s*(.*?)\s*</(?:tool_call|response|code_comment|task_done|file_read|file_find|file_read_diff|code_search)>`)
	jsonFenceRegex   = regexp.MustCompile("(?s)```(?:json|xml)?\\s*(\\{.*?\\})\\s*```")
)

// ExtractFallbackToolCalls inspects text output for tool calls formatted as XML tags or JSON blocks.
func ExtractFallbackToolCalls(content string) []ToolCall {
	var calls []ToolCall
	cleanContent := stripThinkTags(content)

	// 1. Try matching XML tags
	xmlMatches := xmlToolCallRegex.FindAllStringSubmatch(cleanContent, -1)
	for i, match := range xmlMatches {
		if len(match) < 3 {
			continue
		}
		tag := strings.ToLower(match[1])
		body := strings.TrimSpace(match[2])
		id := fmt.Sprintf("fallback_call_%d_%d", time.Now().UnixNano(), i)

		switch tag {
		case "tool_call", "response":
			var raw map[string]any
			if err := json.Unmarshal([]byte(body), &raw); err == nil {
				name, _ := raw["name"].(string)
				if name != "" {
					argsStr := "{}"
					if argsObj, ok := raw["arguments"]; ok {
						if b, err := json.Marshal(argsObj); err == nil {
							argsStr = string(b)
						}
					} else {
						delete(raw, "name")
						if b, err := json.Marshal(raw); err == nil {
							argsStr = string(b)
						}
					}
					calls = append(calls, ToolCall{
						ID:   id,
						Type: "function",
						Function: FunctionCall{
							Name:      name,
							Arguments: argsStr,
						},
					})
				}
			}
		case "task_done":
			state := "DONE"
			var raw map[string]any
			if err := json.Unmarshal([]byte(body), &raw); err == nil {
				if s, ok := raw["state"].(string); ok && s != "" {
					state = s
				}
			}
			calls = append(calls, ToolCall{
				ID:   id,
				Type: "function",
				Function: FunctionCall{
					Name:      "task_done",
					Arguments: fmt.Sprintf(`{"state":"%s"}`, state),
				},
			})
		case "code_comment":
			argsStr := body
			if !strings.HasPrefix(body, "{") {
				if strings.HasPrefix(body, "[") {
					argsStr = fmt.Sprintf(`{"comments":%s}`, body)
				} else {
					argsStr = `{"comments":[]}`
				}
			} else {
				var raw map[string]any
				if err := json.Unmarshal([]byte(body), &raw); err == nil {
					if _, ok := raw["comments"]; !ok {
						argsStr = fmt.Sprintf(`{"comments":[%s]}`, body)
					}
				}
			}
			calls = append(calls, ToolCall{
				ID:   id,
				Type: "function",
				Function: FunctionCall{
					Name:      "code_comment",
					Arguments: argsStr,
				},
			})
		default:
			argsStr := body
			if !strings.HasPrefix(body, "{") {
				argsStr = "{}"
			}
			calls = append(calls, ToolCall{
				ID:   id,
				Type: "function",
				Function: FunctionCall{
					Name:      tag,
					Arguments: argsStr,
				},
			})
		}
	}

	if len(calls) > 0 {
		return calls
	}

	// 2. Try JSON markdown fences
	fenceMatches := jsonFenceRegex.FindAllStringSubmatch(cleanContent, -1)
	for i, match := range fenceMatches {
		if len(match) < 2 {
			continue
		}
		rawJSON := strings.TrimSpace(match[1])
		var raw map[string]any
		if err := json.Unmarshal([]byte(rawJSON), &raw); err == nil {
			name, _ := raw["name"].(string)
			if name != "" {
				id := fmt.Sprintf("fallback_call_fence_%d_%d", time.Now().UnixNano(), i)
				argsStr := "{}"
				if argsObj, ok := raw["arguments"]; ok {
					if b, err := json.Marshal(argsObj); err == nil {
						argsStr = string(b)
					}
				} else {
					delete(raw, "name")
					if b, err := json.Marshal(raw); err == nil {
						argsStr = string(b)
					}
				}
				calls = append(calls, ToolCall{
					ID:   id,
					Type: "function",
					Function: FunctionCall{
						Name:      name,
						Arguments: argsStr,
					},
				})
			}
		}
	}

	if len(calls) > 0 {
		return calls
	}

	// 3. Raw JSON object check
	trimmed := strings.TrimSpace(cleanContent)
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
		var raw map[string]any
		if err := json.Unmarshal([]byte(trimmed), &raw); err == nil {
			name, _ := raw["name"].(string)
			if name != "" {
				id := fmt.Sprintf("fallback_call_raw_%d", time.Now().UnixNano())
				argsStr := "{}"
				if argsObj, ok := raw["arguments"]; ok {
					if b, err := json.Marshal(argsObj); err == nil {
						argsStr = string(b)
					}
				} else {
					delete(raw, "name")
					if b, err := json.Marshal(raw); err == nil {
						argsStr = string(b)
					}
				}
				calls = append(calls, ToolCall{
					ID:   id,
					Type: "function",
					Function: FunctionCall{
						Name:      name,
						Arguments: argsStr,
					},
				})
			}
		}
	}

	return calls
}
