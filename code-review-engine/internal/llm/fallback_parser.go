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

// repairMalformedJSON fixes common model JSON syntax mistakes (e.g. mismatched closing brackets in arrays)
func repairMalformedJSON(s string) string {
	s = regexp.MustCompile(`\]\s*,\s*\{`).ReplaceAllString(s, "},\n{")
	s = regexp.MustCompile(`\]\s*\]\s*\}`).ReplaceAllString(s, "}\n]\n}")
	s = regexp.MustCompile(`\}\s*\]\s*\]`).ReplaceAllString(s, "}\n]")
	// Semicolons used instead of commas between objects or fields
	s = regexp.MustCompile(`\}\s*;\s*\{`).ReplaceAllString(s, "},\n{")
	s = regexp.MustCompile(`;\s*(\r?\n)`).ReplaceAllString(s, ",\n")
	// Trailing duplicate closing braces like }\n}\n}
	s = regexp.MustCompile(`\}\s*\}\s*\}\s*$`).ReplaceAllString(s, "}\n}")
	// Missing comma between string/number/bool and next key
	s = regexp.MustCompile(`("[^"\\]*(?:\\.[^"\\]*)*")\s*\n\s*("[\w_-]+"\s*:)`).ReplaceAllString(s, "$1,\n$2")
	s = regexp.MustCompile(`(\d+|true|false|null)\s*\n\s*("[\w_-]+"\s*:)`).ReplaceAllString(s, "$1,\n$2")
	// Invalid escape characters like \) or \( or \'
	s = regexp.MustCompile(`\\([^\/\\bfnrtu"])`).ReplaceAllString(s, "$1")
	return s
}

func unescapeJSONString(s string) string {
	var out string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err == nil {
		return out
	}
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

// extractBalancedObjects scans s and returns all top-level or item-level braced {...} strings,
// properly handling braces inside quoted strings and escapes.
func extractBalancedObjects(s string) []string {
	var objects []string
	inString := false
	escape := false
	depth := 0
	start := -1

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escape {
			escape = false
			continue
		}
		if ch == '\\' {
			escape = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}

		if ch == '{' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if ch == '}' {
			if depth > 0 {
				depth--
				if depth == 0 && start != -1 {
					objects = append(objects, s[start:i+1])
					start = -1
				}
			}
		}
	}
	return objects
}

func normalizeCommentArgs(argsObj any) any {
	m, ok := argsObj.(map[string]any)
	if !ok {
		return argsObj
	}
	if arr, ok := m["comments"].([]any); ok {
		for _, item := range arr {
			if cm, ok := item.(map[string]any); ok {
				if _, has := cm["existing_code"]; !has {
					if ec, hasEC := cm["existingcode"]; hasEC {
						cm["existing_code"] = ec
					}
				}
				if _, has := cm["content"]; !has {
					if c, hasC := cm["current"]; hasC {
						cm["content"] = c
					} else if i, hasI := cm["issue"]; hasI {
						cm["content"] = i
					} else if com, hasCom := cm["comment"]; hasCom {
						cm["content"] = com
					}
				}
				if _, has := cm["suggestion_code"]; !has {
					if sc, hasSC := cm["suggestedcode"]; hasSC {
						cm["suggestion_code"] = sc
					} else if sc2, hasSC2 := cm["suggested_code"]; hasSC2 {
						cm["suggestion_code"] = sc2
					}
				}
				if _, has := cm["start_line"]; !has {
					if ln, hasLn := cm["line"]; hasLn {
						cm["start_line"] = ln
						cm["end_line"] = ln
					}
				}
				if p, ok := cm["path"].(string); ok && (strings.Contains(p, "current_file_path") || strings.TrimSpace(p) == "") {
					delete(cm, "path")
				}
			}
		}
	}
	return m
}

func extractCommentsFromMalformedJSON(raw string) []any {
	var comments []any

	parseItem := func(block string) map[string]any {
		cleaned := repairMalformedJSON(block)
		var obj map[string]any
		if err := json.Unmarshal([]byte(cleaned), &obj); err == nil {
			if _, ok := obj["comment"]; ok || obj["existing_code"] != nil || obj["existingcode"] != nil || obj["content"] != nil {
				return obj
			}
		}
		// Fallback: extract fields with regex from block
		content := ""
		if m := regexp.MustCompile(`"(?:content|comment|issue|description)"\s*:\s*"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(block); len(m) > 1 {
			content = unescapeJSONString(m[1])
		}
		if content == "" {
			return nil
		}
		existingCode := ""
		if m := regexp.MustCompile(`"(?:existing_code|existingcode|code)"\s*:\s*"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(block); len(m) > 1 {
			existingCode = unescapeJSONString(m[1])
		}
		cat := "security"
		if m := regexp.MustCompile(`"(?:category)"\s*:\s*"([^"]+)"`).FindStringSubmatch(block); len(m) > 1 {
			cat = m[1]
		}
		sev := "high"
		if m := regexp.MustCompile(`"(?:severity)"\s*:\s*"([^"]+)"`).FindStringSubmatch(block); len(m) > 1 {
			sev = m[1]
		}
		return map[string]any{
			"content":       content,
			"existing_code": existingCode,
			"category":      cat,
			"severity":      sev,
		}
	}

	// 1. Try to find the comments array block: "comments"\s*:\s*\[ ... \]
	if idx := strings.Index(raw, `"comments"`); idx != -1 {
		arrSub := raw[idx:]
		if arrStart := strings.Index(arrSub, "["); arrStart != -1 {
			arrContent := arrSub[arrStart:]
			items := extractBalancedObjects(arrContent)
			for _, it := range items {
				if parsed := parseItem(it); parsed != nil {
					comments = append(comments, parsed)
				}
			}
			if len(comments) > 0 {
				return comments
			}
		}
	}

	// 2. Extract any balanced objects in raw that have comment/content/existing_code indicators
	for _, it := range extractBalancedObjects(raw) {
		if strings.Contains(it, `"comment"`) || strings.Contains(it, `"content"`) || strings.Contains(it, `"existing_code"`) || strings.Contains(it, `"existingcode"`) {
			if parsed := parseItem(it); parsed != nil {
				comments = append(comments, parsed)
			}
		}
	}

	return comments
}

func hasCodeCommentCall(calls []ToolCall) bool {
	for _, c := range calls {
		if c.Function.Name == "code_comment" {
			return true
		}
	}
	return false
}

func extractMarkdownFindings(text string) []map[string]any {
	var comments []map[string]any
	splitPattern := regexp.MustCompile(`(?i)(?:###|\*\*)\s*Finding\s*\d*[:\s]`)
	indices := splitPattern.FindAllStringIndex(text, -1)
	if len(indices) == 0 {
		return nil
	}

	for i := 0; i < len(indices); i++ {
		start := indices[i][0]
		end := len(text)
		if i+1 < len(indices) {
			end = indices[i+1][0]
		}
		block := text[start:end]

		// Extract severity
		sev := "high"
		if m := regexp.MustCompile(`(?i)severity[*:\s]+(critical|high|medium|low)`).FindStringSubmatch(block); len(m) > 1 {
			sev = strings.ToLower(m[1])
		}

		// Extract category
		cat := "security"
		if m := regexp.MustCompile(`(?i)category[*:\s]+(security|bug|performance|maintainability|memory)`).FindStringSubmatch(block); len(m) > 1 {
			cat = strings.ToLower(m[1])
			if cat == "memory" {
				cat = "security"
			}
		}

		// Extract code blocks (support both 2 and 3 backticks)
		codeBlocks := regexp.MustCompile("(?s)`{2,}([a-zA-Z]*)\\r?\\n(.*?)\\r?\\n\\s*`{2,}").FindAllStringSubmatch(block, -1)
		existingCode := ""
		suggestedCode := ""
		if len(codeBlocks) > 0 {
			existingCode = strings.TrimSpace(codeBlocks[0][2])
		}
		if len(codeBlocks) > 1 {
			suggestedCode = strings.TrimSpace(codeBlocks[1][2])
		}

		// Clean description
		lines := strings.Split(block, "\n")
		var descLines []string
		for _, l := range lines {
			lTrim := strings.TrimSpace(l)
			if strings.HasPrefix(lTrim, "```") ||
				strings.HasPrefix(lTrim, "**Category") ||
				strings.HasPrefix(lTrim, "**Severity") ||
				strings.HasPrefix(lTrim, "### Finding") {
				continue
			}
			if lTrim != "" {
				descLines = append(descLines, lTrim)
			}
		}
		desc := strings.Join(descLines, " ")
		if len(desc) > 300 {
			desc = desc[:300]
		}
		if desc == "" {
			desc = "Security defect identified by code reviewer"
		}

		comments = append(comments, map[string]any{
			"content":         desc,
			"severity":        sev,
			"category":        cat,
			"existing_code":   existingCode,
			"suggestion_code": suggestedCode,
		})
	}
	return comments
}

// ExtractFallbackToolCalls inspects text output for tool calls formatted as XML tags or JSON blocks.
func ExtractFallbackToolCalls(content string) []ToolCall {
	var calls []ToolCall
	cleanContent := repairMalformedJSON(stripThinkTags(content))

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
				if name == "" {
					name, _ = raw["function"].(string)
				}
				if name == "current_comment" {
					name = "code_comment"
				}
				if name != "" {
					argsStr := "{}"
					if argsObj, ok := raw["arguments"]; ok {
						if b, err := json.Marshal(argsObj); err == nil {
							argsStr = string(b)
						}
					} else {
						delete(raw, "name")
						delete(raw, "function")
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

	if hasCodeCommentCall(calls) {
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
			if name == "" {
				name, _ = raw["function"].(string)
			}
			if name == "current_comment" {
				name = "code_comment"
			}
			if name != "" {
				id := fmt.Sprintf("fallback_call_fence_%d_%d", time.Now().UnixNano(), i)
				argsStr := "{}"
				if argsObj, ok := raw["arguments"]; ok {
					argsObj = normalizeCommentArgs(argsObj)
					if b, err := json.Marshal(argsObj); err == nil {
						argsStr = string(b)
					}
				} else {
					delete(raw, "name")
					delete(raw, "function")
					normRaw := normalizeCommentArgs(raw)
					if b, err := json.Marshal(normRaw); err == nil {
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
		} else {
			extracted := extractCommentsFromMalformedJSON(rawJSON)
			if len(extracted) > 0 {
				id := fmt.Sprintf("fallback_call_fence_extracted_%d_%d", time.Now().UnixNano(), i)
				normObj := normalizeCommentArgs(map[string]any{"comments": extracted})
				if b, err := json.Marshal(normObj); err == nil {
					calls = append(calls, ToolCall{
						ID:   id,
						Type: "function",
						Function: FunctionCall{
							Name:      "code_comment",
							Arguments: string(b),
						},
					})
				}
			}
		}
	}

	if hasCodeCommentCall(calls) {
		return calls
	}

	// 3. Raw JSON object check
	trimmed := strings.TrimSpace(cleanContent)
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
		var raw map[string]any
		if err := json.Unmarshal([]byte(trimmed), &raw); err == nil {
			name, _ := raw["name"].(string)
			if name == "" {
				name, _ = raw["function"].(string)
			}
			if name == "current_comment" {
				name = "code_comment"
			}
			if name != "" {
				id := fmt.Sprintf("fallback_call_raw_%d", time.Now().UnixNano())
				argsStr := "{}"
				if argsObj, ok := raw["arguments"]; ok {
					argsObj = normalizeCommentArgs(argsObj)
					if b, err := json.Marshal(argsObj); err == nil {
						argsStr = string(b)
					}
				} else {
					delete(raw, "name")
					delete(raw, "function")
					normRaw := normalizeCommentArgs(raw)
					if b, err := json.Marshal(normRaw); err == nil {
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
		} else {
			extracted := extractCommentsFromMalformedJSON(trimmed)
			if len(extracted) > 0 {
				id := fmt.Sprintf("fallback_call_raw_extracted_%d", time.Now().UnixNano())
				normObj := normalizeCommentArgs(map[string]any{"comments": extracted})
				if b, err := json.Marshal(normObj); err == nil {
					calls = append(calls, ToolCall{
						ID:   id,
						Type: "function",
						Function: FunctionCall{
							Name:      "code_comment",
							Arguments: string(b),
						},
					})
				}
			}
		}
	}

	if hasCodeCommentCall(calls) {
		return calls
	}

	// 4. Markdown findings extraction (e.g. Qwen writing "### Finding 1: ... **Severity**: Critical ...")
	mdFindings := extractMarkdownFindings(cleanContent)
	if len(mdFindings) > 0 {
		if b, err := json.Marshal(map[string]any{"comments": mdFindings}); err == nil {
			return []ToolCall{{
				ID:   fmt.Sprintf("fallback_md_comment_%d", time.Now().UnixNano()),
				Type: "function",
				Function: FunctionCall{
					Name:      "code_comment",
					Arguments: string(b),
				},
			}}
		}
	}

	// 5. Natural language review completion detection (e.g. Qwen writing "Task Done", "Conclusion", or "no issues identified")
	lower := strings.ToLower(cleanContent)
	if strings.Contains(lower, "task_done") ||
		strings.Contains(lower, "task done") ||
		strings.Contains(lower, "done") ||
		strings.Contains(lower, "finished") ||
		strings.Contains(lower, "conclusion") ||
		strings.Contains(lower, "summary") ||
		strings.Contains(lower, "no critical or high") ||
		strings.Contains(lower, "no issues identified") ||
		strings.Contains(lower, "no further issues") ||
		strings.Contains(lower, "no vulnerabilities") ||
		strings.Contains(lower, "review is complete") ||
		strings.Contains(lower, "review is done") ||
		strings.Contains(lower, "no defects identified") ||
		strings.Contains(lower, "no major issues") ||
		strings.Contains(lower, "minor issues") ||
		strings.Contains(lower, "low severity") ||
		strings.Contains(lower, "low-se") ||
		strings.Contains(lower, "code looks good") ||
		strings.Contains(lower, "lgtm") {
		calls = append(calls, ToolCall{
			ID:   fmt.Sprintf("fallback_task_done_%d", time.Now().UnixNano()),
			Type: "function",
			Function: FunctionCall{
				Name:      "task_done",
				Arguments: `{"state":"DONE"}`,
			},
		})
	}

	return calls
}
