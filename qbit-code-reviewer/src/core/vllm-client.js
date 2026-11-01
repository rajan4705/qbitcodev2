import { config } from './config.js';

/**
 * Streams a chat completion directly from the local vLLM OpenAI-compatible endpoint.
 * Throws an explicit error if vLLM is down or unreachable.
 */
export async function* streamChatWithVllm({
  messages,
  systemPrompt = 'You are Qbit, an elite AI code reviewer and security engineer. You help developers understand vulnerabilities, explain risks, and plan secure refactorings.',
  temperature = 0.2,
  maxTokens = 2048
}) {
  const fullMessages = [
    { role: 'system', content: systemPrompt },
    ...messages
  ];

  const endpoint = `${config.vllmUrl}/chat/completions`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  let res;
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.apiKey}`
      },
      body: JSON.stringify({
        model: config.model,
        messages: fullMessages,
        temperature,
        max_tokens: maxTokens,
        stream: true
      }),
      signal: controller.signal
    });
  } catch (err) {
    clearTimeout(timeout);
    throw new Error(`Cannot connect to vLLM server at ${config.vllmUrl}: ${err.message}. Ensure the vLLM engine is running.`);
  }

  clearTimeout(timeout);

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`vLLM HTTP ${res.status}: ${res.statusText} - ${errText}`);
  }

  if (!res.body) {
    throw new Error('Response body from vLLM is empty');
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith(':')) continue;
      if (trimmed === 'data: [DONE]') return;

      if (trimmed.startsWith('data: ')) {
        try {
          const data = JSON.parse(trimmed.slice(6));
          const delta = data.choices?.[0]?.delta?.content;
          if (delta) yield delta;
        } catch {}
      }
    }
  }
}

/**
 * Non-streaming completion with vLLM
 */
export async function generateCompletionWithVllm({
  messages,
  systemPrompt = 'You are an autonomous code remediation engine. Output only the requested code or replacement, without conversational filler.',
  temperature = 0.1,
  maxTokens = 2048
}) {
  const fullMessages = [
    { role: 'system', content: systemPrompt },
    ...messages
  ];

  const endpoint = `${config.vllmUrl}/chat/completions`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model,
      messages: fullMessages,
      temperature,
      max_tokens: maxTokens,
      stream: false
    })
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`vLLM HTTP ${res.status}: ${res.statusText} - ${errText}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content || '';
}
