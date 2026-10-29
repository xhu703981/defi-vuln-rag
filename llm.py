# Generation: OpenRouter chat (DeepSeek V3.2); old Gemini cache entries are reused read-only. Jev decisions. Disk caches, keys never printed.
import json, os, time, hashlib, urllib.request, urllib.error, http.client
GEN, OLD, CACHE = 'deepseek/deepseek-v3.2', 'gemini-2.5-flash', 'data/llm'
os.makedirs(CACHE, exist_ok=True)
def _reasoning():
    """OpenRouter `reasoning` config, env-tunable. deepseek-v4.1-flash's long chain-of-thought
    was eating the whole max_tokens budget and truncating the Solidity body (finish_reason=length,
    empty/short content). This model exposes efforts max/high/low/none; probes show effort "none"
    yields reasoning_tokens=0 and the full body, "low" is unreliable (consumed the full budget),
    and max_tokens is NOT a hard cap (maps to effort). So the primary knob is effort, default none.
      LLM_REASONING_EFFORT: none|low|high|max|default   (default: none)
      LLM_REASONING_MAX_TOKENS: int                      (best-effort budget; passed if set)
    Returns {} to omit the param entirely (effort=default)."""
    eff = os.environ.get('LLM_REASONING_EFFORT', 'none').strip().lower()
    cfg = {}
    if eff and eff != 'default':
        cfg['effort'] = eff
    mt = os.environ.get('LLM_REASONING_MAX_TOKENS', '').strip()
    if mt:
        cfg.pop('effort', None)          # effort and max_tokens are mutually exclusive
        cfg['max_tokens'] = int(mt)
    return {'reasoning': cfg} if cfg else {}
# Transient network failures treated like a timeout: backoff + retry.
RETRYABLE = (http.client.IncompleteRead, http.client.RemoteDisconnected,
             ConnectionResetError, BrokenPipeError, ConnectionError, TimeoutError)
def post(url, body):
    for i in range(6):
        try:
            req = urllib.request.Request(url, json.dumps(body).encode(), {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + os.environ['OPENROUTER_API_KEY']})
            return json.load(urllib.request.urlopen(req, timeout=180))
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 402, 403, 404): raise
            time.sleep(2 ** i)
        except urllib.error.URLError as e:
            # URLError often wraps IncompleteRead / BrokenPipe / ConnectionReset — retry those too.
            if isinstance(getattr(e, 'reason', None), RETRYABLE) or isinstance(e, RETRYABLE):
                time.sleep(2 ** i); continue
            time.sleep(2 ** i)
        except RETRYABLE: time.sleep(2 ** i)
    raise RuntimeError('openrouter failed')
def _chat(model, prefix, dynamic, temp):
    """One OpenRouter chat call. When a static `prefix` is given and the model is an Anthropic model,
    the prefix is sent as a separate content block with cache_control: ephemeral so the big static
    SYS+source head (shared across a case's turns) is prompt-cached (~80%% input-cost cut on it).
    Behavior is identical to sending `prefix + dynamic` as one string."""
    if prefix and 'anthropic' in model:
        content = [{'type': 'text', 'text': prefix, 'cache_control': {'type': 'ephemeral'}},
                   {'type': 'text', 'text': dynamic}]
    else:
        content = (prefix or "") + dynamic
    r = post('https://openrouter.ai/api/v1/chat/completions', {'model': model, 'temperature': temp, 'max_tokens': int(os.environ.get('LLM_MAX_TOKENS', '32768')), 'messages': [{'role': 'user', 'content': content}], **_reasoning()})
    return r['choices'][0]['message']['content'], r.get('usage')

def gen_model(model, prompt, temp=0, prefix=None):  # OpenRouter chat for an explicit model id; disk-cached under data/llm/
    # Disk key hashes the FULL logical prompt (prefix+prompt) so keys match the pre-caching single-string form.
    full = (prefix or "") + prompt
    key = f'{CACHE}/{hashlib.sha1((model + full + (f"|t{temp}" if temp else "")).encode()).hexdigest()}.json'
    if os.path.exists(key): return json.load(open(key))['text']
    if os.environ.get('CACHE_ONLY'): raise RuntimeError('not cached (CACHE_ONLY)')
    text, usage = _chat(model, prefix, prompt, temp)
    json.dump({'text': text, 'usage': usage, 'model': model}, open(key, 'w')); return text
def gen(prompt, temp=0):
    key = lambda m: f'{CACHE}/{hashlib.sha1((m + prompt + (f"|t{temp}" if temp else "")).encode()).hexdigest()}.json'
    for m in (OLD, GEN):
        if os.path.exists(key(m)): return json.load(open(key(m)))['text']
    if os.environ.get('CACHE_ONLY'): raise RuntimeError('not cached (CACHE_ONLY)')
    r = post('https://openrouter.ai/api/v1/chat/completions', {'model': GEN, 'temperature': temp, 'max_tokens': int(os.environ.get('LLM_MAX_TOKENS', '32768')), 'messages': [{'role': 'user', 'content': prompt}], **_reasoning()})
    text = r['choices'][0]['message']['content']; json.dump({'text': text, 'usage': r.get('usage')}, open(key(GEN), 'w')); return text

def jev(state, questions):  # OpenRouter Jev decisions API, cached; returns answers dict
    p = f'data/jev/{hashlib.sha1(json.dumps([state, questions], sort_keys=True).encode()).hexdigest()}.json'
    os.makedirs('data/jev', exist_ok=True)
    if os.path.exists(p): return json.load(open(p))['answers']
    r = post('https://openrouter.ai/api/alpha/decisions', {'model': '~typesafe/jev-latest', 'state': state, 'questions': questions})
    json.dump(r, open(p, 'w')); return r['answers']
