# Generation: OpenRouter chat (DeepSeek V3.2); old Gemini cache entries are reused read-only. Jev decisions. Disk caches, keys never printed.
import json, os, time, hashlib, urllib.request, urllib.error, http.client
GEN, OLD, CACHE = 'deepseek/deepseek-v3.2', 'gemini-2.5-flash', 'data/llm'
os.makedirs(CACHE, exist_ok=True)
_EFFORT_OVERRIDE = None  # set transiently by gen_model(reasoning_effort=...) for per-call effort; None -> use env
def _reasoning():
    """OpenRouter `reasoning` config, env-tunable. deepseek-v4.1-flash's long chain-of-thought
    was eating the whole max_tokens budget and truncating the Solidity body. This model exposes
    efforts max/high/medium/low/none. Probe (deepseek/deepseek-v4.1-flash, 32768 max_tokens, a
    ~120-line Solidity write prompt), reasoning_tokens / completion / content_len / finish:
      effort=high    8327 / 10400 / 8292 / stop
      effort=medium  6459 /  7886 / 5707 / stop   <- DEFAULT: some reasoning, ~22%% < high, full body
      effort=low     6730 /  8332 / 6406 / stop
      effort=none       0 /  2316 / 9474 / stop   (zero reasoning; user wants nonzero)
      max_tokens=512/1024/2048/4096: 6889/6731/5226/6350 reasoning (NOT a hard cap -> maps to effort,
                                     so reasoning.max_tokens is an unreliable knob here)
    So the primary knob is effort. Default "medium" keeps a bit of reasoning (nonzero, clearly below
    high) while still writing a complete body; reasoning.max_tokens is honored if explicitly set but
    is best-effort only. Keep LLM_MAX_TOKENS high (32768) so ~6.5k reasoning leaves ample room.
      LLM_REASONING_EFFORT: none|low|medium|high|max|default   (default: medium)
      LLM_REASONING_MAX_TOKENS: int                             (best-effort budget; passed if set)
    Returns {} to omit the param entirely (effort=default)."""
    eff = (_EFFORT_OVERRIDE if _EFFORT_OVERRIDE is not None
           else os.environ.get('LLM_REASONING_EFFORT', 'medium')).strip().lower()
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

def gen_model(model, prompt, temp=0, prefix=None, reasoning_effort=None):  # OpenRouter chat for an explicit model id; disk-cached under data/llm/
    # reasoning_effort (none|low|medium|high|max) overrides LLM_REASONING_EFFORT for THIS call only — lets the
    # plan (reasoning) and write (code) roles use different effort. Folded into the disk cache key.
    # Disk key hashes the FULL logical prompt (prefix+prompt) so keys match the pre-caching single-string form.
    global _EFFORT_OVERRIDE
    full = (prefix or "") + prompt
    eff_tag = f'|r{reasoning_effort}' if reasoning_effort else ''
    key = f'{CACHE}/{hashlib.sha1((model + full + (f"|t{temp}" if temp else "") + eff_tag).encode()).hexdigest()}.json'
    if os.path.exists(key): return json.load(open(key))['text']
    if os.environ.get('CACHE_ONLY'): raise RuntimeError('not cached (CACHE_ONLY)')
    _prev = _EFFORT_OVERRIDE; _EFFORT_OVERRIDE = reasoning_effort if reasoning_effort else _prev
    try:
        text, usage = _chat(model, prefix, prompt, temp)
    finally:
        _EFFORT_OVERRIDE = _prev
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
