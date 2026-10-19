# Generation: OpenRouter chat (DeepSeek V3.2); old Gemini cache entries are reused read-only. Jev decisions. Disk caches, keys never printed.
import json, os, time, hashlib, urllib.request, urllib.error
GEN, OLD, CACHE = 'deepseek/deepseek-v3.2', 'gemini-2.5-flash', 'data/llm'
os.makedirs(CACHE, exist_ok=True)
def post(url, body):
    for i in range(6):
        try:
            req = urllib.request.Request(url, json.dumps(body).encode(), {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + os.environ['OPENROUTER_API_KEY']})
            return json.load(urllib.request.urlopen(req, timeout=180))
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 402, 403, 404): raise
            time.sleep(2 ** i)
        except (urllib.error.URLError, TimeoutError): time.sleep(2 ** i)
    raise RuntimeError('openrouter failed')
def gen_model(model, prompt, temp=0):  # OpenRouter chat for an explicit model id; disk-cached under data/llm/
    key = f'{CACHE}/{hashlib.sha1((model + prompt + (f"|t{temp}" if temp else "")).encode()).hexdigest()}.json'
    if os.path.exists(key): return json.load(open(key))['text']
    if os.environ.get('CACHE_ONLY'): raise RuntimeError('not cached (CACHE_ONLY)')
    r = post('https://openrouter.ai/api/v1/chat/completions', {'model': model, 'temperature': temp, 'messages': [{'role': 'user', 'content': prompt}]})
    text = r['choices'][0]['message']['content']; json.dump({'text': text, 'usage': r.get('usage'), 'model': model}, open(key, 'w')); return text
def gen(prompt, temp=0):
    key = lambda m: f'{CACHE}/{hashlib.sha1((m + prompt + (f"|t{temp}" if temp else "")).encode()).hexdigest()}.json'
    for m in (OLD, GEN):
        if os.path.exists(key(m)): return json.load(open(key(m)))['text']
    if os.environ.get('CACHE_ONLY'): raise RuntimeError('not cached (CACHE_ONLY)')
    r = post('https://openrouter.ai/api/v1/chat/completions', {'model': GEN, 'temperature': temp, 'messages': [{'role': 'user', 'content': prompt}]})
    text = r['choices'][0]['message']['content']; json.dump({'text': text, 'usage': r.get('usage')}, open(key(GEN), 'w')); return text

def jev(state, questions):  # OpenRouter Jev decisions API, cached; returns answers dict
    p = f'data/jev/{hashlib.sha1(json.dumps([state, questions], sort_keys=True).encode()).hexdigest()}.json'
    os.makedirs('data/jev', exist_ok=True)
    if os.path.exists(p): return json.load(open(p))['answers']
    r = post('https://openrouter.ai/api/alpha/decisions', {'model': '~typesafe/jev-latest', 'state': state, 'questions': questions})
    json.dump(r, open(p, 'w')); return r['answers']
