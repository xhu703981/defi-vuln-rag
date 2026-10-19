# defi-vuln-rag (MVP)
DeFiHackLabs → 4 类案例 (price_manipulation / access_control / reentrancy / precision) → 三表示索引 → 混合检索 + RRF → 时间切分留一评测。
```
python3 -m venv .venv && .venv/bin/pip install rank_bm25 sentence-transformers torch --extra-index-url https://download.pytorch.org/whl/cpu
git clone --depth 1 https://github.com/SunWeb3Sec/DeFiHackLabs
.venv/bin/python build_corpus.py      # -> cases.jsonl
.venv/bin/python rag.py               # 评测
.venv/bin/python rag.py X.sol         # 按函数查相似案例
```
.venv/bin/python fetch_source.py   # 需 ETHERSCAN_API_KEY；缓存在 data/，code=受害合约源码，poc 另存
ONLY=victim MODES=code .venv/bin/python rag.py  # 只评有源码的子集
局限：llm_describe / llm_rerank 为桩，需 LLM key。
