# Parse DeFiHackLabs READMEs -> cases.jsonl (4 categories). Code = PoC source (no Etherscan key).
import re, json, glob, os
R = 'DeFiHackLabs'
CATS = [('reentrancy', r'reentr|re-entr'),
        ('access_control', r'access control|unprotected|no access|lack of access|missing (auth|access)|permissionless|ungated|onlyowner|unauthori|arbitrary call'),
        ('price_manipulation', r'price manipulat|oracle|spot price|getreserves|price calculat|flawed price|manipulat'),
        ('precision', r'precision|rounding|round(s|ed)? (down|up)|truncat|divceil|division')]
out = []
for f in [f'{R}/README.md'] + sorted(glob.glob(f'{R}/past/*/README.md')):
    for blk in re.split(r'\n(?=### 20\d{6})', open(f).read())[1:]:
        m = re.match(r'### (20\d{6})\s*-?\s*(.+?)\s+-\s+(.+)', blk)
        if not m: continue
        date, name, desc = m.groups()
        cat = next((c for c, p in CATS if re.search(p, desc, re.I)), None)
        poc = re.search(r'\((?:\.\./\.\./|\./)?(src/test/[^)]+\.sol)\)', blk)
        if not cat or not poc or not os.path.exists(f'{R}/{poc[1]}'): continue
        lost = re.search(r'### Lost:\s*(.+)', blk)
        code = open(f'{R}/{poc[1]}', errors='ignore').read()
        out.append(dict(id=f'{date}_{name.strip()}', date=date, category=cat,
                        loss=lost[1].strip()[:200] if lost else '', root_cause=desc.strip(),
                        code=code, attack=poc[1]))
with open('cases.jsonl', 'w') as w:
    for c in out: w.write(json.dumps(c) + '\n')
from collections import Counter; print(len(out), Counter(c['category'] for c in out))
