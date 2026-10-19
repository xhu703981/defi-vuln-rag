import re
KW = set('''contract interface function returns return if else for while require emit event
memory storage calldata external public internal private view pure payable uint256 uint address
bool bytes string mapping new true false this msg sender value override virtual'''.split())

def strip(c): return re.sub(r'//.*|/\*[\s\S]*?\*/|pragma.*|import.*', '', c)
def norm(c):  # comments out, identifiers -> V
    return ' '.join('V' if re.match(r'[A-Za-z_]\w*$', t) and t not in KW else t
                    for t in re.findall(r'[A-Za-z_]\w*|\S', strip(c)))
def funcs(c):  # naive regex split: 'function ...{ body }' with brace matching
    c, out = strip(c), []
    for m in re.finditer(r'function\s+\w+[^;{]*\{', c):
        d, i = 1, m.end()
        while d and i < len(c): d += {'{': 1, '}': -1}.get(c[i], 0); i += 1
        if i - m.start() > 80: out.append(c[m.start():i])
    return out or [c]
def toks(c): return re.findall(r'[A-Za-z_]\w+', c.lower())

