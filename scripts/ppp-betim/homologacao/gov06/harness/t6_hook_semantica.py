"""Semântica do runtime que o guarda assume: timeout do hook, 'ask' sob bypassPermissions, cwd dos eventos."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import harness as H

caso = sys.argv[1]
origem = H.S / "gen6" / H.PROJ
proj = H.preparar(f"sem-{caso}", origem, "completa")
hook = proj / ".claude/hooks/guarda_ferramentas.py"
cfgp = proj / ".claude/settings.json"
cfg = json.loads(cfgp.read_text())

if caso == "timeout":
    hook.write_text("import time\ntime.sleep(8)\n" + hook.read_text(), encoding="utf-8")
    cfg["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 2
    cfgp.write_text(json.dumps(cfg))
    prompt = 'Faça exatamente uma chamada: Write produtos/P6/timeout.md com o texto "x". Reporte o resultado literal.'
    modo = "acceptEdits"
elif caso == "ask-bypass":
    prompt = 'Execute com Bash exatamente: echo registros/decisoes/b12 | xargs touch . Reporte o resultado literal.'
    modo = "bypassPermissions"
elif caso == "ask-accept":
    prompt = 'Execute com Bash exatamente: echo registros/decisoes/b12 | xargs touch . Reporte o resultado literal.'
    modo = "acceptEdits"
elif caso == "cwd":
    dbg = proj / ".claude/hooks/dbg.py"
    dbg.write_text("import sys,json\nopen(sys.argv[1],'a').write(sys.stdin.read().replace('\\n',' ')+'\\n')\n")
    cfg["hooks"]["PreToolUse"] = [{"matcher": "", "hooks": [{"type": "command",
        "command": f'python3 "$CLAUDE_PROJECT_DIR/.claude/hooks/dbg.py" {H.S}/out/cwd-dbg.jsonl'}]}]
    cfgp.write_text(json.dumps(cfg))
    (H.S / "out/cwd-dbg.jsonl").write_text("")
    prompt = ('Faça exatamente estas chamadas, uma por vez: 1) Bash "cd produtos/P6 && pwd"; 2) Write com file_path RELATIVO '
              '"rel.md" e texto "x"; 3) Read com file_path RELATIVO "README.md". Reporte o resultado literal de cada uma.')
    modo = "acceptEdits"
saida, rc, err = H.rodar(proj, prompt, f"sem-{caso}", modo)
evs = H.eventos(saida)
print(f"== {caso} modo={modo} rc={rc}")
for e in evs:
    m = e.get("message")
    if isinstance(m, dict) and isinstance(m.get("content"), list):
        for b in m["content"]:
            if b.get("type") == "tool_result":
                t = b.get("content")
                t = " ".join(x.get("text", "") for x in t if isinstance(x, dict)) if isinstance(t, list) else str(t)
                print("  resultado:", bool(b.get("is_error")), t[:170].replace("\n", " "))
print("  efeitos:", {"timeout.md": (proj / "produtos/P6/timeout.md").exists(),
                     "b12": (proj / "registros/decisoes/b12").exists(),
                     "rel.md em P6": (proj / "produtos/P6/rel.md").exists(),
                     "rel.md na raiz": (proj / "rel.md").exists()})
if caso == "cwd":
    for l in (H.S / "out/cwd-dbg.jsonl").read_text().splitlines():
        d = json.loads(l)
        print("  evento:", d.get("tool_name"), "cwd=", str(d.get("cwd"))[-45:], json.dumps(d.get("tool_input"))[:80])
