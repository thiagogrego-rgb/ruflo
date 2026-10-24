"""Uso real de skills por agente nomeado: positivas (matriz) e negativas (fora da matriz / externas)."""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import harness as H

AGENTE = sys.argv[1]
modo = sys.argv[2] if len(sys.argv) > 2 else "default"
VAR = sys.argv[3] if len(sys.argv) > 3 else "completa"
origem = H.S / "gen10" / H.PROJ
matriz = json.loads((origem / "governanca/matriz-agentes.json").read_text())["agentes"]
todas = sorted(p.parent.name for p in (origem / ".claude/skills").glob("*/SKILL.md"))
proprias = matriz[AGENTE]["skills"]
alheias = [s for s in todas if s not in proprias]
negativas = [alheias[0], alheias[-1], "update-config", "anthropic-skills:pdf"]


def objetivo(skill):
    t = (origem / f".claude/skills/{skill}/SKILL.md").read_text(encoding="utf-8")
    return re.search(r"## O — Objetivo\n(.+)", t).group(1).strip()


proj = H.preparar(f"sk-{AGENTE}-{VAR}", origem, VAR)
passo1 = (f'PASSO 1 — prompt: "TESTE SINTÉTICO: para cada skill da lista, na ordem, faça UMA chamada à ferramenta '
          f'Skill (não use Read nem Grep nos arquivos das skills). Depois responda uma linha por skill no formato '
          f'\'nome :: primeira frase literal da seção Objetivo da skill carregada\'. Lista: {", ".join(proprias)}"')
passo2 = (f'PASSO 2 — prompt: "TESTE SINTÉTICO: tente chamar a ferramenta Skill, uma chamada para cada nome, na ordem: '
          f'{", ".join(negativas)}. Para cada um reporte a mensagem exata de erro ou diga que carregou. Não tente alternativas."')
prompt = (f'TESTE DE RUNTIME com dados 100% SINTÉTICOS. Você é só o executor: não use Bash, Write, Read nem Skill '
          f'você mesmo. Use somente a ferramenta Agent, em primeiro plano, uma chamada por passo, na ordem, com '
          f'subagent_type EXATO "{AGENTE}". Ao final imprima a resposta literal de cada passo.\n{passo1}\n{passo2}')

saida, rc, err = H.rodar(proj, prompt, f"sk-{AGENTE}-{VAR}", modo)
evs = H.eventos(saida)
passos = H.chamadas(evs)
print(f"== agente={AGENTE} rc={rc} custo=${H.custo(evs):.3f} passos={len(passos)}")
res = {"agente": AGENTE, "positivas": {}, "negativas": {}, "leu_arquivo_de_skill": False}
for idx, (ag, _, _, filhos, final) in enumerate(passos):
    for nome, inp, erro, texto in filhos:
        if nome in ("Read", "Grep", "Glob") and ".claude/skills" in json.dumps(inp):
            res["leu_arquivo_de_skill"] = True
        if nome == "Skill":
            alvo = (inp or {}).get("skill") or (inp or {}).get("name")
            (res["positivas"] if idx == 0 else res["negativas"]).setdefault(alvo, []).append((erro, texto[:140]))
# texto final do passo 1: objetivo reproduzido?
resposta = ""
for e in evs:
    if e.get("type") == "result":
        resposta = e.get("result", "")
res["objetivo_reproduzido"] = {s: objetivo(s)[:45] in resposta.replace("\n", " ") for s in proprias}
for s in proprias:
    chamadas_s = res["positivas"].get(s)
    ok = bool(chamadas_s) and chamadas_s[-1][0] is False
    print(f"  POS {s:34} chamada={'sim' if chamadas_s else 'NAO'} sem_erro={ok} objetivo_reproduzido={res['objetivo_reproduzido'][s]}")
for s in negativas:
    c = res["negativas"].get(s)
    print(f"  NEG {s:34} " + (f"erro={c[-1][0]} :: {c[-1][1]}" if c else "sem chamada"))
print("  leu arquivos de skill por Read/Grep:", res["leu_arquivo_de_skill"])
log = proj / "logs" / "guarda.jsonl"
if log.exists():
    ls = [json.loads(x) for x in log.read_text().splitlines()]
    sk = [x for x in ls if x["ferramenta"] == "Skill"]
    print("  log do guarda (Skill):", {d: sum(1 for x in sk if x["decisao"] == d) for d in {x["decisao"] for x in sk}})
json.dump(res, open(H.S / "out" / f"sk-{AGENTE}-{VAR}.json", "w"), ensure_ascii=False, indent=1, default=str)
