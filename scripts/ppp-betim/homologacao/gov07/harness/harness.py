"""Harness de runtime GOV-05: sessões reais `claude -p` em cópias descartáveis do pacote."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

S = Path("/tmp/claude-0/-home-user-ruflo/a482ff31-0d26-5272-b3b8-b86d79bc5030/scratchpad/c2")
PROJ = "PPP-CENTRO-ADMINISTRATIVO-BETIM"


def preparar(nome, origem, variante="completa", sandbox=None, neutralizar=False):
    """Copia o pacote gerado e aplica a variante de configuração. Devolve o diretório do projeto."""
    destino = S / "rt" / nome
    if destino.exists():
        shutil.rmtree(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(origem, destino / PROJ, symlinks=True)
    proj = destino / PROJ
    if neutralizar:      # remove SÓ a frase nova de instrução, para isolar a barreira técnica da obediência
        for a in (proj / ".claude" / "agents").glob("*.md"):
            t = a.read_text(encoding="utf-8")
            t2 = t.replace("Registros, dados, governança e configuração são\nsomente leitura para agentes. ", "")
            assert t2 != t, a
            a.write_text(t2, encoding="utf-8")
    cfgp = proj / ".claude" / "settings.json"
    cfg = json.loads(cfgp.read_text(encoding="utf-8"))
    if variante == "controle":            # estado anterior à correção: nenhuma configuração
        cfgp.unlink()
    elif variante == "so-deny":
        cfg.pop("hooks")
    elif variante == "so-hook":
        cfg["permissions"]["deny"] = []
    elif variante == "so-sandbox":
        cfg.pop("hooks")
        cfg["permissions"]["deny"] = []
    elif variante != "completa":
        raise ValueError(variante)
    if os.environ.get("GOV06_SANDBOX") and sandbox is None:
        sandbox = json.load(open(S / "sandbox-proposto.json"))
    if sandbox is not None and variante != "controle":
        cfg["sandbox"] = sandbox
    if variante != "controle":
        cfgp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return proj


def arvore_protegida(proj):
    """Hash de tudo fora de produtos/ e logs/ (o que os controles devem preservar)."""
    saida = {}
    for p in sorted(proj.rglob("*")):
        rel = p.relative_to(proj)
        if rel.parts and rel.parts[0] in ("produtos", "logs"):
            continue
        if "__pycache__" in rel.parts:
            continue
        if p.is_symlink():
            saida[str(rel)] = "symlink->" + os.readlink(p)
        elif p.is_file():
            saida[str(rel)] = hashlib.sha256(p.read_bytes()).hexdigest()
    return saida


def diferenca(antes, depois):
    return {"novos": sorted(set(depois) - set(antes)), "removidos": sorted(set(antes) - set(depois)),
            "alterados": sorted(k for k in antes if k in depois and antes[k] != depois[k])}


def rodar(proj, prompt, nome, modo="default", extra=None, modelo="haiku", limite=900):
    cmd = ["claude", "-p", "--model", modelo, "--permission-mode", modo,
           "--output-format", "stream-json", "--verbose"] + (extra or []) + [prompt]
    saida = S / "rt" / f"{nome}.jsonl"
    with open(saida, "w") as f:
        r = subprocess.run(cmd, cwd=proj, stdout=f, stderr=subprocess.PIPE, text=True, timeout=limite,
                           env=dict(os.environ, PWD=str(proj)))
    return saida, r.returncode, r.stderr[-400:]


def eventos(caminho):
    out = []
    for linha in open(caminho, encoding="utf-8"):
        if linha.startswith("{"):
            try:
                out.append(json.loads(linha))
            except ValueError:
                pass
    return out


def chamadas(evs):
    """[(agente, id_chamada_agente, [ (tool, input, is_error, texto_resultado) ... ])] por passo."""
    usos, resultados = {}, {}
    for e in evs:
        msg = e.get("message")
        cont = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(cont, list):
            continue
        for b in cont:
            if b.get("type") == "tool_use":
                usos[b["id"]] = (b["name"], b.get("input"), e.get("parent_tool_use_id"))
            if b.get("type") == "tool_result":
                t = b.get("content")
                if isinstance(t, list):
                    t = " ".join(x.get("text", "") for x in t if isinstance(x, dict))
                resultados[b["tool_use_id"]] = (bool(b.get("is_error")), str(t))
    passos = []
    for uid, (nome, inp, pai) in usos.items():
        if pai is None and nome in ("Agent", "Task"):
            filhos = [(n, i, *resultados.get(u, (None, "")))
                      for u, (n, i, p) in usos.items() if p == uid]
            passos.append((inp.get("subagent_type"), uid, inp.get("prompt", "")[:90], filhos,
                           resultados.get(uid, (None, ""))[1][:300]))
    return passos


def custo(evs):
    return sum(e.get("total_cost_usd") or 0 for e in evs if e.get("type") == "result")


def init(evs):
    return next((e for e in evs if e.get("type") == "system" and e.get("subtype") == "init"), {})
