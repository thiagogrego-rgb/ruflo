#!/usr/bin/env python3
"""Verifica a integridade dos controles de GOV-05/06 ANTES de iniciar uma sessão do Claude Code.

Por quê: um `settings.json` inválido, um `settings.local.json` com `disableAllHooks` ou um hook alterado
desligam os controles SEM aviso (medido em GOV-06). Este verificador roda fora do Claude Code.

Uso:
  python3 scripts/verificar_configuracao.py            # verifica; código 0 = íntegro, 1 = problema
  python3 scripts/verificar_configuracao.py --gerar    # regrava o manifesto (decisão humana, após revisão)

O manifesto detecta deriva e corrupção acidental; NÃO é assinatura nem prova de autoria: quem altera os
arquivos e o manifesto juntos não é detectado. Registre o hash do manifesto em local externo.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
MANIFESTO = "governanca/manifesto-controles.json"
OBRIGATORIOS = ("Edit(/dados/**)", "Edit(/registros/**)", "Edit(/governanca/**)", "Edit(/.claude/**)",
                "Edit(/scripts/**)", "Edit(/testes/**)", "Edit(/logs/**)", "WebFetch", "WebSearch")
FERRAMENTAS_DO_GUARDA = ("Write", "Edit", "MultiEdit", "NotebookEdit", "Read", "Grep", "Glob", "Skill", "Bash", "mcp__",
                         "Task", "Agent", "WebFetch", "WebSearch", "SendMessage", "EnterWorktree", "ExitWorktree", "Monitor")
FERRAMENTAS_DE_AGENTE = {"Read", "Grep", "Glob", "Write", "Skill"}      # nenhum agente tem terminal, rede, delegação nem conectores


def sha256(caminho):
    return hashlib.sha256(Path(caminho).read_bytes()).hexdigest()


def arquivos_controlados(raiz):
    fixos = [".claude/settings.json", "governanca/matriz-agentes.json",
             "scripts/verificar_configuracao.py", "scripts/iniciar_sessao.py", "scripts/isolamento.py", "scripts/isolamento_base.py", "scripts/isolamento_so.py",
             "scripts/jaula.py", "scripts/logd.py", "scripts/gateway.py", "scripts/entrada_jaula.py",
             "scripts/ancora_logs.py", "scripts/piloto_ambiente.py", "scripts/piloto_cenarios.py", "scripts/piloto_falhas.py", "scripts/piloto.py",
             "governanca/papeis.json", "governanca/sandbox-recomendado.json"]
    fixos += sorted(p.relative_to(raiz).as_posix() for p in (raiz / ".claude/hooks").glob("*.py"))
    agentes = sorted(p.relative_to(raiz).as_posix() for p in (raiz / ".claude/agents").glob("*.md"))
    skills = sorted(p.relative_to(raiz).as_posix() for p in (raiz / ".claude/skills").glob("*/SKILL.md"))
    return fixos + agentes + skills


def gerar(raiz=RAIZ):
    manifesto = {"versao": 1, "arquivos": {a: sha256(raiz / a) for a in arquivos_controlados(raiz)}}
    (raiz / MANIFESTO).write_text(json.dumps(manifesto, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifesto


def verificar(raiz=RAIZ):
    """Lista de problemas; vazia = íntegro."""
    problemas = []
    try:
        cfg = json.loads((raiz / ".claude/settings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as erro:
        return [f"settings.json ilegível ou inválido ({type(erro).__name__}): os controles ficariam DESLIGADOS"]
    try:
        deny = set(cfg["permissions"]["deny"])
        for regra in OBRIGATORIOS:
            if regra not in deny:
                problemas.append(f"regra deny ausente: {regra}")
        if cfg["permissions"].get("defaultMode") in ("bypassPermissions", "acceptEdits"):
            problemas.append("defaultMode permissivo")
        grupos = cfg["hooks"]["PreToolUse"]
        comandos = [h for g in grupos for h in g["hooks"]]
        guarda = [h for h in comandos if "guarda_ferramentas.py" in h.get("command", "")]
        if len(guarda) != 1:
            problemas.append("hook guarda_ferramentas.py não registrado exatamente uma vez")
        else:
            if not guarda[0]["command"].rstrip().endswith("|| exit 2"):
                problemas.append("hook sem '|| exit 2' (não falharia fechado)")
            if not isinstance(guarda[0].get("timeout"), int) or guarda[0]["timeout"] < 15:
                problemas.append("hook sem timeout explícito adequado")
            for g in grupos:
                if guarda[0] in g["hooks"]:
                    for ferramenta in FERRAMENTAS_DO_GUARDA:
                        if not re.search(g["matcher"], ferramenta):
                            problemas.append(f"matcher do guarda não cobre {ferramenta}")
    except (KeyError, TypeError, AttributeError) as erro:
        problemas.append(f"estrutura de settings.json inesperada ({type(erro).__name__})")
    pasta_agentes = raiz / ".claude/agents"
    if not pasta_agentes.is_dir():
        problemas.append("pasta .claude/agents ausente (sem lista de ferramentas por agente)")
    else:
        try:
            papeis = json.loads((raiz / "governanca/papeis.json").read_text(encoding="utf-8"))["papeis"]
            matriz = json.loads((raiz / "governanca/matriz-agentes.json").read_text(encoding="utf-8"))["agentes"]
            for nome, papel in papeis.items():
                padrao = papel.get("agente_padrao")
                if not (pasta_agentes / f"{padrao}.md").is_file() or padrao not in matriz:
                    problemas.append(f"papel {nome}: agente_padrao '{padrao}' ausente em .claude/agents ou na matriz")
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            problemas.append("não foi possível cruzar papeis.json com os agentes e a matriz")
    for agente in sorted(pasta_agentes.glob("*.md")):
        linha = next((x for x in agente.read_text(encoding="utf-8").splitlines() if x.startswith("tools:")), None)
        if linha is None:
            problemas.append(f"agente {agente.stem} sem lista 'tools:' (herdaria TODAS as ferramentas)")
            continue
        fora = {x.strip() for x in linha[len("tools:"):].split(",") if x.strip()} - FERRAMENTAS_DE_AGENTE
        if fora:
            problemas.append(f"agente {agente.stem} com ferramentas fora do escopo: {sorted(fora)}")
    if cfg.get("disableAllHooks"):
        problemas.append("disableAllHooks ligado em settings.json")
    local = raiz / ".claude/settings.local.json"
    if local.exists():
        problemas.append("existe .claude/settings.local.json (pode desligar hooks; área sigilosa)")
    try:
        manifesto = json.loads((raiz / MANIFESTO).read_text(encoding="utf-8"))["arquivos"]
    except (OSError, ValueError, KeyError, TypeError):
        return problemas + [f"manifesto {MANIFESTO} ausente ou inválido"]
    atuais = set(arquivos_controlados(raiz))
    for novo in sorted(atuais - set(manifesto)):
        problemas.append(f"arquivo controlado fora do manifesto: {novo}")
    for arq, esperado in sorted(manifesto.items()):
        caminho = raiz / arq
        if not caminho.is_file():
            problemas.append(f"arquivo do manifesto ausente: {arq}")
        elif sha256(caminho) != esperado:
            problemas.append(f"arquivo alterado desde o manifesto: {arq}")
    return problemas


def main(argv):
    if "--gerar" in argv:
        m = gerar()
        print(f"manifesto regravado ({len(m['arquivos'])} arquivos). sha256 do manifesto: "
              f"{sha256(RAIZ / MANIFESTO)}  <- registre fora deste diretório")
        return 0
    problemas = verificar()
    for p in problemas:
        print("PROBLEMA:", p, file=sys.stderr)
    print("configuração íntegra" if not problemas else f"{len(problemas)} problema(s); não inicie a sessão")
    return 1 if problemas else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
