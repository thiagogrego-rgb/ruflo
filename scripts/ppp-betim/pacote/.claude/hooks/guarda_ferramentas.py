#!/usr/bin/env python3
"""Guarda de ferramentas do Claude Code para a PPP Centro Administrativo de Betim (GOV-05).

Hook PreToolUse. Lê o evento em JSON no stdin e decide por ferramenta:

- Write/Edit/MultiEdit/NotebookEdit: só grava em `produtos/<área>/`; cada agente
  nomeado só grava na(s) sua(s) área(s) (`governanca/matriz-agentes.json`).
  O caminho é resolvido (absoluto, relativo, `..`, symlinks) antes da decisão.
- Skill: um agente só invoca as skills da sua linha na matriz; agente fora da matriz
  não invoca nenhuma.
- Bash: subagentes não executam comandos; na sessão principal, comandos que escrevam
  em área protegida são recusados (detecção heurística, NÃO é barreira de SO).
- mcp__*: conectores não são usados por subagentes.

Toda decisão é registrada em `logs/guarda.jsonl` (rastreabilidade, não prova de autoria:
o log é do mesmo usuário do SO). Qualquer falha interna recusa a operação (exit 2).
A decisão é uma política da camada de ferramentas do Claude Code: não substitui
isolamento de SO nem autenticação humana."""
import glob
import json
import os
import shlex
import sys
import threading
import time
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # a pasta dos módulos do guarda é área protegida
from guarda_base import *  # noqa: E402,F401,F403
from guarda_base import _prefixo_estatico, _sigilosas_tocadas  # noqa: E402,F401
from guarda_bash import decide_bash  # noqa: E402

FERRAMENTAS_INTERNAS = {"TodoWrite", "ToolSearch", "TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "ExitPlanMode", "EnterPlanMode",
                        "AskUserQuestion"}     # sem E/S de arquivo nem de rede; todo o resto é recusado (fail-closed)

TEMPO_MAXIMO = min(10.0, float(os.environ.get("GUARDA_TEMPO_MAXIMO", 10)))             # segundos; o timeout do Claude Code é fail-ABERTO (medido), então ficamos bem abaixo

def decide_escrita(evento, matriz):
    ferramenta = evento["tool_name"]
    entrada = evento.get("tool_input") or {}
    base = evento.get("cwd") or RAIZ_REAL
    real = resolver(entrada.get(FERRAMENTAS_ARQUIVO[ferramenta]), base)
    partes = relativo_ao_projeto(real)
    agente = agente_do_evento(evento)
    if len(partes) < 3 or partes[0] != AREA_ESCRITA:
        # Maiúsculas/minúsculas diferentes de `produtos` também caem aqui (o nome é exato).
        raise Recusa(f"área protegida ou não autorizada para escrita: {'/'.join(partes) or '.'}")
    if agente:
        if agente not in matriz:
            raise Recusa(f"agente '{agente}' fora da matriz não grava arquivos")
        if f"{partes[0]}/{partes[1]}" not in matriz[agente].get("escrita", []):
            raise Recusa(f"agente '{agente}' não grava em {partes[0]}/{partes[1]}")
    return "/".join(partes)

def decide_leitura(evento):
    ferramenta = evento["tool_name"]
    entrada = evento.get("tool_input") or {}
    base = evento.get("cwd") or RAIZ_REAL
    sigilosas, principal, extra, _ = carregar_politica()
    agente = agente_do_evento(evento)
    if agente and agente not in extra:
        raise Recusa(f"agente '{agente}' fora da matriz não lê arquivos")
    liberadas = set(extra[agente] if agente else principal)
    campo = entrada.get(FERRAMENTAS_LEITURA[ferramenta])
    if campo is None and ferramenta != "Read":
        campo = "."                              # Grep/Glob sem path varrem o diretório de trabalho
    alvos = [campo]
    if ferramenta == "Glob" and isinstance(entrada.get("pattern"), str):
        pat = entrada["pattern"]
        alvos = [pat if os.path.isabs(os.path.expanduser(pat)) else os.path.join(str(resolver(campo, base)), pat)]
        alvos = [_prefixo_estatico(alvos[0])]
    real = resolver(alvos[0], base)
    try:
        partes = real.relative_to(RAIZ_REAL).parts
    except ValueError:
        if agente:
            raise Recusa(f"leitura fora do projeto: {real}")
        return None                                # sessão principal: fora do projeto segue o fluxo de permissões
    tocadas = _sigilosas_tocadas(partes, sigilosas, liberadas)
    if tocadas:
        permitido = "informe um caminho dentro de produtos/<sua pasta>, produtos/C, registros/, governanca/, arquitetura/, referencias/ ou .claude/skills"
        raise Recusa(f"leitura de área sigilosa não liberada para este agente ({', '.join(tocadas)}); {permitido}")
    return "/".join(partes) or "."

def decide_skill(evento, matriz):
    entrada = evento.get("tool_input") or {}
    candidatos = {entrada[k] for k in ("skill", "name", "skill_name") if k in entrada}
    if len(candidatos) > 1:
        raise Recusa("campos de nome da skill divergentes")
    nome = next(iter(candidatos), None)
    if not isinstance(nome, str) or not nome.strip():
        raise Recusa("nome da skill ausente")
    nome = nome.strip().lstrip("/")
    agente = agente_do_evento(evento)
    if not agente:
        return nome                       # sessão principal: decisão humana na sessão
    if agente not in matriz:
        raise Recusa(f"agente '{agente}' fora da matriz não invoca skills")
    if nome not in matriz[agente].get("skills", []):
        raise Recusa(f"skill '{nome}' não autorizada para o agente '{agente}'")
    return nome

def decide(evento):
    if not isinstance(evento, dict) or not isinstance(evento.get("tool_name"), str):
        raise Recusa("evento inválido")
    ferramenta = evento["tool_name"]
    if ferramenta in FERRAMENTAS_ARQUIVO:
        return decide_escrita(evento, carregar_matriz())
    if ferramenta in FERRAMENTAS_LEITURA:
        return decide_leitura(evento)
    if ferramenta == "Skill":
        return decide_skill(evento, carregar_matriz())
    if ferramenta == "Bash":
        return decide_bash(evento)
    if ferramenta.startswith("mcp__"):
        if agente_do_evento(evento):
            raise Recusa("conectores não são usados por subagentes deste projeto")
        if ferramenta not in carregar_politica()[3]:
            raise Recusa(f"conector '{ferramenta}' não consta de conectores_permitidos_sessao_principal")
        return ferramenta
    if ferramenta in FERRAMENTAS_INTERNAS:
        return None
    raise Recusa(f"ferramenta '{ferramenta}' fora do escopo deste projeto (rede, delegação e demais não são autorizadas)")

def _estouro():
    print("GOV-05: tempo interno do guarda esgotado; operação recusada", file=sys.stderr)
    sys.stderr.flush()
    os._exit(2)

def main():
    evento = None
    vigia = threading.Timer(TEMPO_MAXIMO, _estouro)
    vigia.daemon = True
    vigia.start()
    try:
        evento = json.loads(sys.stdin.read())
        alvo = decide(evento)
    except Consulta as erro:
        if isinstance(evento, dict) and evento.get("permission_mode") == "bypassPermissions":
            registrar(evento, "recusado", f"{erro} (modo bypassPermissions: sem consulta humana)")
            print(f"GOV-05: operação recusada — {erro}", file=sys.stderr)
            return 2
        if not registrar(evento, "consulta-humana", str(erro)) and log_obrigatorio():
            print("GOV-08: serviço de log indisponível; operação recusada", file=sys.stderr)
            return 2
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "ask",
            "permissionDecisionReason": f"GOV-05: {erro}; confirmação humana necessária"}}))
        return 0
    except Recusa as erro:
        registrar(evento, "recusado", str(erro))
        print(f"GOV-05: operação recusada — {erro}", file=sys.stderr)
        return 2
    except Exception as erro:       # falha interna: recusa (fail-closed)
        registrar(evento, "recusado", f"falha interna: {type(erro).__name__}")
        print(f"GOV-05: falha interna do guarda ({type(erro).__name__}); operação recusada",
              file=sys.stderr)
        return 2
    gravado = registrar(evento, "permitido", "ok", alvo)
    if not gravado and log_obrigatorio():
        print("GOV-08: serviço de log indisponível; operação recusada (sem trilha, sem execução)", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
