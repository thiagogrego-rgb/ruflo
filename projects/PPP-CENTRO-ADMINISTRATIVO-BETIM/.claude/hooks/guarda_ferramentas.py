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
isolamento de SO nem autenticação humana.
"""
import glob
import json
import os
import shlex
import sys
import time
import unicodedata
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
RAIZ_REAL = Path(os.path.realpath(RAIZ))
FERRAMENTAS_ARQUIVO = {"Write": "file_path", "Edit": "file_path",
                       "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
AREA_ESCRITA = "produtos"

# Comandos sem efeito de escrita (por si só); redirecionamentos são checados à parte.
SOMENTE_LEITURA = {
    "cat", "ls", "head", "tail", "grep", "egrep", "fgrep", "rg", "wc", "sha256sum",
    "sha1sum", "md5sum", "file", "stat", "diff", "cmp", "echo", "pwd", "date", "sort",
    "uniq", "cut", "tr", "jq", "tree", "du", "realpath", "basename", "dirname", "true",
    "printf", "cd", "test", "[", "which", "env",
}
GIT_LEITURA = {"status", "log", "diff", "show", "ls-files", "rev-parse", "blame", "branch"}
INTERPRETES_INLINE = {"python": "-c", "python3": "-c", "node": "-e", "perl": "-e",
                      "ruby": "-e", "php": "-r"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
# Comandos cujos argumentos são, em sua maioria, apenas lidos: só o destino (último argumento,
# ou o valor de -t/--target-directory) é escrito.
DESTINO_ULTIMO = {"cp", "rsync", "install", "scp"}
# Prefixos que apenas repassam a execução ao comando seguinte.
ENVOLTORIOS = {"nohup", "nice", "time", "command", "exec", "sudo", "env", "stdbuf", "timeout",
               "setsid", "ionice", "builtin"}
# Comandos que executam outros comandos sobre caminhos que não aparecem no texto.
EXECUTORES_INDIRETOS = {"xargs", "parallel"}
GIT_SOBREESCREVE = {"reset", "clean", "restore", "stash", "checkout", "revert", "apply", "am"}
DINAMICOS = ("$(", "`", "${", "eval ", "base64", "xxd", "\\x", "\\0")
# Primeiro componente (sem distinguir maiúsculas) de caminhos que um comando de terminal
# não pode escrever; `produtos/` e o restante do sistema não entram na lista.
PROTEGIDOS = {"registros", "dados", "governanca", ".claude", "scripts", "testes",
              "arquitetura", "referencias", "logs", "projects", "claude.md",
              "claude.local.md", "requirements.txt", "requirements.lock", ".gitignore"}


class Recusa(Exception):
    pass


class Consulta(Exception):
    """Caso ambíguo: a decisão passa ao humano da sessão (em modo não interativo, vira recusa)."""


def normaliza(texto):
    return unicodedata.normalize("NFC", texto).casefold()


def registrar(evento, decisao, motivo, alvo=None):
    linha = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "decisao": decisao,
        "ferramenta": evento.get("tool_name") if isinstance(evento, dict) else None,
        "agente": (evento.get("agent_type") or "sessao-principal")
        if isinstance(evento, dict) else None,
        "alvo": alvo,
        "motivo": motivo,
    }
    try:
        pasta = RAIZ / "logs"
        pasta.mkdir(exist_ok=True)
        fd = os.open(pasta / "guarda.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            os.write(fd, (json.dumps(linha, ensure_ascii=False) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        pass            # falha de log não pode liberar a operação; a decisão já foi tomada


def carregar_matriz():
    try:
        dados = json.loads((RAIZ / "governanca" / "matriz-agentes.json").read_text(encoding="utf-8"))
        agentes = dados["agentes"]
        if not isinstance(agentes, dict) or not agentes:
            raise ValueError("matriz vazia")
        return agentes
    except (OSError, ValueError, KeyError, TypeError) as erro:
        raise Recusa(f"matriz de agentes ilegível ({type(erro).__name__}); operação recusada")


def resolver(caminho, base):
    """Caminho absoluto real (symlinks resolvidos, mesmo se o destino ainda não existe)."""
    if not isinstance(caminho, str) or not caminho.strip() or "\0" in caminho:
        raise Recusa("caminho ausente ou inválido")
    p = Path(os.path.expanduser(caminho))
    if not p.is_absolute():
        p = Path(base) / p
    return Path(os.path.realpath(p))


def relativo_ao_projeto(real):
    try:
        return real.relative_to(RAIZ_REAL).parts
    except ValueError:
        raise Recusa(f"destino fora do projeto: {real}")


def decide_escrita(evento, matriz):
    ferramenta = evento["tool_name"]
    entrada = evento.get("tool_input") or {}
    base = evento.get("cwd") or RAIZ_REAL
    real = resolver(entrada.get(FERRAMENTAS_ARQUIVO[ferramenta]), base)
    partes = relativo_ao_projeto(real)
    agente = evento.get("agent_type")
    if len(partes) < 3 or partes[0] != AREA_ESCRITA:
        # Maiúsculas/minúsculas diferentes de `produtos` também caem aqui (o nome é exato).
        raise Recusa(f"área protegida ou não autorizada para escrita: {'/'.join(partes) or '.'}")
    if agente:
        if agente not in matriz:
            raise Recusa(f"agente '{agente}' fora da matriz não grava arquivos")
        if f"{partes[0]}/{partes[1]}" not in matriz[agente].get("escrita", []):
            raise Recusa(f"agente '{agente}' não grava em {partes[0]}/{partes[1]}")
    return "/".join(partes)


def decide_skill(evento, matriz):
    entrada = evento.get("tool_input") or {}
    nome = entrada.get("skill") or entrada.get("name") or entrada.get("skill_name")
    if not isinstance(nome, str) or not nome.strip():
        raise Recusa("nome da skill ausente")
    nome = nome.strip().lstrip("/")
    agente = evento.get("agent_type")
    if not agente:
        return nome                       # sessão principal: decisão humana na sessão
    if agente not in matriz:
        raise Recusa(f"agente '{agente}' fora da matriz não invoca skills")
    if nome not in matriz[agente].get("skills", []):
        raise Recusa(f"skill '{nome}' não autorizada para o agente '{agente}'")
    return nome


def _separa_comandos(comando):
    lexer = shlex.shlex(comando.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    comandos, atual = [], []
    for token in lexer:
        if token and set(token) <= set(";&|()"):
            if atual:
                comandos.append(atual)
            atual = []
        else:
            atual.append(token)
    if atual:
        comandos.append(atual)
    return comandos


def _toca_area_protegida(token, base, destrutivo):
    """True se o token (ou um glob dele) designa uma área protegida do projeto."""
    candidato = token.split("=", 1)[-1] if "=" in token and not token.startswith("-") else token
    candidato = candidato.lstrip("<>")
    if not candidato or set(candidato) <= set("<>&|;()0123456789"):
        return False
    if candidato.startswith("-") and "/" not in candidato:
        return False
    alvos = [candidato]
    if any(c in candidato for c in "*?["):
        alvos = glob.glob(os.path.join(base, os.path.expanduser(candidato))) or [candidato]
    for alvo in alvos:
        real = resolver(alvo, base)
        try:
            partes = real.relative_to(RAIZ_REAL).parts
        except ValueError:
            continue
        if not partes:
            if destrutivo:
                return True        # `rm -r .` na raiz do projeto
            continue
        if normaliza(partes[0]) in PROTEGIDOS:
            return True
    return False


def _script_confiavel(comando, base):
    """`python3 [opções] scripts/x.py` ou `-m unittest`: código em área que o agente não grava."""
    if not comando or os.path.basename(comando[0]) not in {"python", "python3"}:
        return False
    i = 1
    while i < len(comando):
        t = comando[i]
        if t == "-m":
            return comando[i + 1:i + 2] == ["unittest"]
        if t == "-c":
            return False
        if t in ("-X", "-W"):
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        if not t.endswith(".py"):
            return False
        try:
            partes = resolver(t, base).relative_to(RAIZ_REAL).parts
        except ValueError:
            return False
        return len(partes) >= 2 and normaliza(partes[0]) in ("scripts", "testes")
    return False


def _desembrulha(c):
    """Remove prefixos como `nohup`, `timeout 5`, `env X=1` e devolve o comando real."""
    i = 0
    while i < len(c) and os.path.basename(c[i]) in ENVOLTORIOS:
        i += 1
        while i < len(c) and (c[i].startswith("-") or "=" in c[i] or c[i].replace(".", "", 1).isdigit()):
            i += 1
    return c[i:]


def _confere_symlink(c, base):
    """`ln -s ALVO LINK`: o alvo relativo vale a partir da pasta do LINK; recusa alvo protegido ou fora do projeto."""
    args = [t for t in c[1:] if not t.startswith("-")]
    if len(args) < 2:
        return
    link = resolver(args[-1], base)
    for origem in args[:-1]:
        alvo = Path(os.path.expanduser(origem))
        real = Path(os.path.realpath(alvo if alvo.is_absolute() else link.parent / alvo))
        try:
            partes = real.relative_to(RAIZ_REAL).parts
        except ValueError:
            raise Recusa(f"link simbólico apontando para fora do projeto: {origem}")
        if partes and normaliza(partes[0]) in PROTEGIDOS:
            raise Recusa(f"link simbólico para área protegida: {origem}")


def _confere_codigo_de_agente(c, nome, base):
    """Executar arquivo de `produtos/` roda código que um agente pode ter escrito: decisão humana."""
    def em_produtos(token):
        if token.startswith("-") or "=" in token:
            return False
        try:
            partes = resolver(token, base).relative_to(RAIZ_REAL).parts
        except (ValueError, Recusa):
            return False
        return bool(partes) and partes[0] == AREA_ESCRITA and Path(os.path.realpath(
            Path(base) / token if not os.path.isabs(token) else token)).is_file()
    candidatos = []
    if "/" in c[0]:
        candidatos.append(c[0])
    if nome in SHELLS or nome in INTERPRETES_INLINE:
        candidatos += c[1:]
    if any(em_produtos(t) for t in candidatos):
        raise Consulta("execução de arquivo de produtos/ (pode ter sido escrito por um agente)")


def decide_bash(evento, profundidade=0, comando=None, base=None):
    if evento.get("agent_type"):
        raise Recusa("subagentes não executam comandos de terminal")
    if comando is None:
        comando = (evento.get("tool_input") or {}).get("command")
    if not isinstance(comando, str) or not comando.strip():
        raise Recusa("comando ausente")
    base = base or evento.get("cwd") or RAIZ_REAL
    try:
        simples = _separa_comandos(comando)
    except ValueError as erro:
        raise Recusa(f"comando não analisável ({erro}); recusado por prudência")
    redirecionamentos = [t for c in simples for t in c if t.lstrip("0123456789&").startswith(">")]
    destinos = []
    for c in simples:
        for i, t in enumerate(c):
            if t.lstrip("0123456789&").startswith(">") and i + 1 < len(c):
                destinos.append(c[i + 1])
    dinamico = any(d in comando for d in DINAMICOS)
    for c in simples:
        c = _desembrulha(c)
        if not c:
            continue
        nome = os.path.basename(c[0])
        if nome in ("cd", "pushd") and len(c) > 1:
            base = str(resolver(c[1], base))      # `cd registros && touch x` continua protegido
            continue
        if _script_confiavel(c, base):
            continue
        if profundidade == 0 and nome in SHELLS | set(INTERPRETES_INLINE):
            flag = "-c" if nome in SHELLS else INTERPRETES_INLINE[nome]
            if flag in c[1:] and c.index(flag) + 1 < len(c):
                codigo = c[c.index(flag) + 1]
                if nome in SHELLS:
                    decide_bash(evento, 1, codigo, base)
                else:
                    if any(p in normaliza(codigo) for p in PROTEGIDOS):
                        raise Recusa(f"código inline menciona área protegida ({nome} {flag})")
                    raise Consulta(f"código inline em {nome} não é analisável")
                continue
        _confere_codigo_de_agente(c, nome, base)
        if nome in EXECUTORES_INDIRETOS or (nome == "find" and any(
                a in c for a in ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint"))):
            raise Consulta(f"'{nome}' aplica comandos a caminhos que o texto não mostra")
        if nome == "ln":
            _confere_symlink(c, base)
        so_leitura = nome in SOMENTE_LEITURA or nome == "find" or (
            nome == "sed" and not any(a == "--in-place" or (a.startswith("-i") and not a.startswith("--"))
                                      for a in c[1:])) or (
            nome == "git" and len(c) > 1 and c[1] in GIT_LEITURA)
        if so_leitura and not redirecionamentos:
            continue
        destrutivo = nome in {"rm", "rmdir", "mv", "shred", "unlink"}
        alvos = c if not so_leitura else []
        if nome in DESTINO_ULTIMO:
            alvos = [c[-1]] if len(c) > 1 else []
            alvos += [c[i + 1] for i, t in enumerate(c[:-1]) if t == "-t"]
            alvos += [t.split("=", 1)[1] for t in c if t.startswith("--target-directory=")]
        for t in alvos + destinos:
            if _toca_area_protegida(t, base, destrutivo):
                raise Recusa(f"comando com efeito de escrita sobre área protegida: {t}")
        if nome == "git" and any(a in GIT_SOBREESCREVE for a in c[1:3]):
            raise Consulta("operação git que pode sobrescrever áreas protegidas")
        if dinamico and (not so_leitura or redirecionamentos):
            raise Consulta("construção dinâmica com possível efeito de escrita não analisável")
    return comando[:200]


def decide(evento):
    if not isinstance(evento, dict) or not isinstance(evento.get("tool_name"), str):
        raise Recusa("evento inválido")
    ferramenta = evento["tool_name"]
    if ferramenta in FERRAMENTAS_ARQUIVO:
        return decide_escrita(evento, carregar_matriz())
    if ferramenta == "Skill":
        return decide_skill(evento, carregar_matriz())
    if ferramenta == "Bash":
        return decide_bash(evento)
    if ferramenta.startswith("mcp__") and evento.get("agent_type"):
        raise Recusa("conectores não são usados por subagentes deste projeto")
    return None


def main():
    evento = None
    try:
        evento = json.loads(sys.stdin.read())
        alvo = decide(evento)
    except Consulta as erro:
        registrar(evento, "consulta-humana", str(erro))
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
    if alvo is not None:
        registrar(evento, "permitido", "ok", alvo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
