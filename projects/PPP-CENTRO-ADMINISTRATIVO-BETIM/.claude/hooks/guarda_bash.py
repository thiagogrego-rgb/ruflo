"""Análise heurística de comandos de terminal da sessão principal (GOV-05/06). NÃO é barreira de SO."""
import glob
import json
import os
import shlex
import sys
import threading
import time
import unicodedata
from pathlib import Path

from guarda_base import *  # noqa: F401,F403
from guarda_base import _prefixo_estatico, _sigilosas_tocadas  # noqa: F401

APLICADORES = {"unzip", "patch", "cpio", "7z", "7za", "bsdtar", "make", "gmake", "ninja", "cmake",
               "npm", "npx", "yarn", "pnpm", "pip", "pip3", "cargo", "mvn", "gradle", "ansible-playbook"}

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

# Comandos que executam o conteúdo de um arquivo passado como argumento.
EXECUTORES_DE_ARQUIVO = {"source", ".", "awk", "gawk", "mawk", "sed", "lua", "Rscript", "julia", "tclsh",
                         "expect", "deno", "bun", "ts-node", "java", "ex", "ed", "vim", "vi"}

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

def _expande(padrao, base):
    absoluto = os.path.join(base, os.path.expanduser(padrao))
    try:
        Path(os.path.realpath(_prefixo_estatico(absoluto))).relative_to(RAIZ_REAL)
    except ValueError:
        return [padrao]            # fora do projeto: nada a proteger, e evita varrer o sistema inteiro
    achados = []
    for i, caminho in enumerate(glob.iglob(os.path.join(base, os.path.expanduser(padrao)))):
        if i >= LIMITE_GLOB:
            raise Recusa(f"padrão amplo demais para análise (mais de {LIMITE_GLOB} resultados): {padrao}")
        achados.append(caminho)
    return achados or [padrao]

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
        alvos = _expande(candidato, base)
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

def _tar_extrai(args):
    for a in args:
        if a in ("--extract", "--get"):
            return True
        letras = a.lstrip("-")
        if not a.startswith("--") and letras.isalpha() and len(letras) <= 6 and "x" in letras:
            return True
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
    if nome in SHELLS or nome in INTERPRETES_INLINE or nome in EXECUTORES_DE_ARQUIVO:
        candidatos += c[1:]
    if any(em_produtos(t) for t in candidatos):
        raise Consulta("execução de arquivo de produtos/ (pode ter sido escrito por um agente)")

def _confere_leitura_sigilosa(c, base):
    """Terminal da sessão principal: nenhum comando (exceto scripts confiáveis) toca área sigilosa."""
    sigilosas, principal, _, _ = carregar_politica()
    for t in c:
        candidato = t.split("=", 1)[-1].lstrip("<>")
        if not candidato or candidato.startswith("-") and "/" not in candidato:
            continue
        alvos = [candidato]
        if any(ch in candidato for ch in "*?["):
            alvos = _expande(candidato, base)
        for alvo in alvos:
            try:
                partes = resolver(alvo, base).relative_to(RAIZ_REAL).parts
            except ValueError:
                continue
            tocadas = _sigilosas_tocadas(partes, sigilosas, set(principal))
            # tocar só o pai (ex.: `ls dados`) não revela conteúdo; exige estar dentro da área sigilosa
            dentro = [a for a in tocadas if len(partes) >= len(a.split("/"))]
            if dentro:
                raise Recusa(f"comando toca área sigilosa: {dentro[0]}")

def decide_bash(evento, profundidade=0, comando=None, base=None):
    if agente_do_evento(evento):
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
        _confere_leitura_sigilosa(c, base)
        _confere_codigo_de_agente(c, nome, base)
        if nome in APLICADORES or (nome in ("tar", "gtar", "bsdtar") and _tar_extrai(c[1:3])):
            raise Consulta(f"'{nome}' aplica/extrai conteúdo sobre caminhos que o texto não mostra")
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
            if _toca_area_protegida(t, base, destrutivo or nome in DESTINO_ULTIMO):
                raise Recusa(f"comando com efeito de escrita sobre área protegida: {t}")
        if nome == "git" and any(a in GIT_SOBREESCREVE for a in c[1:3]):
            raise Consulta("operação git que pode sobrescrever áreas protegidas")
        if dinamico and (not so_leitura or redirecionamentos):
            raise Consulta("construção dinâmica com possível efeito de escrita não analisável")
    return comando[:200]
