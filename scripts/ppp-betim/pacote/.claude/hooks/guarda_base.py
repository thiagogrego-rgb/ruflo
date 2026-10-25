"""Núcleo comum do guarda de ferramentas (GOV-05/06): exceções, resolução de caminhos, matriz e política, log."""
import glob
import json
import os
import shlex
import sys
import threading
import time
import unicodedata
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]

RAIZ_REAL = Path(os.path.realpath(RAIZ))

FERRAMENTAS_ARQUIVO = {"Write": "file_path", "Edit": "file_path",
                       "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}

AREA_ESCRITA = "produtos"

FERRAMENTAS_LEITURA = {"Read": "file_path", "Grep": "path", "Glob": "path"}

GLOB_CHARS = "*?[{"

LIMITE_GLOB = 200            # padrão com mais resultados que isto é amplo demais para ser analisado

class Recusa(Exception):
    pass

class Consulta(Exception):
    """Caso ambíguo: a decisão passa ao humano da sessão (em modo não interativo, vira recusa)."""

def agente_do_evento(evento):
    """None = sessão principal; str não vazia = agente. Qualquer outra forma é recusada."""
    if "agent_type" not in evento:
        if evento.get("agent_id"):
            raise Recusa("evento de subagente sem agent_type")
        return None
    valor = evento["agent_type"]
    if not isinstance(valor, str) or not valor.strip():
        raise Recusa("agent_type inválido")
    return valor

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
        papel = os.environ.get("PPP_PAPEL", "")      # o lançador define; só escolhe QUAL log (cada papel tem o seu, só-anexar)
        nome = f"guarda-{papel}.jsonl" if papel and papel.replace("-", "").isalnum() and papel.islower() else "guarda.jsonl"
        fd = os.open(pasta / nome, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
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

def carregar_politica():
    """(áreas sigilosas, leitura extra da sessão principal, leitura extra por agente, conectores permitidos)."""
    try:
        d = json.loads((RAIZ / "governanca" / "matriz-agentes.json").read_text(encoding="utf-8"))
        sig = d["areas_sigilosas"]
        if not isinstance(sig, list) or not sig or not all(isinstance(x, str) and x for x in sig):
            raise ValueError("areas_sigilosas inválido")
        extra = {a: v.get("leitura_extra", []) for a, v in d["agentes"].items()}
        principal = d.get("sessao_principal", {}).get("leitura_extra", [])
        conectores = d.get("conectores_permitidos_sessao_principal", [])
        for lista in list(extra.values()) + [principal, conectores]:
            if not isinstance(lista, list):
                raise ValueError("lista inválida")
        return [tuple(x.split("/")) for x in sig], principal, extra, conectores
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as erro:
        raise Recusa(f"política de leitura ilegível ({type(erro).__name__}); operação recusada")

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

def _prefixo_estatico(padrao):
    """Parte do padrão de Glob anterior ao primeiro componente com curinga."""
    partes = padrao.split("/")
    fixas = []
    for i, p in enumerate(partes):
        if any(c in p for c in GLOB_CHARS):
            break
        fixas.append(p)
    return "/".join(fixas) if fixas != [""] else "/"

def _sigilosas_tocadas(partes, sigilosas, liberadas):
    """Áreas sigilosas não liberadas que `partes` é, contém ou está dentro."""
    tocadas = []
    for area in sigilosas:
        if "/".join(area) in liberadas:
            continue
        n = min(len(area), len(partes))
        if tuple(normaliza(x) for x in partes[:n]) == tuple(normaliza(x) for x in area[:n]):
            tocadas.append("/".join(area))
    return tocadas


__all__ = ['AREA_ESCRITA', 'Consulta', 'FERRAMENTAS_ARQUIVO', 'FERRAMENTAS_LEITURA', 'GLOB_CHARS', 'LIMITE_GLOB', 'RAIZ', 'RAIZ_REAL', 'Recusa', '_prefixo_estatico', '_sigilosas_tocadas', 'agente_do_evento', 'carregar_matriz', 'carregar_politica', 'normaliza', 'registrar', 'relativo_ao_projeto', 'resolver']
