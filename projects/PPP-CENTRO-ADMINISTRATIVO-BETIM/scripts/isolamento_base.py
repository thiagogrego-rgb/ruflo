"""Especificação de isolamento por SO (GOV-07/08): leitura da spec, previsão POSIX, validação e textos.

Sem efeitos colaterais: nada aqui altera arquivos, contas ou processos.
"""
import json
import os
import re
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
SPEC_PADRAO = RAIZ / "governanca" / "papeis.json"
SENTINELA = ".sentinela"
OPERACOES = ("listar", "ler", "criar", "sobrescrever", "renomear")
CHAVES_AREA = {"caminho", "dono", "grupo", "modo_dir", "modo_arq", "leitura", "escrita", "sigilosa", "logs_de_servico", "nota"}
CHAVES_PAPEL = {"conta", "grupos", "agente_padrao"}


def carregar(caminho=SPEC_PADRAO):
    return json.loads(Path(caminho).read_text(encoding="utf-8"))


def ids_papel(spec, papel):
    p = spec["papeis"][papel]
    uid = spec["contas"][p["conta"]]
    return uid, uid, sorted({spec["grupos"][g] for g in p["grupos"]} | {uid})


def area_de(spec, rel):
    rel = "." if rel in ("", None) else str(rel).strip("/")
    padrao = melhor = None
    for a in spec["areas"]:
        c = a["caminho"]
        if c == ".":
            padrao = a
        elif rel == c or rel.startswith(c + "/"):
            if melhor is None or len(c) > len(melhor["caminho"]):
                melhor = a
    return melhor or padrao


def _dados(spec, rel, tipo):
    """(uid_dono, gid_grupo, modo) esperados de um caminho, por tipo 'dir' ou 'arq'."""
    a = area_de(spec, rel)
    return spec["contas"][a["dono"]], spec["grupos"][a["grupo"]], int(a["modo_dir" if tipo == "dir" else "modo_arq"], 8)


def _bit(uid, gids, dono, grupo, modo, bit):
    if uid == 0:
        return True
    classe = (modo >> 6) if uid == dono else (modo >> 3) if grupo in gids else modo
    return bool(classe & 7 & bit)


def _ancestrais_ok(spec, uid, gids, rel):
    """Permissão de travessia (x) na raiz e em cada diretório antes de `rel`."""
    partes = [] if rel in ("", ".") else rel.split("/")
    caminhos = ["."] + ["/".join(partes[:i + 1]) for i in range(len(partes) - 1)]
    return all(_bit(uid, gids, *_dados(spec, c, "dir"), 1) for c in caminhos)


def prever(spec, papel, rel, op):
    """Previsão POSIX de `op` na pasta `rel` (e no arquivo sentinela dentro dela) para o papel."""
    uid, _, gids = ids_papel(spec, papel)
    if not _ancestrais_ok(spec, uid, gids, rel):
        return False
    d = _dados(spec, rel, "dir")
    arq = _dados(spec, rel, "arq")
    x = _bit(uid, gids, *d, 1)
    if op == "listar":
        return _bit(uid, gids, *d, 4)
    if op == "ler":
        return x and _bit(uid, gids, *arq, 4)
    if op in ("criar", "renomear"):
        return x and _bit(uid, gids, *d, 2)
    if op == "sobrescrever":
        return x and _bit(uid, gids, *arq, 2)
    raise ValueError(op)


MODO = re.compile(r"^[0-7]{4}$")


def _validar_forma(spec):
    p = []
    for chave in ("contas", "grupos", "papeis", "areas"):
        if chave not in spec:
            p.append(f"chave obrigatória ausente: {chave}")
    if p:
        return p
    for nome, papel in spec["papeis"].items():
        if set(papel) - CHAVES_PAPEL or not isinstance(papel.get("grupos"), list):
            p.append(f"papel '{nome}' com chaves ou tipos inválidos")
    for a in spec["areas"]:
        extra = set(a) - CHAVES_AREA
        if extra:
            p.append(f"área {a.get('caminho')}: chaves desconhecidas {sorted(extra)}")
        for k in ("leitura", "escrita"):
            if not isinstance(a.get(k), list) or any(x not in spec["papeis"] for x in a.get(k, [])):
                p.append(f"área {a.get('caminho')}: '{k}' deve ser lista de papéis existentes")
    for a in spec["areas"]:
        for k in ("caminho", "dono", "grupo", "modo_dir", "modo_arq", "leitura", "escrita"):
            if k not in a:
                p.append(f"área {a.get('caminho')}: campo obrigatório ausente: {k}")
        for k in ("modo_dir", "modo_arq"):
            if k in a and not (isinstance(a[k], str) and MODO.match(a[k])):
                p.append(f"área {a.get('caminho')}: {k} deve ser octal de quatro dígitos")
    for k in ("logd_socket", "gateway_socket", "dir", "conta_log", "conta_rede", "grupo_socket", "grupos_contas_servico"):
        if k not in spec.get("servicos", {}):
            p.append(f"servicos.{k} ausente")
    if "upstream" not in spec.get("rede", {}) or not spec.get("rede", {}).get("caminhos_permitidos"):
        p.append("rede.upstream e rede.caminhos_permitidos são obrigatórios")
    if not str(spec.get("home_base", "")).startswith("/"):
        p.append("home_base deve ser caminho absoluto")
    for nome, papel in spec["papeis"].items():
        if not papel.get("agente_padrao"):
            p.append(f"papel '{nome}' sem agente_padrao")
    caminhos = [a.get("caminho") for a in spec["areas"]]
    if len(set(caminhos)) != len(caminhos):
        p.append("áreas duplicadas")
    return p


def validar(spec):
    problemas = _validar_forma(spec)
    if problemas:
        return problemas
    contas, grupos = spec["contas"], spec["grupos"]
    todos = list(contas.values()) + list(grupos.values())
    if len(set(contas.values())) != len(contas) or len(set(grupos.values())) != len(grupos):
        problemas.append("ids de contas ou de grupos duplicados")
    if set(contas.values()) & set(grupos.values()):
        problemas.append("id de grupo colide com id de conta (o grupo privado de cada conta usa o mesmo número)")
    if any((not isinstance(i, int)) or i < 1000 for i in todos):
        problemas.append("ids devem ser inteiros >= 1000 (nunca root nem contas de sistema)")
    usadas = [p["conta"] for p in spec["papeis"].values()]
    if len(set(usadas)) != len(usadas):
        problemas.append("dois papéis compartilham a mesma conta de SO")
    servicos = {spec.get("servicos", {}).get(k) for k in ("conta_log", "conta_rede")}
    for nome, p in spec["papeis"].items():
        if p["conta"] in ("ppp-admin", "ppp-guardiao", "ppp-rede") or p["conta"] in servicos:
            problemas.append(f"papel '{nome}' usa a conta privilegiada ou de serviço {p['conta']}")
        if p["conta"] not in contas or any(g not in grupos for g in p["grupos"]):
            problemas.append(f"papel '{nome}' referencia conta ou grupo inexistente")
    por_conta = {p["conta"]: n for n, p in spec["papeis"].items()}
    for a in spec["areas"]:
        c = a["caminho"]
        if os.path.isabs(c) or ".." in Path(c).parts:
            problemas.append(f"caminho de área inválido: {c}")
        if a["dono"] not in contas or a["grupo"] not in grupos:
            problemas.append(f"área {c}: dono/grupo inexistente")
            continue
        md, ma = int(a["modo_dir"], 8), int(a["modo_arq"], 8)
        for k, m in (("modo_dir", md), ("modo_arq", ma)):
            if m & 0o002:
                problemas.append(f"área {c}: {k} permite escrita a 'outros'")
            if m & 0o020:
                problemas.append(f"área {c}: {k} permite escrita ao grupo (a escrita é só do dono)")
        if ma & 0o7000 or md & 0o5000:
            problemas.append(f"área {c}: bit especial indevido (setuid/sticky; só setgid em diretório é aceito)")
        outros = a.get("sigilosa") and (md & 0o007 or ma & 0o007)
        if outros:
            problemas.append(f"área sigilosa {c} legível ou gravável por 'outros'")
        dono_papel = por_conta.get(a["dono"])
        if a["escrita"] != ([dono_papel] if dono_papel else []):
            problemas.append(f"área {c}: quem escreve deve ser exatamente o papel dono da área (e só ele); dono de papel sem escrita é proibido")
        if a.get("sigilosa") and dono_papel:
            problemas.append(f"área sigilosa {c} tem como dono uma conta de papel (o dono sempre pode mudar modo e grupo): use uma pasta-casca do administrador")
    if problemas:
        return problemas
    for a in spec["areas"]:
        for papel in spec["papeis"]:
            ler = prever(spec, papel, a["caminho"], "ler") and prever(spec, papel, a["caminho"], "listar")
            esc = prever(spec, papel, a["caminho"], "criar")
            if ler != (papel in a["leitura"]):
                problemas.append(f"área {a['caminho']}: leitura prevista pelos modos ({ler}) difere da declarada para '{papel}'")
            if esc != (papel in a["escrita"]):
                problemas.append(f"área {a['caminho']}: escrita prevista pelos modos ({esc}) difere da declarada para '{papel}'")
    return problemas


def matriz_markdown(spec):
    papeis = list(spec["papeis"])
    linhas = ["| Área | " + " | ".join(papeis) + " |", "|---|" + "---|" * len(papeis)]
    for a in spec["areas"]:
        cel = [("L" if p in a["leitura"] else "-") + ("E" if p in a["escrita"] else "-") for p in papeis]
        linhas.append(f"| `{a['caminho']}` ({a['dono']}:{a['grupo']} {a['modo_dir']}) | " + " | ".join(cel) + " |")
    linhas.append("\nL = lê e lista; E = cria/altera/renomeia; - = negado pelo kernel.")
    return "\n".join(linhas)


def comandos_contas(spec):
    saida = ["# REVISAR antes de executar como administrador (esta ferramenta não cria contas)."]
    for g, gid in spec["grupos"].items():
        saida.append(f"groupadd -g {gid} {g}")
    for c, uid in spec["contas"].items():
        papel = next((p for p in spec["papeis"].values() if p["conta"] == c), None)
        if papel:
            sup = f" -G {','.join(papel['grupos'])}"
        elif c in (spec.get("servicos", {}).get("conta_log"), spec.get("servicos", {}).get("conta_rede")):
            sup = f" -G {','.join(spec['servicos'].get('grupos_contas_servico', []))}"        # contas de serviço atravessam o projeto
        else:
            sup = ""
        saida.append(f"groupadd -g {uid} {c} && useradd -r -M -u {uid} -g {c}{sup} -s /usr/sbin/nologin {c}")
    return "\n".join(saida)


def nomes_de_log(spec):
    """Nomes exatos permitidos em logs/: um por papel, mais o log de rede."""
    return [f"guarda-{p}.jsonl" for p in spec["papeis"]] + ["rede.jsonl"]
