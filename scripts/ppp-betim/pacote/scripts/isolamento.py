#!/usr/bin/env python3
"""Isolamento por sistema operacional dos papéis de sessão (GOV-07).

A matriz de leitura/escrita é realizada por dono, grupo e modo dos arquivos (DAC), aplicada a contas de SO distintas
por papel (`governanca/papeis.json`). Hooks, `deny` e sandbox viram defesa em profundidade: se falharem abertos
(timeout, configuração inválida), o kernel continua negando.

Subcomandos (todos aceitam --raiz, --spec, --json):
  validar   confere a especificação (e se os modos previstos realizam exatamente leitura/escrita declaradas)
  matriz    imprime a matriz prevista papel x área (tabela Markdown)
  contas    imprime (NÃO executa) os comandos groupadd/useradd para o administrador revisar
  aplicar   [root] aplica donos/grupos/modos, sentinelas, logs só-anexar e homes dos papéis
  auditar   confere a árvore real contra a especificação (donos, modos, setuid, world-writable, symlinks, ancestrais)
  sondar    [root] tenta de fato as operações COMO cada papel (fork + setuid) e compara com a previsão

Limites: DAC protege contra processos dos papéis; NÃO protege contra root/administrador, contra outro host nem contra
quem controla o compartilhamento de rede; Windows/macOS exigem equivalente próprio (NTFS ACL / permissões POSIX).
"""
import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
SPEC_PADRAO = RAIZ / "governanca" / "papeis.json"
SENTINELA = ".sentinela"
OPERACOES = ("listar", "ler", "criar", "sobrescrever", "renomear")


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


def validar(spec):
    problemas = []
    contas, grupos = spec["contas"], spec["grupos"]
    todos = list(contas.values()) + list(grupos.values())
    if len(set(contas.values())) != len(contas) or len(set(grupos.values())) != len(grupos):
        problemas.append("ids de contas ou de grupos duplicados")
    if any((not isinstance(i, int)) or i < 1000 for i in todos):
        problemas.append("ids devem ser inteiros >= 1000 (nunca root nem contas de sistema)")
    for nome, p in spec["papeis"].items():
        if p["conta"] in ("ppp-admin", "ppp-guardiao"):
            problemas.append(f"papel '{nome}' usa a conta privilegiada {p['conta']}")
        if p["conta"] not in contas or any(g not in grupos for g in p["grupos"]):
            problemas.append(f"papel '{nome}' referencia conta ou grupo inexistente")
    for a in spec["areas"]:
        c = a["caminho"]
        if os.path.isabs(c) or ".." in Path(c).parts:
            problemas.append(f"caminho de área inválido: {c}")
        if a["dono"] not in contas or a["grupo"] not in grupos:
            problemas.append(f"área {c}: dono/grupo inexistente")
            continue
        for k in ("modo_dir", "modo_arq"):
            if int(a[k], 8) & 0o002:
                problemas.append(f"área {c}: {k} permite escrita a 'outros'")
        dir_outros = (
            int(a["modo_dir"], 8) & 0o007 & ~(0o001 if a.get("logs_por_papel") else 0))
        if a.get("sigilosa") and (dir_outros or int(a["modo_arq"], 8) & 0o007):
            problemas.append(f"área sigilosa {c} legível ou gravável por 'outros'")
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
        cel = []
        for p in papeis:
            marca = ("L" if p in a["leitura"] else "-") + ("E" if p in a["escrita"] else "-")
            cel.append(marca)
        linhas.append(f"| `{a['caminho']}` ({a['dono']}:{a['grupo']} {a['modo_dir']}) | " + " | ".join(cel) + " |")
    linhas.append("\nL = lê e lista; E = cria/altera/renomeia; - = negado pelo kernel.")
    return "\n".join(linhas)


def comandos_contas(spec):
    saida = ["# REVISAR antes de executar como administrador (esta ferramenta não cria contas)."]
    for g, gid in spec["grupos"].items():
        saida.append(f"groupadd -g {gid} {g}")
    for c, uid in spec["contas"].items():
        papel = next((p for p in spec["papeis"].values() if p["conta"] == c), None)
        sup = f" -G {','.join(papel['grupos'])}" if papel else ""
        saida.append(f"groupadd -g {uid} {c} && useradd -r -M -u {uid} -g {c}{sup} -s /usr/sbin/nologin {c}")
    return "\n".join(saida)


def _percorrer(raiz):
    yield raiz
    def _falha(erro):
        raise erro      # diretório ilegível não pode virar "conforme" em silêncio

    for base, dirs, arqs in os.walk(raiz, followlinks=False, onerror=_falha):
        for n in dirs + arqs:
            yield Path(base) / n


def _rel(raiz, p):
    r = Path(p).relative_to(raiz).as_posix()
    return "." if r == "." else r


def _chattr(op, caminho):
    try:
        subprocess.run(["chattr", op, str(caminho)], check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def aplicar(raiz, spec, home_base=None):
    if os.geteuid() != 0:
        raise SystemExit("aplicar exige root (chown); nada foi alterado")
    raiz = Path(raiz)
    avisos = []
    for a in spec["areas"]:
        (raiz / a["caminho"]).mkdir(parents=True, exist_ok=True)
        s = raiz / a["caminho"] / SENTINELA
        s.touch()
    for p in _percorrer(raiz):
        rel = _rel(raiz, p)
        if p.name.startswith("guarda-") and rel.startswith("logs/"):
            continue
        st = os.lstat(p)
        tipo = "dir" if stat.S_ISDIR(st.st_mode) else "arq"
        uid, gid, modo = _dados(spec, rel, tipo)
        os.lchown(p, uid, gid)
        if not stat.S_ISLNK(st.st_mode):
            os.chmod(p, modo)
    logs = raiz / "logs"
    if logs.is_dir():
        area = area_de(spec, "logs")
        for nome, p in spec["papeis"].items():
            arq = logs / f"guarda-{nome}.jsonl"
            if arq.exists():
                _chattr("-a", arq)
            arq.touch()
            os.chown(arq, spec["contas"][p["conta"]], spec["grupos"][area["grupo"]])
            os.chmod(arq, 0o640)
            if not _chattr("+a", arq):
                avisos.append(f"chattr +a indisponível em {arq}: log não é só-anexar neste filesystem")
    if home_base:
        for nome, p in spec["papeis"].items():
            h = Path(home_base) / nome
            h.mkdir(parents=True, exist_ok=True)
            for d in (h, h / "tmp"):
                d.mkdir(parents=True, exist_ok=True)
                os.chown(d, spec["contas"][p["conta"]], spec["contas"][p["conta"]])
                os.chmod(d, 0o700)
    return avisos


def auditar(raiz, spec):
    raiz = Path(raiz)
    div = []
    for p in _percorrer(raiz):
        rel = _rel(raiz, p)
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode):
            alvo = Path(os.path.realpath(p))
            try:
                alvo_rel = alvo.relative_to(os.path.realpath(raiz)).as_posix()
            except ValueError:
                div.append(f"symlink aponta para fora do projeto: {rel}")
                continue
            if area_de(spec, alvo_rel) is not area_de(spec, rel):
                div.append(f"symlink cruza áreas: {rel} -> {alvo_rel}")
            continue
        modo = stat.S_IMODE(st.st_mode)
        if modo & 0o002:
            div.append(f"gravável por 'outros': {rel}")
        if stat.S_ISREG(st.st_mode) and modo & 0o6000:
            div.append(f"setuid/setgid em arquivo: {rel}")
        if p.name.startswith("guarda-") and rel.startswith("logs/"):
            continue
        tipo = "dir" if stat.S_ISDIR(st.st_mode) else "arq"
        uid, gid, esperado = _dados(spec, rel, tipo)
        if (st.st_uid, st.st_gid) != (uid, gid) or modo != esperado:
            div.append(f"{rel}: encontrado {st.st_uid}:{st.st_gid} {oct(modo)}, esperado {uid}:{gid} {oct(esperado)}")
    for nome, papel in spec["papeis"].items():
        arq = raiz / "logs" / f"guarda-{nome}.jsonl"
        if arq.exists():
            st = os.lstat(arq)
            if st.st_uid != spec["contas"][papel["conta"]] or stat.S_IMODE(st.st_mode) != 0o640:
                div.append(f"log do papel {nome}: dono ou modo incorretos")
            attrs = subprocess.run(["lsattr", "-d", str(arq)], capture_output=True, text=True).stdout.split(" ")[0]
            if "a" not in attrs:
                div.append(f"log do papel {nome} não é só-anexar (chattr +a)")
    try:
        if Path("/proc/sys/fs/protected_hardlinks").read_text().strip() != "1":
            div.append("fs.protected_hardlinks != 1: hardlink de arquivo legível por papel sem escrita seria possível")
    except OSError:
        div.append("não foi possível ler fs.protected_hardlinks")
    atual = os.path.realpath(raiz)
    while atual != "/":
        st = os.stat(atual)
        for nome in spec["papeis"]:
            uid, _, gids = ids_papel(spec, nome)
            if atual != os.path.realpath(raiz) and not _bit(uid, gids, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), 1):
                div.append(f"ancestral não atravessável pelo papel {nome}: {atual}")
        atual = os.path.dirname(atual)
    return sorted(set(div))


def _como(uid, gid, gids, funcao):
    """Executa `funcao()` num filho com os ids do papel; devolve o resultado serializável."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            os.setgroups(gids)
            os.setgid(gid)
            os.setuid(uid)
            try:
                os.setuid(0)
                recuperou = True
            except PermissionError:
                recuperou = False
            resultado = {"recuperou_root": recuperou, **funcao()}
        except Exception as erro:       # falha do próprio teste
            resultado = {"erro_do_teste": repr(erro)}
        os.write(w, json.dumps(resultado).encode())
        os._exit(0)
    os.close(w)
    dados = b""
    while True:
        bloco = os.read(r, 65536)
        if not bloco:
            break
        dados += bloco
    os.close(r)
    os.waitpid(pid, 0)
    return json.loads(dados or b"{}")


def _ler(caminho):
    with open(caminho, "rb") as f:
        return f.read()


def _abrir_rw(caminho):
    with open(caminho, "r+b"):
        pass


def _tentar(fn):
    try:
        fn()
        return True
    except OSError:
        return False


def _sondas(raiz, spec, papel):
    uid, gid, gids = ids_papel(spec, papel)
    raiz = Path(raiz)

    def corpo():
        res, pid = {}, os.getpid()
        escrevivel = None
        for a in spec["areas"]:
            d = raiz / a["caminho"]
            s = d / SENTINELA
            c = a["caminho"]
            res[f"{c}|listar"] = _tentar(lambda: os.listdir(d))
            res[f"{c}|ler"] = _tentar(lambda: _ler(s))
            nome = d / f".sonda-{pid}"

            def criar():
                os.close(os.open(nome, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            res[f"{c}|criar"] = _tentar(criar)
            if res[f"{c}|criar"]:
                _tentar(lambda: os.unlink(nome))
                escrevivel = escrevivel or d
            res[f"{c}|sobrescrever"] = _tentar(lambda: _abrir_rw(s))
            novo = d / f".sentinela-{pid}"

            def renomear():
                os.rename(s, novo)
                os.rename(novo, s)
            res[f"{c}|renomear"] = _tentar(renomear)
        ataques = {}
        if escrevivel is not None:
            for a in spec["areas"]:
                s = raiz / a["caminho"] / SENTINELA
                elo, duro = escrevivel / f".elo-{pid}", escrevivel / f".duro-{pid}"

                def via_elo():
                    os.symlink(s, elo)
                    try:
                        _ler(elo)
                    finally:
                        os.unlink(elo)
                ataques[f"{a['caminho']}|via_symlink"] = _tentar(via_elo)

                def via_duro():
                    os.link(s, duro)
                    os.unlink(duro)
                ataques[f"{a['caminho']}|hardlink"] = _tentar(via_duro)
        ataques["raiz|mover_area_registros"] = _tentar(lambda: os.rename(raiz / "registros", raiz / "registros-movido"))
        if ataques["raiz|mover_area_registros"]:
            _tentar(lambda: os.rename(raiz / "registros-movido", raiz / "registros"))
        logs = {}
        for outro in spec["papeis"]:
            arq = raiz / "logs" / f"guarda-{outro}.jsonl"
            logs[f"{outro}|anexar"] = _tentar(lambda: os.close(os.open(arq, os.O_WRONLY | os.O_APPEND)))
            logs[f"{outro}|truncar"] = _tentar(lambda: os.close(os.open(arq, os.O_WRONLY | os.O_TRUNC)))
            logs[f"{outro}|apagar"] = _tentar(lambda: os.unlink(arq))
        return {"areas": res, "ataques": ataques, "logs": logs}
    return _como(uid, gid, gids, corpo)


def sondar(raiz, spec):
    if os.geteuid() != 0:
        raise SystemExit("sondar exige root (para assumir os ids dos papéis); nada foi alterado")
    divergencias, registro = [], {}
    for papel in spec["papeis"]:
        r = _sondas(raiz, spec, papel)
        registro[papel] = r
        if "erro_do_teste" in r:
            divergencias.append(f"{papel}: erro do próprio teste: {r['erro_do_teste']}")
            continue
        if r["recuperou_root"]:
            divergencias.append(f"{papel}: processo recuperou root após setuid")
        for chave, obtido in r["areas"].items():
            caminho, op = chave.split("|")
            previsto = prever(spec, papel, caminho, op)
            if obtido != previsto:
                divergencias.append(f"{papel} {caminho} {op}: obtido {obtido}, previsto {previsto}")
        for chave, obtido in r["ataques"].items():
            caminho, ataque = chave.split("|")
            if ataque == "via_symlink":
                previsto = prever(spec, papel, caminho, "ler")
            elif ataque == "hardlink":      # com fs.protected_hardlinks=1: só quem lê E grava o original
                previsto = prever(spec, papel, caminho, "ler") and prever(spec, papel, caminho, "sobrescrever")
            else:
                previsto = False
            if obtido != previsto:
                divergencias.append(f"{papel} ataque {chave}: obtido {obtido}, previsto {previsto}")
        for chave, obtido in r["logs"].items():
            dono, op = chave.split("|")
            previsto = (dono == papel) if op == "anexar" else False
            if obtido != previsto:
                divergencias.append(f"{papel} log de {dono} {op}: obtido {obtido}, previsto {previsto}")
    return divergencias, registro


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("comando", choices=["validar", "matriz", "contas", "aplicar", "auditar", "sondar"])
    ap.add_argument("--raiz", default=str(RAIZ))
    ap.add_argument("--spec", default=str(SPEC_PADRAO))
    ap.add_argument("--home-base", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    a.raiz = os.path.realpath(a.raiz)
    spec = carregar(a.spec)
    if a.comando == "matriz":
        print(matriz_markdown(spec))
        return 0
    if a.comando == "contas":
        print(comandos_contas(spec))
        return 0
    problemas = validar(spec)
    if a.comando == "validar" or problemas:
        for p in problemas:
            print("PROBLEMA:", p, file=sys.stderr)
        print("especificação íntegra" if not problemas else f"{len(problemas)} problema(s) na especificação")
        return 1 if problemas else 0
    if a.comando == "aplicar":
        for aviso in aplicar(a.raiz, spec, a.home_base):
            print("AVISO:", aviso, file=sys.stderr)
        print("isolamento aplicado")
        return 0
    if a.comando == "auditar":
        div = auditar(a.raiz, spec)
    else:
        div, registro = sondar(a.raiz, spec)
        if a.json:
            print(json.dumps(registro, ensure_ascii=False, indent=1))
    for d in div:
        print("DIVERGÊNCIA:", d, file=sys.stderr)
    print("conforme" if not div else f"{len(div)} divergência(s)")
    return 1 if div else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
