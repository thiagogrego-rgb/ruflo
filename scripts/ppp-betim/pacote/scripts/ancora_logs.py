#!/usr/bin/env python3
"""Âncora externa das cadeias de log (GOV-09): detecta TRUNCAMENTO e reescrita que o serviço de log não consegue ver sozinho.

`publicar` grava, num diretório que NÃO é do serviço de log (do root, idealmente em mídia só-anexar ou enviado a outro host),
a cabeça (seq, hash) de cada cadeia. `verificar` confere que cada cabeça publicada ainda está EXATAMENTE onde estava: se o fim
da cadeia foi cortado ou o conteúdo reescrito, a cabeça publicada não bate. Registros novos depois da âncora não atrapalham.

LIMITE: protege contra o serviço de log comprometido e contra quem não controla o destino das âncoras. Se o destino for
alterável por quem altera os logs, não protege nada. Não assina as âncoras (use mídia só-anexar/remota).

    python3 -I -B scripts/ancora_logs.py publicar  --raiz DIR --destino /var/lib/ppp-betim/ancoras     (root)
    python3 -I -B scripts/ancora_logs.py verificar --raiz DIR --destino /var/lib/ppp-betim/ancoras
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolamento_base as B  # noqa: E402
import logd  # noqa: E402


def _logs(raiz, spec):
    return {nome: Path(raiz) / "logs" / nome for nome in B.nomes_de_log(spec)}


def publicar(raiz, spec, destino, agora=None):
    destino = Path(destino)
    st = os.lstat(destino)
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise SystemExit("o destino das âncoras deve ser do root e sem escrita para grupo/outros")
    cabecas = {}
    for nome, caminho in _logs(raiz, spec).items():
        problemas = logd.verificar(caminho)
        if problemas:
            raise SystemExit(f"não ancora cadeia corrompida ({nome}): {problemas[0]}")
        seq, h = logd.cabeca(caminho)
        cabecas[nome] = {"seq": seq, "hash": h}
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime(agora)) + f"-{time.monotonic_ns() % 1000000:06d}"
    conteudo = json.dumps({"ts": ts, "cabecas": cabecas}, sort_keys=True, indent=1) + "\n"
    fd = os.open(destino / f"ancora-{ts}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        os.write(fd, conteudo.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return ts, cabecas


def verificar(raiz, spec, destino):
    """Lista de problemas (vazia = todas as âncoras publicadas ainda batem com as cadeias atuais)."""
    problemas = []
    ancoras = sorted(Path(destino).glob("ancora-*.json"))
    if not ancoras:
        return ["nenhuma âncora publicada: sem ela o truncamento do fim da cadeia não é detectável"]
    logs = _logs(raiz, spec)
    registros = {}
    for nome, caminho in logs.items():
        p = logd.verificar(caminho)
        if p:
            problemas.append(f"{nome}: cadeia inválida ({p[0]})")
            continue
        registros[nome] = {json.loads(l)["seq"]: json.loads(l)["hash"] for l in logd._linhas(caminho)}
    for arq in ancoras:
        try:
            ancora = json.loads(arq.read_text(encoding="utf-8"))["cabecas"]
        except (OSError, ValueError, KeyError):
            problemas.append(f"{arq.name}: âncora ilegível")
            continue
        for nome, c in ancora.items():
            if nome not in registros:
                continue
            if c["seq"] == 0:
                continue
            atual = registros[nome].get(c["seq"])
            if atual is None:
                problemas.append(f"{nome}: TRUNCADA — a âncora {arq.name} registra seq {c['seq']} e a cadeia atual não chega lá")
            elif atual != c["hash"]:
                problemas.append(f"{nome}: REESCRITA — o hash do seq {c['seq']} difere do publicado em {arq.name}")
    return problemas


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("comando", choices=["publicar", "verificar"])
    ap.add_argument("--raiz", required=True)
    ap.add_argument("--destino", required=True)
    ap.add_argument("--spec", default=str(B.SPEC_PADRAO))
    a = ap.parse_args(argv)
    spec = B.carregar(a.spec)
    if a.comando == "publicar":
        ts, cabecas = publicar(os.path.realpath(a.raiz), spec, a.destino)
        print(json.dumps({"ancora": ts, "cabecas": cabecas}))
        return 0
    problemas = verificar(os.path.realpath(a.raiz), spec, a.destino)
    for p in problemas:
        print("PROBLEMA:", p, file=sys.stderr)
    print("âncoras conferem" if not problemas else f"{len(problemas)} problema(s)")
    return 1 if problemas else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
