#!/usr/bin/env python3
"""Isolamento por sistema operacional dos papéis de sessão (GOV-07/08).

A matriz de leitura/escrita é realizada por dono, grupo e modo dos arquivos (DAC), aplicada a contas de SO distintas
por papel (`governanca/papeis.json`), uma conta por agente P1-P7. Hooks, `deny` e sandbox viram defesa em profundidade:
se falharem abertos (timeout, configuração inválida), o kernel continua negando.

Subcomandos (todos aceitam --raiz, --spec, --json):
  validar   confere a especificação (e se os modos previstos realizam exatamente leitura/escrita declaradas)
  matriz    imprime a matriz prevista papel x área (tabela Markdown)
  contas    imprime (NÃO executa) os comandos groupadd/useradd para o administrador revisar
  aplicar   [root] aplica donos/grupos/modos por descritor (sem seguir links), sentinelas, logs só-anexar e homes
  auditar   confere a árvore real contra a especificação (donos, modos, setuid, links, ACL, montagens, ancestrais)
  sondar    [root] tenta de fato as operações COMO cada papel (fork + setuid) e compara com a previsão

Limites: DAC protege contra processos dos papéis; NÃO protege contra root/administrador, contra outro host nem contra
quem controla o compartilhamento de rede; Windows/macOS exigem equivalente próprio (NTFS ACL / permissões POSIX).
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from isolamento_base import (OPERACOES, RAIZ, SENTINELA, SPEC_PADRAO, _bit, _dados, area_de, carregar,  # noqa: E402,F401
                             comandos_contas, ids_papel, matriz_markdown, nomes_de_log, prever, validar)
from isolamento_so import (_chattr, _como, _percorrer, _sondas, _tem_so_anexar, _tentar, aplicar, auditar,  # noqa: E402,F401
                           sondar)


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
        div = auditar(a.raiz, spec, a.home_base)
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
