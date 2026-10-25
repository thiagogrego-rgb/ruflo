#!/usr/bin/env python3
"""Jaula de namespace de montagem (bubblewrap) em volta do PROCESSO INTEIRO da sessão (GOV-07).

Mecanismo equivalente ao isolamento por contas de SO, útil em máquina de um só usuário (Linux/WSL2): as ferramentas
Read/Write/Edit/Grep/Glob e o terminal do agente passam a enxergar o projeto como o papel enxerga, por montagens
somente leitura e diretórios ocultos. Vale mesmo se hook, `deny` e `settings.json` falharem abertos.

Perfil do papel (derivado de `governanca/papeis.json`, a mesma fonte do isolamento por contas):
  - tudo somente leitura; HOME do papel gravável; /tmp privado;
  - gravável apenas onde o papel tem `escrita` (ex.: produtos/C ou produtos/P*), mais o próprio log (só-anexar);
  - áreas sigilosas sem `leitura` para o papel ficam VAZIAS e somente leitura;
  - sem capabilities, namespaces de usuário/IPC/PID próprios, `--die-with-parent`; a rede NÃO é isolada (o agente precisa da API).
Uso:  python3 scripts/jaula.py --papel PAPEL --raiz DIR --home DIR [--uid N --gid N] -- comando ...
"""
import argparse
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolamento as ISO  # noqa: E402


def argumentos_jaula(spec, papel, raiz, home, uid=None, gid=None):
    """Vetor `bwrap ...` (sem o comando final)."""
    if papel not in spec["papeis"]:
        raise ValueError(f"papel desconhecido: {papel}")
    raiz, home = str(raiz), str(home)
    a = ["bwrap", "--die-with-parent", "--unshare-user", "--unshare-ipc", "--unshare-pid", "--cap-drop", "ALL"]
    if uid is not None:
        a += ["--uid", str(uid), "--gid", str(gid if gid is not None else uid)]
    a += ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    if not (raiz.startswith("/tmp/") or home.startswith("/tmp/")):      # /tmp privado, salvo se o projeto mora nele (só em teste)
        a += ["--tmpfs", "/tmp"]
    a += ["--bind", home, home]
    for area in spec["areas"]:
        caminho = os.path.join(raiz, area["caminho"]) if area["caminho"] != "." else raiz
        if papel in area["escrita"]:
            a += ["--bind", caminho, caminho]
    log = os.path.join(raiz, "logs", f"guarda-{papel}.jsonl")
    for area in spec["areas"]:
        if area.get("sigilosa") and papel not in area["leitura"]:
            caminho = os.path.join(raiz, area["caminho"])
            a += ["--tmpfs", caminho]
            if area["caminho"] == "logs" and os.path.exists(log):      # o ponto de montagem do log precisa existir antes do ro
                a += ["--bind", log, log]
            a += ["--remount-ro", caminho]
    if os.path.exists(log) and not any("logs" == x["caminho"] and x.get("sigilosa") and papel not in x["leitura"] for x in spec["areas"]):
        a += ["--bind", log, log]
    return a + ["--chdir", raiz]


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--papel", required=True)
    ap.add_argument("--raiz", required=True)
    ap.add_argument("--home", required=True)
    ap.add_argument("--uid", type=int)
    ap.add_argument("--gid", type=int)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("comando", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    comando = a.comando[1:] if a.comando[:1] == ["--"] else a.comando
    if not comando:
        raise SystemExit("informe o comando após --")
    spec = ISO.carregar()
    problemas = ISO.validar(spec)
    if problemas:
        raise SystemExit("papeis.json inválido:\n  - " + "\n  - ".join(problemas))
    if not shutil.which("bwrap"):
        raise SystemExit("bubblewrap (bwrap) não encontrado: sem jaula, sem sessão")
    vetor = argumentos_jaula(spec, a.papel, os.path.realpath(a.raiz), os.path.realpath(a.home), a.uid, a.gid) + ["--", *comando]
    if a.dry_run:
        print(" ".join(vetor))
        return 0
    os.execvp("bwrap", vetor)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
