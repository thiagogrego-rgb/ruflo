#!/usr/bin/env python3
"""Jaula de namespace de montagem e de rede (bubblewrap) em volta do PROCESSO INTEIRO da sessão (GOV-07/08).

Mecanismo equivalente ao isolamento por contas de SO, útil em máquina de um só usuário (Linux/WSL2): as ferramentas
Read/Write/Edit/Grep/Glob e o terminal do agente passam a enxergar o projeto como o papel enxerga, por montagens
somente leitura e diretórios ocultos. Vale mesmo se hook, `deny` e `settings.json` falharem abertos.

Perfil do papel (derivado de `governanca/papeis.json`, a mesma fonte do isolamento por contas):
  - tudo somente leitura; HOME do papel gravável; /tmp privado; /root, /home, /mnt, /media, /run, /var/tmp ocultos
    (só o necessário é re-exposto: projeto, home do papel, diretório de serviços);
  - gravável apenas onde o papel tem `escrita`; áreas que o papel não lê ficam VAZIAS e somente leitura;
  - os logs NÃO são graváveis: o hook fala com o serviço de log por socket Unix;
  - rede: `gateway` (padrão) = namespace de rede próprio, sem rota nenhuma; a única saída é o socket do gateway;
    `aberta` = rede do host (só dados sintéticos, explícito);
  - sem capabilities, namespaces de usuário/IPC/PID/UTS próprios, `--die-with-parent`.
Uso:  python3 scripts/jaula.py --papel PAPEL --raiz DIR --home DIR [--rede gateway|aberta] [--uid N --gid N] -- comando ...
"""
import argparse
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolamento as ISO  # noqa: E402

OCULTAR = ("/root", "/home", "/mnt", "/media", "/run", "/var/tmp", "/tmp")


def _dentro(caminho, pasta):
    return caminho == pasta or caminho.startswith(pasta + "/")


def argumentos_jaula(spec, papel, raiz, home, uid=None, gid=None, rede="gateway", extra_ro=()):
    """Vetor `bwrap ...` (sem o comando final)."""
    if papel not in spec["papeis"]:
        raise ValueError(f"papel desconhecido: {papel}")
    if rede not in ("gateway", "aberta"):
        raise ValueError(f"modo de rede desconhecido: {rede}")
    raiz, home = str(raiz), str(home)
    a = [shutil.which("bwrap") or "bwrap", "--die-with-parent", "--unshare-user", "--unshare-ipc",
         "--unshare-pid", "--unshare-uts", "--unshare-cgroup-try", "--disable-userns", "--cap-drop", "ALL"]      # sem --new-session: quebraria a sessão interativa (não testada)
    if rede == "gateway":
        a.append("--unshare-net")
    if uid is not None:
        a += ["--uid", str(uid), "--gid", str(gid if gid is not None else uid)]
    a += ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    servicos = spec.get("servicos", {}).get("dir")
    expor = [(raiz, "ro"), (home, "rw")] + [(str(p), "ro") for p in extra_ro]
    if servicos and os.path.isdir(servicos):
        expor.append((servicos, "ro"))
    for pasta in OCULTAR:
        if not os.path.isdir(pasta):
            continue
        a += ["--tmpfs", pasta]
        for caminho, modo in sorted((x for x in expor if _dentro(x[0], pasta)), key=lambda x: len(x[0])):
            a += ["--bind" if modo == "rw" else "--ro-bind", caminho, caminho]
    if not any(_dentro(home, p) for p in OCULTAR if os.path.isdir(p)):
        pai = os.path.dirname(home)
        if pai not in ("", "/") and not _dentro(raiz, pai) and not _dentro(pai, raiz) and os.path.isdir(pai):
            a += ["--tmpfs", pai]                   # esconde os homes dos OUTROS papéis (só o próprio volta, abaixo)
        a += ["--bind", home, home]                 # home fora das pastas ocultas: só precisa ficar gravável
    for area in spec["areas"]:
        caminho = os.path.join(raiz, area["caminho"]) if area["caminho"] != "." else raiz
        if papel in area["escrita"]:
            a += ["--bind", caminho, caminho]
    ocultas = []
    for area in sorted(spec["areas"], key=lambda x: len(x["caminho"])):        # pais antes dos filhos
        if papel not in area["leitura"]:        # oculta por falta de leitura, não pelo rótulo "sigilosa"
            caminho = os.path.join(raiz, area["caminho"])
            if any(_dentro(caminho, o) for o in ocultas):
                continue                         # já está dentro de uma pasta oculta (e somente leitura)
            ocultas.append(caminho)
            a += ["--tmpfs", caminho, "--remount-ro", caminho]
    return a + ["--chdir", raiz]


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--papel", required=True)
    ap.add_argument("--raiz", required=True)
    ap.add_argument("--home", required=True)
    ap.add_argument("--uid", type=int)
    ap.add_argument("--gid", type=int)
    ap.add_argument("--rede", default="gateway", choices=["gateway", "aberta"])
    ap.add_argument("--extra-ro", action="append", default=[], help="caminho extra visível somente leitura (repetível)")
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
    vetor = argumentos_jaula(spec, a.papel, os.path.realpath(a.raiz), os.path.realpath(a.home), a.uid, a.gid, a.rede, [os.path.realpath(x) for x in a.extra_ro]) + ["--", *comando]
    if a.dry_run:
        print(" ".join(vetor))
        return 0
    os.execvp(vetor[0], vetor)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
