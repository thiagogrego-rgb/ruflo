"""Gera `requirements.lock` com hashes SHA-256 dos wheels publicados no PyPI (GOV-04).

Ferramenta de MANUTENÇÃO: exige rede e deve ser executada por um mantenedor, numa
máquina de desenvolvimento, nunca no host do guardião. O resultado é revisado e
versionado; o guardião e os agentes não a executam.

    python3 -I gerar_lock.py --saida requirements.lock \
        attrs==26.1.0 cffi==2.1.1 'typing-extensions==4.16.0;python_version < "3.13"' ...

Somente wheels entram no lock: com `pip install --require-hashes --only-binary=:all:`
nenhum sdist é aceito, logo nenhum código de build de terceiros é executado.
"""
import argparse
import json
import re
import sys
import urllib.request

PADRAO_ENTRADA = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][A-Za-z0-9._+!-]*)\s*(?:;\s*(.+))?$")
CABECALHO = """\
# GOV-04 - dependências travadas com hashes SHA-256 (somente wheels, CPython >= 3.11).
# Gerado por scripts/gerar_lock.py a partir dos metadados oficiais do PyPI; revisar o diff.
# Instalação reproduzível (venv de root, fora do alcance dos agentes):
#   python3 -m venv /opt/ppp-betim/venv
#   /opt/ppp-betim/venv/bin/pip install --require-hashes --only-binary=:all: --no-deps \\
#       -r requirements.lock
# Conferência: python3 -I scripts/ambiente.py --lock requirements.lock
"""


def normalizar(nome):
    return re.sub(r"[-_.]+", "-", nome).lower()


def buscar_pypi(nome, versao, timeout=30):
    url = f"https://pypi.org/pypi/{nome}/{versao}/json"
    with urllib.request.urlopen(url, timeout=timeout) as resposta:  # noqa: S310 (https fixo)
        return json.load(resposta)


def hashes_de_wheels(metadados):
    return sorted({arquivo["digests"]["sha256"] for arquivo in metadados["urls"]
                   if arquivo["packagetype"] == "bdist_wheel" and not arquivo.get("yanked")})


def gerar(entradas, buscar=buscar_pypi):
    blocos = []
    for entrada in sorted(entradas, key=lambda e: normalizar(PADRAO_ENTRADA.match(e).group(1))
                          if PADRAO_ENTRADA.match(e) else e):
        encontrado = PADRAO_ENTRADA.match(entrada.strip())
        if not encontrado:
            raise ValueError(f"Entrada inválida (use nome==versão[;marcador]): {entrada!r}")
        nome, versao, marcador = encontrado.groups()
        hashes = hashes_de_wheels(buscar(nome, versao))
        if not hashes:
            raise ValueError(f"{nome}=={versao}: nenhum wheel disponível; não há como travar com segurança")
        cabeca = f"{normalizar(nome)}=={versao}" + (f" ; {marcador.strip()}" if marcador else "")
        linhas = [f"{cabeca} \\"] + [f"    --hash=sha256:{h} \\" for h in hashes]
        linhas[-1] = linhas[-1].rstrip(" \\")
        blocos.append("\n".join(linhas))
    return CABECALHO + "\n" + "\n".join(blocos) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--saida", required=True)
    parser.add_argument("entradas", nargs="+")
    args = parser.parse_args(argv)
    conteudo = gerar(args.entradas)
    with open(args.saida, "x", encoding="utf-8") as arquivo:   # nunca sobrescreve
        arquivo.write(conteudo)
    print(f"{args.saida}: {len(args.entradas)} distribuições travadas")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as erro:
        print("ERRO:", erro, file=sys.stderr)
        sys.exit(1)
