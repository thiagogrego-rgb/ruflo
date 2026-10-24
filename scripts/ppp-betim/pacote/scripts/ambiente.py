"""Verificação do ambiente Python contra `requirements.lock` (GOV-04, risco R10).

Confere, para cada distribuição travada no lock:
- presença e versão EXATA (ausente ou incompatível => recusa);
- integridade de cada arquivo instalado contra o hash do RECORD do pip;
- ausência de arquivos de código não listados no RECORD (injeção em pacote existente);
- proteção contra escrita de terceiros nos diretórios do pacote (com `uid_servico`).
E, no interpretador: modo isolado (-I) e proteção de cada diretório de `sys.path`, de
arquivos `.pth` e de `sitecustomize`/`usercustomize`, que executam código na inicialização.

Limites honestos:
- O RECORD é um arquivo comum: quem pode reescrever o pacote e o RECORD anula a checagem de
  hashes. A barreira real é o dono/permissão dos diretórios (checada com `uid_servico`).
- `.pyc` em `__pycache__` não têm hash no RECORD, então um `.pyc` adulterado (com o `.py`
  intacto) escaparia da checagem. Por isso, com `exigir_sem_pyc`, o interpretador deve rodar
  com `-X pycache_prefix=<dir>`: o Python deixa de carregar o bytecode ao lado do código e
  compila a partir das fontes cujo hash foi conferido. Sem isso, `__pycache__` não é verificável.
- Só dependências do lock são verificadas; o interpretador e a biblioteca padrão dependem
  da proteção do sistema.

    python3 -I ambiente.py --lock requirements.lock [--exigir-isolado]
"""
import argparse
import base64
import csv
import hashlib
import importlib.metadata as metadata
import io
import os
import re
import sys
from pathlib import Path

CAMINHO_LOCK_PADRAO = Path(__file__).resolve().parents[1] / "requirements.lock"
SUFIXOS_EXECUTAVEIS = {".py", ".so", ".pyd", ".pth", ".dll", ".dylib", ".pyc"}
ARQUIVOS_DE_INICIALIZACAO = ("sitecustomize.py", "usercustomize.py")
PADRAO_CABECA = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9A-Za-z.+!_-]+)(?:\s*;\s*(.+))?")
PADRAO_MARCADOR = re.compile(r"""python_version\s*(<=|>=|==|!=|<|>)\s*["'](\d+)\.(\d+)["']""")


class AmbienteInvalido(RuntimeError):
    """O ambiente não corresponde ao lock ou não está íntegro/protegido."""


def normalizar(nome):
    return re.sub(r"[-_.]+", "-", nome).lower()


def ler_lock(texto):
    """{nome: {"versao", "marcador", "hashes"}}; qualquer linha não reconhecida é recusada."""
    logicas, atual = [], ""
    for linha in texto.splitlines():
        bruta = linha.strip()
        if not bruta or bruta.startswith("#"):
            continue
        if bruta.endswith("\\"):
            atual += " " + bruta[:-1].strip()
            continue
        logicas.append((atual + " " + bruta).strip())
        atual = ""
    if atual.strip():
        logicas.append(atual.strip())
    entradas = {}
    for logica in logicas:
        partes = logica.split("--hash=")
        encontrado = PADRAO_CABECA.fullmatch(partes[0].strip())
        hashes = [h.strip() for h in partes[1:]]
        if not encontrado:
            raise AmbienteInvalido(f"Linha de lock não reconhecida: {logica[:80]!r}")
        if not hashes or not all(re.fullmatch(r"sha256:[0-9a-f]{64}", h) for h in hashes):
            raise AmbienteInvalido(f"{encontrado.group(1)}: entrada sem hashes sha256 válidos")
        nome = normalizar(encontrado.group(1))
        if nome in entradas:
            raise AmbienteInvalido(f"{nome}: entrada duplicada no lock")
        entradas[nome] = {"versao": encontrado.group(2), "marcador": encontrado.group(3),
                          "hashes": hashes}
    if not entradas:
        raise AmbienteInvalido("Lock vazio")
    return entradas


def marcador_aplica(marcador, versao_python):
    """Avalia só `python_version <op> "X.Y"` (combinados por `and`); o resto é recusado."""
    if not marcador:
        return True
    comparadores = {"<": lambda a, b: a < b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b,
                    ">=": lambda a, b: a >= b, "==": lambda a, b: a == b, "!=": lambda a, b: a != b}
    for clausula in re.split(r"\s+and\s+", marcador.strip()):
        encontrado = PADRAO_MARCADOR.fullmatch(clausula.strip())
        if not encontrado:
            raise AmbienteInvalido(f"Marcador de ambiente não suportado: {clausula!r}")
        operador, maior, menor = encontrado.groups()
        if not comparadores[operador](tuple(versao_python), (int(maior), int(menor))):
            return False
    return True


def localizar(nome, caminhos=None):
    if caminhos is None:
        try:
            return metadata.distribution(nome)
        except metadata.PackageNotFoundError:
            return None
    for distribuicao in metadata.distributions(path=[str(c) for c in caminhos]):
        if normalizar(distribuicao.metadata["Name"] or "") == nome:
            return distribuicao
    return None


def _sha256_b64(caminho):
    resumo = hashlib.sha256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(1 << 20), b""):
            resumo.update(bloco)
    return base64.urlsafe_b64encode(resumo.digest()).rstrip(b"=").decode("ascii")


def ler_record(nome, distribuicao):
    """[(caminho, algoritmo|None, hash|None)] lido DIRETAMENTE do RECORD.

    Não usar `Distribution.files`: desde o Python 3.12 ele omite em silêncio os arquivos que
    não existem mais em disco, escondendo exatamente a remoção que se quer detectar.
    """
    texto = distribuicao.read_text("RECORD")
    if not texto or not texto.strip():
        raise AmbienteInvalido(f"{nome}: distribuição sem RECORD; não há como conferir a integridade")
    entradas = []
    for linha in csv.reader(io.StringIO(texto)):
        if not linha:
            continue
        if len(linha) != 3:
            raise AmbienteInvalido(f"{nome}: linha malformada no RECORD: {linha!r}")
        caminho, resumo, _tamanho = linha
        algoritmo, _, valor = resumo.partition("=")
        entradas.append((caminho, algoritmo or None, valor or None))
    return entradas


def verificar_arquivos(nome, distribuicao):
    """Confere cada arquivo hasheado do RECORD e a ausência de código não listado.

    Retorna (diretórios/arquivos de topo do pacote, diretórios .dist-info).
    """
    entradas = ler_record(nome, distribuicao)
    conhecidos, topos, infos = set(), set(), set()
    for relativo, algoritmo, valor in entradas:
        caminho = Path(os.path.normpath(distribuicao.locate_file(relativo)))
        conhecidos.add(caminho)
        primeira = relativo.split("/", 1)[0]
        if primeira.endswith(".dist-info"):
            infos.add(distribuicao.locate_file(primeira))
        elif primeira and primeira != ".." and not primeira.endswith(".data"):
            topos.add(distribuicao.locate_file(primeira))
        if algoritmo is None:
            continue
        if algoritmo != "sha256":
            raise AmbienteInvalido(f"{nome}: {relativo} usa hash {algoritmo!r}; só sha256 é aceito")
        if not caminho.is_file() or caminho.is_symlink():
            raise AmbienteInvalido(f"{nome}: arquivo do RECORD ausente ou não regular: {relativo}")
        if _sha256_b64(caminho) != valor:
            raise AmbienteInvalido(f"{nome}: {relativo} difere do hash do RECORD (arquivo alterado)")
    for topo in topos:
        topo = Path(os.path.normpath(topo))
        itens = [topo] if topo.is_file() else sorted(topo.rglob("*")) if topo.is_dir() else []
        for item in itens:
            if "__pycache__" in item.parts:
                continue                     # não verificável por hash; ver docstring do módulo
            if (item.is_file() or item.is_symlink()) and item.suffix in SUFIXOS_EXECUTAVEIS \
                    and Path(os.path.normpath(item)) not in conhecidos:
                raise AmbienteInvalido(f"{nome}: arquivo de código não listado no RECORD: {item}")
    return topos, infos


def _inicializacao(diretorio):
    diretorio = Path(diretorio)
    if not diretorio.is_dir():
        return []
    return [*diretorio.glob("*.pth"), *(diretorio / n for n in ARQUIVOS_DE_INICIALIZACAO
                                         if (diretorio / n).exists())]


def verificar(lock, *, caminhos=None, uid_servico=None, exigir_isolado=False,
              exigir_sem_pyc=False, versao_python=None):
    """Retorna {nome: versão} verificados; levanta AmbienteInvalido (ou ConfiguracaoInsegura)."""
    from protecao import exigir_protegido
    versao_python = tuple(versao_python or sys.version_info[:2])
    try:
        entradas = ler_lock(Path(lock).read_text(encoding="utf-8"))
    except OSError as erro:
        raise AmbienteInvalido(f"Lock ilegível: {erro}") from erro
    if exigir_isolado and not sys.flags.isolated:
        raise AmbienteInvalido("O interpretador deve executar em modo isolado (python -I)")
    if exigir_sem_pyc:
        if not sys.pycache_prefix:
            raise AmbienteInvalido(
                "Defina -X pycache_prefix=<dir>: bytecode em disco não é verificável e não deve ser carregado")
        if uid_servico is not None and Path(sys.pycache_prefix).exists():
            exigir_protegido(sys.pycache_prefix, uid_servico, recursivo=True)
    verificadas = {}
    for nome, entrada in sorted(entradas.items()):
        if not marcador_aplica(entrada["marcador"], versao_python):
            continue
        distribuicao = localizar(nome, caminhos)
        if distribuicao is None:
            raise AmbienteInvalido(f"{nome}: dependência ausente (o lock exige {entrada['versao']})")
        if distribuicao.version != entrada["versao"]:
            raise AmbienteInvalido(
                f"{nome}: versão instalada {distribuicao.version} incompatível com a travada {entrada['versao']}")
        topos, infos = verificar_arquivos(nome, distribuicao)
        if uid_servico is not None:
            for topo in topos:
                exigir_protegido(topo, uid_servico, recursivo=Path(topo).is_dir())
            for info in infos:
                exigir_protegido(info, uid_servico, recursivo=True)
            exigir_protegido(distribuicao.locate_file(""), uid_servico)
        verificadas[nome] = distribuicao.version
    if uid_servico is not None:
        for diretorio in (sys.path if caminhos is None else [str(c) for c in caminhos]):
            if diretorio and Path(diretorio).exists():
                exigir_protegido(diretorio, uid_servico)
                for arquivo in _inicializacao(diretorio):
                    exigir_protegido(arquivo, uid_servico)
    return verificadas


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lock", default=str(CAMINHO_LOCK_PADRAO))
    parser.add_argument("--exigir-isolado", action="store_true")
    parser.add_argument("--exigir-sem-pyc", action="store_true",
                        help="exige -X pycache_prefix (bytecode em disco não é carregado)")
    parser.add_argument("--sem-protecao", action="store_true",
                        help="não confere dono/permissão (apenas versões e integridade)")
    args = parser.parse_args(argv)
    try:
        verificadas = verificar(args.lock, exigir_isolado=args.exigir_isolado,
                                exigir_sem_pyc=args.exigir_sem_pyc,
                                uid_servico=None if args.sem_protecao else os.getuid())
    except (AmbienteInvalido, RuntimeError) as erro:
        print("AMBIENTE INVÁLIDO:", erro, file=sys.stderr)
        return 1
    for nome, versao in verificadas.items():
        print(f"ok {nome}=={versao}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
