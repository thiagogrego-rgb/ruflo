"""Harness de integração do GOV-04: guardião REAL (formato 2) com uids sintéticos sem privilégio.

Como em test_fronteira, root é necessário apenas para PREPARAR a separação (chown/setuid em
subprocessos); nenhum usuário é criado no sistema. Chaves e dados são sintéticos e descartados.
Sem Linux+root, ou com um Python fora do `requirements.lock`, os testes de integração são
pulados e a fronteira NÃO fica validada.
"""
import base64
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "scripts"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import ambiente  # noqa: E402
import aprovacao  # noqa: E402
from ancora import chave_hex  # noqa: E402
from governanca import canonico  # noqa: E402
from premissas_repositorio import RepositorioPremissas  # noqa: E402

UID_GUARDIAO, UID_AGENTE, UID_HUMANO, UID_ANCORA, UID_OUTRO = 52101, 52102, 52103, 52104, 52105
APTO_PARA_INTEGRACAO = (os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0
                        and hasattr(socket, "SO_PEERCRED"))
MOTIVO_NAO_APTO = "requer Linux e root para preparar uids separados; fronteira NÃO validada"
PREFIXO_PYC = "/nonexistent-ppp"
EMITIDA_EM = "2026-10-24T12:00:00+00:00"


def ambiente_conforme():
    """(conforme, motivo): o guardião de formato 2 só inicia num Python que satisfaça o lock."""
    try:
        ambiente.verificar(RAIZ / "requirements.lock")
        return True, ""
    except ambiente.AmbienteInvalido as erro:
        return False, str(erro)


def como(uid):
    def trocar():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return trocar


def entregar(caminho, uid, modo):
    os.chown(caminho, uid, uid)
    os.chmod(caminho, modo)


CHAMADOR = """
import json, sys
sys.path.insert(0, {scripts!r})
import cliente_guardiao as c
saida = []
for pedido in json.loads(sys.stdin.read()):
    try:
        saida.append({{"ok": True, "resultado": c.chamar(pedido, caminho_socket={socket!r}, timeout={timeout})}})
    except c.ErroGuardiao as erro:
        saida.append({{"ok": False, "erro": erro.tipo, "mensagem": str(erro)}})
    except Exception as erro:
        saida.append({{"ok": False, "erro": type(erro).__name__, "mensagem": str(erro)}})
print(json.dumps(saida))
"""


class Mundo:
    """Árvore temporária compartilhada pela classe de testes: código de root + raiz de governança."""

    def __init__(self):
        self.base = Path(tempfile.mkdtemp(prefix="ppp-gov04-"))
        os.chmod(self.base, 0o755)
        self.raiz = Ed25519PrivateKey.generate()                    # só em memória
        self.raiz_hex = chave_hex(self.raiz)
        self.chaves = {n: Ed25519PrivateKey.generate()
                       for n in ("ana.aprovadora", "bruno.aprovador", "carla.revogada")}
        self.codigo = self._copiar_codigo(self.base / "codigo")
        self.processos = []
        self.contador = 0

    @staticmethod
    def _copiar_codigo(destino):
        (destino / "governanca").mkdir(parents=True)
        shutil.copytree(RAIZ / "scripts", destino / "scripts",
                        ignore=shutil.ignore_patterns("__pycache__", "gerar_projeto.py*"))
        shutil.copytree(RAIZ / "governanca" / "schemas", destino / "governanca" / "schemas")
        shutil.copy(RAIZ / "requirements.lock", destino / "requirements.lock")
        for item in [destino, *destino.rglob("*")]:
            os.chmod(item, 0o755 if item.is_dir() else 0o644)
        return destino

    def codigo_com_lock(self, texto_lock):
        """Cópia do código (de root) com outro requirements.lock, para testar ambiente incompatível."""
        self.contador += 1
        copia = self._copiar_codigo(self.base / f"codigo-lock-{self.contador}")
        (copia / "requirements.lock").write_text(texto_lock, encoding="utf-8")
        return copia

    def fechar(self):
        for processo in self.processos:
            if processo.poll() is None:
                processo.kill()
            processo.communicate()
        shutil.rmtree(self.base, ignore_errors=True)


class Cenario:
    """Um guardião configurável (cadastro, referência externa, serviço) com diretórios próprios."""

    def __init__(self, mundo, nome, *, serie=1, nomes=("ana.aprovadora",), inativos=(), formato=2,
                 limites=None, ancoradores=(UID_ANCORA,)):
        self.mundo, self.formato, self.limites = mundo, formato, limites or {}
        self.ancoradores = list(ancoradores)
        self.dir = mundo.base / nome
        self.dir.mkdir(mode=0o755)
        self.config_dir = self.dir / "config"
        self.externo = self.dir / "externo"
        self.servico = self.dir / "servico"
        for pasta in (self.config_dir, self.externo):
            pasta.mkdir(mode=0o755)
        self.servico.mkdir()
        self.registros = self.servico / "registros"
        (self.registros / "fontes").mkdir(parents=True)
        (self.registros / "fontes" / "FONTE-001.json").write_text('{"sintetica": true}')
        self.run = self.servico / "run"
        self.run.mkdir()
        self.pem = self.servico / "guardiao.pem"
        self.chave_guardiao = Ed25519PrivateKey.generate()
        self.pem.write_bytes(self.chave_guardiao.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.publica_guardiao = chave_hex(self.chave_guardiao)
        for item in (self.servico, self.registros, self.registros / "fontes",
                     self.registros / "fontes" / "FONTE-001.json", self.run, self.pem):
            entregar(item, UID_GUARDIAO, 0o700 if item.is_dir() else 0o600)
        os.chmod(self.servico, 0o711)
        os.chmod(self.run, 0o755)
        self.socket = str(self.run / "g.sock")
        self.cadastro = self.config_dir / "aprovadores.json"
        self.referencia = self.externo / "referencia-serie.json"
        self.estado = self.registros / "estado" / "serie-cadastro.json"
        self.ancora = self.registros / "ancora"
        if serie is not None or formato == 1:
            self.publicar_cadastro(serie, nomes, inativos, com_referencia=formato == 2)
        self.config_padrao = self.escrever_config("guardiao.json")

    # -- artefatos assinados pela raiz (sempre de propriedade de root) ------------------------
    def aprovador(self, nome, ativo=True):
        return {"id": nome, "nome": nome, "tipo": "humano", "papeis": ["aprovador-premissas"],
                "produtos": ["P3"], "chave_publica_ed25519": chave_hex(self.mundo.chaves[nome]),
                "ativo": ativo}

    def publicar_cadastro(self, serie, nomes=("ana.aprovadora",), inativos=(), *, com_referencia=True,
                          chave=None, extra=None):
        dados = {"formato": 1, "aprovadores": [self.aprovador(n, n not in inativos) for n in nomes]}
        if serie is not None:
            dados["serie"] = serie
        dados.update(extra or {})
        bruto = json.dumps(dados, sort_keys=True).encode()
        self.cadastro.write_bytes(bruto)
        Path(f"{self.cadastro}.sig").write_text(
            base64.b64encode((chave or self.mundo.raiz).sign(bruto)).decode("ascii"))
        for arquivo in (self.cadastro, Path(f"{self.cadastro}.sig")):
            os.chmod(arquivo, 0o644)
        if com_referencia and serie is not None:
            import hashlib
            self.publicar_referencia(serie, hashlib.sha256(bruto).hexdigest())
        return bruto

    def publicar_referencia(self, serie_minima, sha, chave=None):
        payload = {"tipo": "referencia-serie-cadastro", "formato": 1, "serie_minima": serie_minima,
                   "sha256_cadastro": sha, "emitida_em": EMITIDA_EM}
        documento = aprovacao.assinar(payload, chave or self.mundo.raiz)
        self.referencia.write_bytes(canonico(documento))
        os.chmod(self.referencia, 0o644)
        return documento

    def config_dados(self, **sobrescritas):
        dados = {"formato": self.formato, "registros": str(self.registros), "aprovadores": str(self.cadastro),
                 "chave_raiz_governanca": self.mundo.raiz_hex, "chave_privada_guardiao": str(self.pem),
                 "socket": self.socket, "ancoradores": self.ancoradores,
                 "proponentes": {str(UID_AGENTE): "agente-p3", str(UID_OUTRO): "agente-p4"}}
        if self.formato == 2:
            dados["referencia_serie"] = str(self.referencia)
            if self.limites:
                dados["limites"] = self.limites
        dados.update(sobrescritas)
        return {k: v for k, v in dados.items() if v is not None}

    def escrever_config(self, nome, **sobrescritas):
        caminho = self.config_dir / nome
        caminho.write_text(json.dumps(self.config_dados(**sobrescritas)))
        os.chmod(caminho, 0o644)
        return caminho

    # -- ciclo de vida do guardião ---------------------------------------------------------------
    def comando(self, config=None, *, estrito=False, isolado=True, prefixo=PREFIXO_PYC, codigo=None):
        argumentos = [sys.executable] + (["-I"] if isolado else []) + ["-B"]
        if prefixo:
            argumentos += ["-X", f"pycache_prefix={prefixo}"]
        argumentos.append(str((codigo or self.mundo.codigo) / "scripts" / "guardiao.py"))
        return argumentos + (["--estrito"] if estrito else []) + [str(config or self.config_padrao)]

    def iniciar(self, config=None, *, uid=UID_GUARDIAO, **opcoes):
        processo = subprocess.Popen(
            self.comando(config, **opcoes), preexec_fn=como(uid) if uid else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd="/",
            env={"PATH": "/usr/bin:/bin"})
        self.mundo.processos.append(processo)
        return processo

    def tentar_iniciar(self, config=None, **opcoes):
        """(código de saída, stderr); código None se chegou a ficar PRONTO (e então é encerrado)."""
        processo = self.iniciar(config, **opcoes)
        if select.select([processo.stdout], [], [], 20)[0]:
            if processo.stdout.readline().strip() == "PRONTO":
                processo.kill()
                _, erro = processo.communicate()
                return None, erro
            _, erro = processo.communicate(timeout=30)
            return processo.returncode, erro
        processo.kill()
        _, erro = processo.communicate()
        return None, "sem resposta em 20 s\n" + erro

    @contextmanager
    def servir(self, config=None, **opcoes):
        processo = self.iniciar(config, **opcoes)
        try:
            if not select.select([processo.stdout], [], [], 20)[0] or processo.stdout.readline().strip() != "PRONTO":
                processo.kill()
                _, erro = processo.communicate()
                raise AssertionError("guardião não ficou PRONTO:\n" + erro)
            yield processo
        finally:
            if processo.poll() is None:
                processo.kill()
            processo.communicate()

    # -- clientes (cada chamada roda como um uid sintético sem privilégio) ----------------------------
    def executar_como(self, uid, codigo, entrada="", timeout=60):
        resultado = subprocess.run(
            [sys.executable, "-I", "-B", "-c", codigo], input=entrada, preexec_fn=como(uid),
            capture_output=True, text=True, timeout=timeout, cwd="/", env={"PATH": "/usr/bin:/bin"})
        if resultado.returncode != 0:
            raise AssertionError(f"cliente falhou: {resultado.stderr[-1500:]}")
        return resultado.stdout

    def chamar(self, uid, *pedidos, timeout=10):
        codigo = CHAMADOR.format(scripts=str(self.mundo.codigo / "scripts"), socket=self.socket,
                                 timeout=timeout)
        respostas = json.loads(self.executar_como(uid, codigo, json.dumps(list(pedidos))))
        return respostas[0] if len(pedidos) == 1 else respostas

    # -- utilitários de teste -----------------------------------------------------------------------------
    def repositorio_de_root(self):
        return RepositorioPremissas(self.registros)

    def aprovar(self, premissa_id, versao, nome="ana.aprovadora", chave=None):
        sha = self.repositorio_de_root().historico(premissa_id)[versao - 1][1]
        payload = aprovacao.payload_aprovacao(premissa_id, versao, sha, nome, EMITIDA_EM)
        return aprovacao.assinar(payload, chave or self.mundo.chaves[nome])
