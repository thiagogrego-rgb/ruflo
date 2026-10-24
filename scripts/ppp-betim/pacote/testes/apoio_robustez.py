"""Apoio dos testes do GOV-04: governança sintética (raiz, cadastro assinado, referência externa).

Chaves e identidades são sintéticas, vivem em memória e em diretório temporário descartado.
"""
import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "scripts"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import aprovacao  # noqa: E402
from ancora import chave_hex  # noqa: E402
from governanca import canonico  # noqa: E402
from premissas_repositorio import RepositorioPremissas  # noqa: E402
from serie import PoliticaSerie  # noqa: E402

EMITIDA_EM = "2026-10-24T12:00:00+00:00"
PROPONENTE = "agente-p3"


def sha256_hex(dados):
    return hashlib.sha256(dados).hexdigest()


def premissa(versao=1, **campos):
    dados = dict(id="PREM-001", versao=versao, produto="P3", natureza="OBSERVADO",
                 unidade="BRL/m2/mes", status="PROPOSTA", fonte_id="FONTE-001",
                 valor=42.5, data_base="2026-06", descricao="Aluguel médio sintético")
    dados.update(campos)
    return dados


class Governanca:
    """Raiz de governança sintética, cadastro assinado e referência externa em diretório temporário."""

    NOMES = ("ana.aprovadora", "bruno.aprovador", "carla.revogada")

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        (self.base / "externo").mkdir()
        (self.base / "servico" / "registros" / "fontes").mkdir(parents=True)
        (self.base / "servico" / "registros" / "fontes" / "FONTE-001.json").write_text('{"sintetica": true}')
        self.raiz = Ed25519PrivateKey.generate()
        self.chaves = {nome: Ed25519PrivateKey.generate() for nome in self.NOMES}
        self.cadastro = self.base / "aprovadores.json"
        self.referencia = self.base / "externo" / "referencia-serie.json"
        self.estado = self.base / "servico" / "estado" / "serie-cadastro.json"
        self.registros = self.base / "servico" / "registros"
        self.politica = PoliticaSerie(self.referencia, self.estado, chave_hex(self.raiz))

    # -- artefatos assinados --------------------------------------------------
    def aprovador(self, nome, ativo=True, produtos=("P3",)):
        return {"id": nome, "nome": nome, "tipo": "humano", "papeis": ["aprovador-premissas"],
                "produtos": list(produtos), "chave_publica_ed25519": chave_hex(self.chaves[nome]),
                "ativo": ativo}

    def publicar_cadastro(self, serie, nomes=("ana.aprovadora",), destino=None, chave=None,
                          inativos=(), com_serie=True, extra=None):
        """Grava cadastro + .sig (assinado pela raiz, ou por `chave`); devolve os bytes."""
        dados = {"formato": 1, "aprovadores": [self.aprovador(n, ativo=n not in inativos) for n in nomes]}
        if com_serie:
            dados["serie"] = serie
        dados.update(extra or {})
        bruto = json.dumps(dados, sort_keys=True).encode()
        destino = Path(destino or self.cadastro)
        destino.write_bytes(bruto)
        Path(f"{destino}.sig").write_text(
            base64.b64encode((chave or self.raiz).sign(bruto)).decode("ascii"))
        return bruto

    def publicar_referencia(self, serie_minima, sha, chave=None, destino=None, payload_extra=None):
        payload = {"tipo": "referencia-serie-cadastro", "formato": 1, "serie_minima": serie_minima,
                   "sha256_cadastro": sha, "emitida_em": EMITIDA_EM}
        payload.update(payload_extra or {})
        documento = aprovacao.assinar(payload, chave or self.raiz)
        destino = Path(destino or self.referencia)
        destino.write_bytes(canonico(documento))
        return documento

    def publicar(self, serie, **kw):
        """Cadastro + referência coerentes (a situação normal de operação)."""
        bruto = self.publicar_cadastro(serie, **kw)
        self.publicar_referencia(serie, sha256_hex(bruto))
        return bruto

    def carregar(self, politica=True):
        return aprovacao.carregar_aprovadores(self.cadastro, chave_hex(self.raiz),
                                              self.politica if politica else None)

    def repositorio(self, **kw):
        return RepositorioPremissas(self.registros, self.cadastro, chave_hex(self.raiz),
                                    politica_serie=self.politica, **kw)

    def aprovacao(self, repo, nome, premissa_id="PREM-001", versao=1):
        sha = repo.historico(premissa_id)[versao - 1][1]
        payload = aprovacao.payload_aprovacao(premissa_id, versao, sha, nome, EMITIDA_EM)
        return aprovacao.assinar(payload, self.chaves[nome])

    def fechar(self):
        self._tmp.cleanup()
