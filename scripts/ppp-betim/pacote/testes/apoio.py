"""Ambiente de teste com registros e chaves sintéticos. Nenhum dado real."""
import json
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "scripts"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import aprovacao  # noqa: E402
from premissas_repositorio import RepositorioPremissas  # noqa: E402

PROPONENTE = "agente-p3"
EMITIDA_EM = "2026-10-24T12:00:00+00:00"


def premissa(versao=1, **campos):
    dados = dict(id="PREM-001", versao=versao, produto="P3", natureza="OBSERVADO",
                 unidade="BRL/m2/mes", status="PROPOSTA", fonte_id="FONTE-001",
                 valor=42.5, data_base="2026-06", descricao="Aluguel médio sintético")
    dados.update(campos)
    return dados


def chave_publica_hex(privada):
    return privada.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw).hex()


class Ambiente:
    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.registros = base / "registros"
        (self.registros / "fontes").mkdir(parents=True)
        (self.registros / "fontes" / "FONTE-001.json").write_text(
            '{"id": "FONTE-001", "sintetica": true}', encoding="utf-8")
        self.chaves = {nome: Ed25519PrivateKey.generate()
                       for nome in ("ana.aprovadora", "bruno.aprovador", "carla.inativa")}
        self.registro_aprovadores = base / "aprovadores.json"
        self.escrever_registro([
            self.aprovador("ana.aprovadora", ["P3", "P4"]),
            self.aprovador("bruno.aprovador", ["P1"]),
            self.aprovador("carla.inativa", ["P3"], ativo=False),
        ])
        self.repo = RepositorioPremissas(self.registros, self.registro_aprovadores)

    def aprovador(self, identificador, produtos, ativo=True, chave=None):
        return {"id": identificador, "nome": identificador, "tipo": "humano",
                "papeis": ["aprovador-premissas"], "produtos": produtos,
                "chave_publica_ed25519": chave_publica_hex(chave or self.chaves[identificador]),
                "ativo": ativo}

    def escrever_registro(self, aprovadores):
        self.registro_aprovadores.write_text(
            json.dumps({"formato": 1, "aprovadores": aprovadores}), encoding="utf-8")

    def aprovacao(self, premissa_id="PREM-001", versao=1, aprovador="ana.aprovadora",
                  chave=None, sha=None):
        if sha is None:
            sha = self.repo.historico(premissa_id)[versao - 1][1]
        payload = aprovacao.payload_aprovacao(premissa_id, versao, sha, aprovador, EMITIDA_EM)
        return aprovacao.assinar(payload, chave or self.chaves[aprovador])

    def arquivo(self, nome, premissa_id="PREM-001"):
        return self.registros / "premissas" / premissa_id / nome

    def fechar(self):
        self._tmp.cleanup()
