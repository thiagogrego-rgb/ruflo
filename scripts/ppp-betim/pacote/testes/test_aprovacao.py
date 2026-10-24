"""GOV-02: aprovação humana com assinatura verificável e separação de permissões."""
import copy
import json
import subprocess
import sys
import unittest
from unittest import mock

from apoio import PROPONENTE, RAIZ, Ambiente, premissa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aprovacao
from aprovacao import AprovacaoInvalida, AutorizacaoIndisponivel
from governanca import ValidacaoIndisponivel


class TestAprovacao(unittest.TestCase):
    def setUp(self):
        self.amb = Ambiente()
        self.repo = self.amb.repo
        self.repo.propor(premissa(), PROPONENTE)

    def tearDown(self):
        self.amb.fechar()

    def assertRecusada(self, dados, erro=AprovacaoInvalida):
        with self.assertRaises(erro):
            self.repo.registrar_aprovacao(dados)
        self.assertFalse(self.amb.arquivo("v1.aprovacao.json").exists())
        with self.assertRaises(PermissionError):
            self.repo.ler_aprovada("PREM-001")

    def test_aprovacao_valida(self):
        self.assertEqual(self.repo.registrar_aprovacao(self.amb.aprovacao()), "ana.aprovadora")
        self.assertEqual(self.repo.estado("PREM-001", 1), "APROVADA")
        self.assertEqual(self.repo.ler_aprovada("PREM-001")["valor"], 42.5)
        self.repo.propor(premissa(versao=2, valor=44.0), PROPONENTE)
        self.assertEqual(self.repo.estado("PREM-001", 2), "PROPOSTA")
        self.assertEqual(self.repo.ler_aprovada("PREM-001")["valor"], 42.5)

    def test_identidade_nao_autorizada(self):
        estranho = Ed25519PrivateKey.generate()
        self.assertRecusada(self.amb.aprovacao(aprovador="desconhecido", chave=estranho))
        self.assertRecusada(self.amb.aprovacao(aprovador="bruno.aprovador"))  # só P1
        self.assertRecusada(self.amb.aprovacao(aprovador="carla.inativa"))    # inativa

    def test_proponente_nao_aprova_a_propria_premissa(self):
        chave = Ed25519PrivateKey.generate()
        self.amb.escrever_registro([self.amb.aprovador(PROPONENTE, ["P3"], chave=chave)])
        self.assertRecusada(self.amb.aprovacao(aprovador=PROPONENTE, chave=chave))

    def test_aprovacao_vinculada_a_versao_incorreta(self):
        aprovacao_v1 = self.amb.aprovacao()
        self.repo.propor(premissa(versao=2, valor=44.0), PROPONENTE)
        trocada = copy.deepcopy(aprovacao_v1)
        trocada["payload"]["versao"] = 2           # payload alterado: assinatura não confere
        self.assertRecusada(trocada)
        self.assertRecusada(self.amb.aprovacao(versao=2, sha="0" * 64))
        assinada_v1_para_v2 = self.amb.aprovacao(versao=2, sha=self.repo.historico("PREM-001")[0][1])
        self.assertRecusada(assinada_v1_para_v2)
        self.assertRecusada(self.amb.aprovacao(versao=3, sha="a" * 64))

    def test_aprovacao_fabricada_pelo_agente(self):
        chave_do_agente = Ed25519PrivateKey.generate()
        self.assertRecusada(self.amb.aprovacao(chave=chave_do_agente))           # forja ana
        self.assertRecusada(self.amb.aprovacao(aprovador="agente-p3",
                                               chave=chave_do_agente))
        sem_assinatura = self.amb.aprovacao()
        sem_assinatura["assinatura"] = "A" * 86 + "=="
        self.assertRecusada(sem_assinatura)
        copiada = self.amb.aprovacao()
        copiada["payload"]["emitida_em"] = "2030-01-01T00:00:00+00:00"
        self.assertRecusada(copiada)
        for invalido in ({}, {"payload": {}}, [], "APROVADA"):
            with self.subTest(invalido=invalido), self.assertRaises(PermissionError):
                self.repo.registrar_aprovacao(invalido)

    def test_falha_do_mecanismo_de_autorizacao(self):
        valida = self.amb.aprovacao()
        self.repo.registrar_aprovacao(valida)
        registro = self.amb.registro_aprovadores
        original = registro.read_text(encoding="utf-8")
        for conteudo in (None, "{corrompido", json.dumps({"formato": 1}),
                         json.dumps({"formato": 1, "aprovadores": [{"id": "x"}]})):
            with self.subTest(conteudo=conteudo):
                if conteudo is None:
                    registro.unlink()
                else:
                    registro.write_text(conteudo, encoding="utf-8")
                with self.assertRaises(AutorizacaoIndisponivel):
                    self.repo.estado("PREM-001", 1)
                with self.assertRaises(PermissionError):
                    self.repo.ler_aprovada("PREM-001")
        registro.write_text(original, encoding="utf-8")
        for modulo in ("cryptography.exceptions",
                       "cryptography.hazmat.primitives.asymmetric.ed25519", "jsonschema"):
            with self.subTest(modulo=modulo), mock.patch.dict("sys.modules", {modulo: None}):
                with self.assertRaises((PermissionError, ValidacaoIndisponivel)):
                    self.repo.ler_aprovada("PREM-001")
        self.assertEqual(self.repo.estado("PREM-001", 1), "APROVADA")

    def test_registro_distribuido_nao_tem_aprovadores(self):
        self.assertEqual(aprovacao.carregar_aprovadores(), {})

    def test_assinador_exige_terminal_interativo(self):
        resultado = subprocess.run(
            [sys.executable, str(RAIZ / "scripts" / "assinar_aprovacao.py"), "gerar-chave",
             "--saida", str(self.amb.registros / "x.pem")],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        self.assertEqual(resultado.returncode, 2)
        self.assertIn("terminal interativo", resultado.stderr)
        self.assertFalse((self.amb.registros / "x.pem").exists())


if __name__ == "__main__":
    unittest.main()
