"""GOV-01: validação pelo JSON Schema, versionamento e proteção de premissas."""
import json
import os
import unittest
from unittest import mock

from apoio import PROPONENTE, Ambiente, premissa

import premissas_repositorio as repositorio
from governanca import PremissaInvalida, ValidacaoIndisponivel, validar_premissa
from premissas_repositorio import ConflitoVersao, IntegridadeViolada


class TestValidacaoSchema(unittest.TestCase):
    def test_premissa_valida(self):
        self.assertTrue(validar_premissa(premissa()))

    def test_versao_invalida_ou_booleana(self):
        for versao in (0, -1, "1", 1.5, True, False, None):
            with self.subTest(versao=versao), self.assertRaises(PremissaInvalida):
                validar_premissa(premissa(versao=versao))

    def test_hipotese_sem_justificativa(self):
        for justificativa in (None, "", "   "):
            p = premissa(natureza="HIPOTESE", fonte_id=None,
                         justificativa_hipotese=justificativa)
            with self.subTest(justificativa=justificativa), self.assertRaises(PremissaInvalida):
                validar_premissa(p)

    def test_campos_e_identificadores_fora_do_schema(self):
        for campos in ({"campo_extra": 1}, {"produto": "P9"}, {"id": "../PREM-001"},
                       {"fonte_id": "../../etc/passwd"}, {"status": "VERIFICADA"},
                       {"dependencias": ["PREM-001"]}):
            with self.subTest(campos=campos), self.assertRaises(PremissaInvalida):
                validar_premissa(premissa(**campos))

    def test_status_aprovada_nao_e_declaravel(self):
        with self.assertRaises(PermissionError):
            validar_premissa(premissa(status="APROVADA"))

    def test_validador_indisponivel_bloqueia(self):
        with mock.patch.dict("sys.modules", {"jsonschema": None}):
            with self.assertRaises(ValidacaoIndisponivel):
                validar_premissa(premissa())


class TestRepositorio(unittest.TestCase):
    def setUp(self):
        self.amb = Ambiente()
        self.repo = self.amb.repo

    def tearDown(self):
        self.amb.fechar()

    def test_registro_e_historico(self):
        h1 = self.repo.propor(premissa(), PROPONENTE)
        h2 = self.repo.propor(premissa(versao=2, valor=44.0), PROPONENTE)
        cadeia = self.repo.historico("PREM-001")
        self.assertEqual([(n, h) for n, h, _ in cadeia], [(1, h1), (2, h2)])
        self.assertEqual(cadeia[1][2]["hash_anterior"], h1)
        self.assertEqual(self.repo.estado("PREM-001", 2), "PROPOSTA")

    def test_fonte_inexistente(self):
        with self.assertRaises(PremissaInvalida):
            self.repo.propor(premissa(fonte_id="FONTE-999"), PROPONENTE)
        self.assertEqual(self.repo.historico("PREM-001"), [])

    def test_dependencia_inexistente(self):
        with self.assertRaises(PremissaInvalida):
            self.repo.propor(premissa(dependencias=["PREM-002"]), PROPONENTE)

    def test_conflito_entre_versoes(self):
        self.repo.propor(premissa(), PROPONENTE)
        with self.assertRaises(ConflitoVersao):
            self.repo.propor(premissa(valor=1.0), PROPONENTE)       # mesma versão
        with self.assertRaises(ConflitoVersao):
            self.repo.propor(premissa(versao=3), PROPONENTE)        # salto de versão
        original = repositorio.RepositorioPremissas.historico
        concorrente = []

        def historico_com_concorrencia(repo, premissa_id):
            cadeia = original(repo, premissa_id)
            if not concorrente:   # outro escritor grava v2 após esta leitura
                concorrente.append(True)
                self.repo.propor(premissa(versao=2, valor=50.0), "agente-p4")
            return cadeia
        with mock.patch.object(repositorio.RepositorioPremissas, "historico",
                               historico_com_concorrencia):
            with self.assertRaises(ConflitoVersao):
                self.repo.propor(premissa(versao=2, valor=60.0), PROPONENTE)
        self.assertEqual(self.repo.historico("PREM-001")[1][2]["premissa"]["valor"], 50.0)

    def test_sobrescrita_de_versao_aprovada(self):
        self.repo.propor(premissa(), PROPONENTE)
        self.repo.registrar_aprovacao(self.amb.aprovacao())
        antes = self.amb.arquivo("v1.json").read_bytes()
        with self.assertRaises(ConflitoVersao):
            self.repo.propor(premissa(valor=99.0), PROPONENTE)
        with self.assertRaises(FileExistsError):
            repositorio.gravar_exclusivo(self.amb.arquivo("v1.json"), b"{}")
        with self.assertRaises(ConflitoVersao):
            self.repo.registrar_aprovacao(self.amb.aprovacao())
        self.assertEqual(self.amb.arquivo("v1.json").read_bytes(), antes)
        self.assertEqual(self.amb.arquivo("v1.json").stat().st_mode & 0o777, 0o444)
        self.assertEqual(self.repo.estado("PREM-001", 1), "APROVADA")

    def _alterar_direto(self, nome, conteudo):
        arquivo = self.amb.arquivo(nome)
        os.chmod(arquivo, 0o644)      # quem tem escrita no diretório consegue isso
        arquivo.write_bytes(conteudo)

    def test_alteracao_direta_de_versao_aprovada_e_detectada(self):
        self.repo.propor(premissa(), PROPONENTE)
        self.repo.registrar_aprovacao(self.amb.aprovacao())
        envelope = json.loads(self.amb.arquivo("v1.json").read_bytes())
        envelope["premissa"]["valor"] = 1000.0
        self._alterar_direto("v1.json", repositorio.canonico(envelope))
        with self.assertRaises(PermissionError):
            self.repo.estado("PREM-001", 1)
        with self.assertRaises(PermissionError):
            self.repo.ler_aprovada("PREM-001")

    def test_alteracao_direta_rompe_cadeia(self):
        self.repo.propor(premissa(), PROPONENTE)
        self.repo.propor(premissa(versao=2, valor=44.0), PROPONENTE)
        envelope = json.loads(self.amb.arquivo("v1.json").read_bytes())
        envelope["premissa"]["valor"] = 7.0
        self._alterar_direto("v1.json", repositorio.canonico(envelope))
        with self.assertRaises(IntegridadeViolada):
            self.repo.historico("PREM-001")
        self._alterar_direto("v1.json", b"{corrompido")
        with self.assertRaises(IntegridadeViolada):
            self.repo.historico("PREM-001")
        self.amb.arquivo("v1.json").unlink()
        with self.assertRaises(IntegridadeViolada):
            self.repo.propor(premissa(versao=3), PROPONENTE)

    def test_recuperacao_apos_operacao_interrompida(self):
        with mock.patch("premissas_repositorio.os.link", side_effect=OSError("queda simulada")):
            with self.assertRaises(OSError):
                self.repo.propor(premissa(), PROPONENTE)
        self.assertFalse(self.amb.arquivo("v1.json").exists())
        resto = self.amb.arquivo(".v1.json.0123456789abcdef.tmp")   # processo morto
        resto.write_bytes(b'{"parcial"')
        self.assertEqual(self.repo.historico("PREM-001"), [])
        self.assertEqual(self.repo.recuperar(), [resto])
        self.repo.propor(premissa(), PROPONENTE)
        self.assertEqual(len(self.repo.historico("PREM-001")), 1)
        self.assertEqual(self.repo.recuperar(), [])


if __name__ == "__main__":
    unittest.main()
