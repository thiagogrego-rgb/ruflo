"""GOV-04: série crescente do cadastro de aprovadores e referência externa (risco R9)."""
import json
import unittest
from unittest import mock

from apoio_robustez import PROPONENTE, Governanca, premissa, sha256_hex
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aprovacao
import serie as modulo_serie
from aprovacao import AutorizacaoIndisponivel
from serie import (EstadoDeSerieCorrompido, ReferenciaIndisponivel, RetrocessoDeSerie,
                   SerieAusente, SerieConflitante)


class TestSerie(unittest.TestCase):
    def setUp(self):
        self.g = Governanca()

    def tearDown(self):
        self.g.fechar()

    def marca(self):
        return json.loads(self.g.estado.read_text()) if self.g.estado.exists() else None

    # -- cadastro com número de série crescente ------------------------------
    def test_series_crescentes_sao_aceitas_e_a_marca_dagua_acompanha(self):
        self.g.publicar(1)
        self.assertEqual(set(self.g.carregar()), {"ana.aprovadora"})
        self.assertEqual(self.marca()["serie"], 1)
        bruto2 = self.g.publicar(2, nomes=("ana.aprovadora", "bruno.aprovador"))
        self.assertEqual(set(self.g.carregar()), {"ana.aprovadora", "bruno.aprovador"})
        self.assertEqual(self.marca(), {"serie": 2, "sha256": sha256_hex(bruto2)})
        self.g.publicar_cadastro(5, nomes=("ana.aprovadora",))        # a referência pode ficar para trás
        self.g.carregar()
        self.assertEqual(self.marca()["serie"], 5)

    def test_reaceitar_o_mesmo_cadastro_e_idempotente(self):
        self.g.publicar(3)
        self.g.carregar()
        antes = self.g.estado.read_bytes()
        self.g.carregar()
        self.assertEqual(self.g.estado.read_bytes(), antes)

    # -- cadastro anterior reapresentado --------------------------------------
    def test_cadastro_anterior_reapresentado_e_recusado(self):
        antigo = self.g.publicar(1, nomes=("ana.aprovadora", "carla.revogada"))
        self.g.carregar()
        self.g.publicar(2, nomes=("ana.aprovadora", "carla.revogada"), inativos=("carla.revogada",))
        self.g.carregar()
        self.g.cadastro.write_bytes(antigo)                                  # replay do cadastro antigo
        self.g.cadastro.with_name("aprovadores.json.sig").write_text(
            self._assinar(antigo))
        with self.assertRaises(RetrocessoDeSerie):
            self.g.carregar()
        self.assertEqual(self.marca()["serie"], 2, "a marca d'água não pode recuar")

    def _assinar(self, bruto):
        import base64
        return base64.b64encode(self.g.raiz.sign(bruto)).decode("ascii")

    def test_replay_so_com_referencia_em_host_sem_marca_dagua(self):
        antigo = self.g.publicar_cadastro(1)
        self.g.publicar(4)                                                   # referência fixa o piso em 4
        self.g.cadastro.write_bytes(antigo)
        self.g.cadastro.with_name("aprovadores.json.sig").write_text(self._assinar(antigo))
        self.assertFalse(self.g.estado.exists())                             # host novo: sem marca d'água
        with self.assertRaises(RetrocessoDeSerie):
            self.g.carregar()
        self.assertFalse(self.g.estado.exists(), "recusa não pode criar marca d'água")

    def test_replay_so_com_marca_dagua_com_referencia_defasada(self):
        antigo = self.g.publicar(1)
        self.g.carregar()
        self.g.publicar_cadastro(3)
        self.g.carregar()                                                    # marca d'água em 3; referência em 1
        self.g.cadastro.write_bytes(antigo)
        self.g.cadastro.with_name("aprovadores.json.sig").write_text(self._assinar(antigo))
        with self.assertRaises(RetrocessoDeSerie):
            self.g.carregar()

    def test_aprovador_revogado_nao_volta_por_replay_do_cadastro_antigo(self):
        """O ataque do R9 ponta a ponta: a aprovação de quem foi revogado ressuscita?"""
        from premissas_repositorio import RepositorioPremissas
        from ancora import chave_hex
        antigo = self.g.publicar(1, nomes=("ana.aprovadora", "carla.revogada"))
        repo = self.g.repositorio()
        repo.propor(premissa(), PROPONENTE)
        repo.registrar_aprovacao(self.g.aprovacao(repo, "carla.revogada"))   # válida na série 1
        self.assertEqual(repo.estado("PREM-001", 1), "APROVADA")
        self.g.publicar(2, nomes=("ana.aprovadora", "carla.revogada"), inativos=("carla.revogada",))
        with self.assertRaises(aprovacao.AprovacaoInvalida):                 # revogada: deixa de valer
            repo.estado("PREM-001", 1)
        self.g.cadastro.write_bytes(antigo)                                  # replay do cadastro antigo
        self.g.cadastro.with_name("aprovadores.json.sig").write_text(self._assinar(antigo))
        # GOV-02 sozinho (sem política de série): a aprovação revogada VOLTA a valer.
        sem_politica = RepositorioPremissas(self.g.registros, self.g.cadastro, chave_hex(self.g.raiz))
        self.assertEqual(sem_politica.estado("PREM-001", 1), "APROVADA")
        # Com a política de série (GOV-04) o replay é barrado e nada é reconhecido como aprovado.
        with self.assertRaises(RetrocessoDeSerie):
            repo.estado("PREM-001", 1)
        with self.assertRaises(RetrocessoDeSerie):
            repo.ler_aprovada("PREM-001")
        nova = premissa(versao=2, valor=50.0)
        repo_novo = self.g.repositorio()
        with self.assertRaises(PermissionError):                             # nem nova aprovação da Carla
            repo_novo.propor(nova, PROPONENTE)
            repo_novo.registrar_aprovacao(self.g.aprovacao(repo_novo, "carla.revogada", versao=2))

    def test_sem_politica_o_replay_passa_o_que_mostra_o_valor_do_controle(self):
        antigo = self.g.publicar_cadastro(1, nomes=("ana.aprovadora", "carla.revogada"))
        self.g.publicar_cadastro(2, nomes=("ana.aprovadora", "carla.revogada"), inativos=("carla.revogada",))
        self.assertNotIn("carla.revogada", self.g.carregar(politica=False))
        self.g.cadastro.write_bytes(antigo)
        self.g.cadastro.with_name("aprovadores.json.sig").write_text(self._assinar(antigo))
        self.assertIn("carla.revogada", self.g.carregar(politica=False))     # GOV-02 sozinho aceita

    # -- série duplicada --------------------------------------------------------
    def test_serie_duplicada_com_conteudo_diferente_e_recusada(self):
        self.g.publicar(2, nomes=("ana.aprovadora",))
        self.g.carregar()
        self.g.publicar_cadastro(2, nomes=("ana.aprovadora", "bruno.aprovador"))  # outro conteúdo
        with self.assertRaises(SerieConflitante):
            self.g.carregar()
        self.assertEqual(set(aprovacao.carregar_aprovadores(self.g.cadastro)),
                         {"ana.aprovadora", "bruno.aprovador"}, "sem política o conflito passaria")

    def test_serie_duplicada_contra_a_marca_dagua_com_referencia_defasada(self):
        """Só a marca d'água conhece a série 2 aqui: a referência ainda fixa o piso em 1."""
        primeiro = self.g.publicar_cadastro(2, nomes=("ana.aprovadora",))
        self.g.publicar_referencia(1, "0" * 64)
        self.g.carregar()
        self.assertEqual(self.marca(), {"serie": 2, "sha256": sha256_hex(primeiro)})
        self.g.publicar_cadastro(2, nomes=("ana.aprovadora", "bruno.aprovador"))     # mesma série, outro conteúdo
        with self.assertRaisesRegex(SerieConflitante, "já aceita com outro conteúdo"):
            self.g.carregar()
        self.assertEqual(self.marca()["sha256"], sha256_hex(primeiro), "a marca d'água não é sobrescrita")

    def test_serie_duplicada_contra_a_referencia_em_host_novo(self):
        original = self.g.publicar_cadastro(2)
        self.g.publicar_referencia(2, sha256_hex(original))
        self.g.publicar_cadastro(2, nomes=("ana.aprovadora", "bruno.aprovador"))
        with self.assertRaises(SerieConflitante):
            self.g.carregar()
        self.assertFalse(self.g.estado.exists())

    # -- série ausente ou inválida ------------------------------------------------
    def test_serie_ausente_ou_invalida(self):
        self.g.publicar_cadastro(1, com_serie=False)
        self.g.publicar_referencia(1, "0" * 64)
        with self.assertRaises(SerieAusente):
            self.g.carregar()
        for invalida in (True, False, 0, -1, "1", 1.5, None, 2 ** 60):
            with self.subTest(serie=invalida):
                self.g.publicar_cadastro(1, com_serie=False, extra={"serie": invalida})
                with self.assertRaises(AutorizacaoIndisponivel):
                    self.g.carregar()
        self.assertFalse(self.g.estado.exists())

    # -- âncora externa ausente ou adulterada ---------------------------------------
    def test_referencia_externa_ausente_bloqueia(self):
        self.g.publicar_cadastro(1)
        with self.assertRaises(ReferenciaIndisponivel):
            self.g.carregar()
        self.assertFalse(self.g.estado.exists())

    def test_referencia_externa_adulterada_bloqueia(self):
        bruto = self.g.publicar_cadastro(5)
        documento = self.g.publicar_referencia(5, sha256_hex(bruto))
        casos = {
            "serie_minima_reduzida": lambda d: d["payload"].__setitem__("serie_minima", 1),
            "hash_trocado": lambda d: d["payload"].__setitem__("sha256_cadastro", "f" * 64),
            "campo_extra": lambda d: d["payload"].__setitem__("extra", 1),
            "assinatura_zerada": lambda d: d.__setitem__("assinatura", "A" * 86 + "=="),
        }
        for nome, adulterar in casos.items():
            with self.subTest(nome):
                copia = json.loads(json.dumps(documento))
                adulterar(copia)
                self.g.referencia.write_text(json.dumps(copia))
                with self.assertRaises(ReferenciaIndisponivel):
                    self.g.carregar()
        outra_raiz = Ed25519PrivateKey.generate()
        self.g.publicar_referencia(5, sha256_hex(bruto), chave=outra_raiz)
        with self.assertRaises(ReferenciaIndisponivel):
            self.g.carregar()
        for lixo in ("", "não é json", "[]", '{"payload": 1}'):
            self.g.referencia.write_text(lixo)
            with self.subTest(lixo=lixo), self.assertRaises(ReferenciaIndisponivel):
                self.g.carregar()
        self.assertFalse(self.g.estado.exists(), "nenhuma recusa pode gravar marca d'água")

    # -- marca d'água ----------------------------------------------------------------
    def test_marca_dagua_corrompida_bloqueia_e_a_referencia_ainda_protege_apos_recuperacao(self):
        antigo = self.g.publicar(2)
        self.g.carregar()
        for lixo in ("{", "[]", '{"serie": true, "sha256": "' + "0" * 64 + '"}',
                     '{"serie": 2, "sha256": "xyz"}', '{"serie": 2}'):
            with self.subTest(lixo=lixo):
                self.g.estado.write_text(lixo)
                with self.assertRaises(EstadoDeSerieCorrompido):
                    self.g.carregar()
        self.g.estado.unlink()                                                 # procedimento humano
        self.g.publicar(3)
        self.assertEqual(set(self.g.carregar()), {"ana.aprovadora"})
        self.g.cadastro.write_bytes(self.g.publicar_cadastro(1))               # replay após a recuperação
        with self.assertRaises(RetrocessoDeSerie):
            self.g.carregar()
        self.assertTrue(antigo)

    def test_politica_exige_cadastro_assinado(self):
        self.g.publicar(1)
        with self.assertRaises(AutorizacaoIndisponivel):
            aprovacao.carregar_aprovadores(self.g.cadastro, None, self.g.politica)

    def test_cadastro_sem_assinatura_valida_nao_chega_a_politica(self):
        self.g.publicar_cadastro(7, chave=Ed25519PrivateKey.generate())        # assinado por outra chave
        self.g.publicar_referencia(7, "0" * 64)
        with self.assertRaises(AutorizacaoIndisponivel):
            self.g.carregar()
        self.assertFalse(self.g.estado.exists())

    # -- interrupção e recuperação ------------------------------------------------------
    def test_interrupcao_na_gravacao_da_marca_dagua_nao_corrompe_e_recupera(self):
        self.g.publicar(1)
        self.g.carregar()
        self.g.publicar(2)
        with mock.patch("serie.os.replace", side_effect=OSError("queda simulada")):
            with self.assertRaises(OSError):
                self.g.carregar()
        self.assertEqual(self.marca()["serie"], 1, "a marca anterior deve permanecer íntegra")
        resto = self.g.estado.with_name(".serie-cadastro.json.0123456789abcdef.tmp")
        resto.write_bytes(b'{"serie": 99')                                       # processo morto no meio
        self.assertEqual(self.g.politica.recuperar(), [resto])
        self.g.carregar()                                                        # retoma normalmente
        self.assertEqual(self.marca()["serie"], 2)
        self.assertEqual(self.g.politica.recuperar(), [])

    # -- reversão legítima ----------------------------------------------------------------
    def test_reversao_legitima_exige_novo_cadastro_com_serie_maior(self):
        self.g.publicar(1, nomes=("ana.aprovadora", "carla.revogada"))
        self.g.carregar()
        self.g.publicar(2, nomes=("ana.aprovadora",))                          # revoga a carla
        self.assertNotIn("carla.revogada", self.g.carregar())
        self.g.publicar(3, nomes=("ana.aprovadora", "carla.revogada"))         # reversão = série nova
        self.assertIn("carla.revogada", self.g.carregar())
        self.assertEqual(self.marca()["serie"], 3)

    def test_compatibilidade_do_contrato_sem_politica(self):
        self.g.publicar_cadastro(1, com_serie=False)
        self.assertEqual(set(aprovacao.carregar_aprovadores(self.g.cadastro, None)), {"ana.aprovadora"})
        self.assertEqual(set(aprovacao.carregar_aprovadores(
            self.g.cadastro, modulo_serie and __import__("ancora").chave_hex(self.g.raiz))), {"ana.aprovadora"})
        repo = self.g.repositorio()
        self.assertIs(repo.politica_serie, self.g.politica)
        legado = __import__("premissas_repositorio").RepositorioPremissas(self.g.registros)
        self.assertIsNone(legado.politica_serie)


if __name__ == "__main__":
    unittest.main()
