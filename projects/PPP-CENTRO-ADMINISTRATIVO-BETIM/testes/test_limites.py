"""GOV-04: limites de tamanho, frequência e crescimento (risco R12)."""
import dataclasses
import socket
import threading
import time
import unittest
from unittest import mock

from apoio_robustez import PROPONENTE, Governanca, premissa

from guardiao import ler_linha
from limites import LimiteExcedido, LimitadorTaxa, Limites, PERFIL_ESTRITO, limites_estritos


class Relogio:
    def __init__(self):
        self.agora = 1000.0

    def __call__(self):
        return self.agora


class TestLimitadorTaxa(unittest.TestCase):
    def setUp(self):
        self.relogio = Relogio()

    def limitador(self, por_minuto=60, rajada=3, max_chaves=4096):
        return LimitadorTaxa(por_minuto, rajada, max_chaves, relogio=self.relogio)

    def test_excesso_de_operacoes_por_identidade(self):
        lim = self.limitador(rajada=3)
        for _ in range(3):
            lim.consumir(52002)
        with self.assertRaises(LimiteExcedido) as erro:
            lim.consumir(52002)
        self.assertIn("52002", str(erro.exception))

    def test_identidades_sao_independentes(self):
        lim = self.limitador(rajada=2)
        lim.consumir(1)
        lim.consumir(1)
        with self.assertRaises(LimiteExcedido):
            lim.consumir(1)
        lim.consumir(2)                                  # outra identidade não é afetada
        lim.consumir(2)

    def test_reposicao_com_o_tempo_e_limite_pela_rajada(self):
        lim = self.limitador(por_minuto=60, rajada=3)    # 1 ficha por segundo
        for _ in range(3):
            lim.consumir("a")
        with self.assertRaises(LimiteExcedido):
            lim.consumir("a")
        self.relogio.agora += 1.0
        lim.consumir("a")                                # uma ficha reposta
        with self.assertRaises(LimiteExcedido):
            lim.consumir("a")
        self.relogio.agora += 3600                       # muito tempo: nunca passa da rajada
        for _ in range(3):
            lim.consumir("a")
        with self.assertRaises(LimiteExcedido):
            lim.consumir("a")

    def test_recusa_nao_consome_ficha_e_informa_a_espera(self):
        lim = self.limitador(por_minuto=60, rajada=1)
        lim.consumir("a")
        for _ in range(5):
            with self.assertRaises(LimiteExcedido) as erro:
                lim.consumir("a")
        self.assertIn("1.0s", str(erro.exception))
        self.relogio.agora += 1.0
        lim.consumir("a")                                # as recusas não adiaram a reposição

    def test_memoria_limitada_descarta_a_identidade_menos_recente(self):
        lim = self.limitador(rajada=1, max_chaves=3)
        for uid in range(10):
            lim.consumir(uid)
        self.assertEqual(lim.rastreadas(), 3)

    def test_relogio_que_recua_nao_gera_fichas_negativas(self):
        lim = self.limitador(rajada=1)
        lim.consumir("a")
        self.relogio.agora -= 500
        with self.assertRaises(LimiteExcedido):
            lim.consumir("a")

    def test_parametros_invalidos(self):
        for argumentos in ((0, 1), (1, 0), (-1, 1), (1, 1, 0)):
            with self.subTest(argumentos=argumentos), self.assertRaises(ValueError):
                LimitadorTaxa(*argumentos)


class TestLimites(unittest.TestCase):
    def test_perfil_estrito_e_mais_restritivo_que_o_padrao(self):
        padrao, estrito = Limites(), limites_estritos()
        for campo, valor in PERFIL_ESTRITO.items():
            if campo != "intervalo_minimo_checkpoint_s":
                self.assertLess(getattr(estrito, campo), getattr(padrao, campo), campo)
        self.assertGreater(estrito.intervalo_minimo_checkpoint_s, padrao.intervalo_minimo_checkpoint_s)

    def test_sobrescritas_explicitas_e_validacao(self):
        self.assertEqual(limites_estritos(rajada=5).rajada, 5)
        for invalido in ({"rajada": 0}, {"rajada": -1}, {"rajada": True}, {"rajada": "10"},
                         {"max_bytes_total": None}):
            with self.subTest(invalido=invalido), self.assertRaises(ValueError):
                Limites(**invalido)
        with self.assertRaises(TypeError):
            limites_estritos(inexistente=1)
        self.assertEqual(Limites(intervalo_minimo_checkpoint_s=0).intervalo_minimo_checkpoint_s, 0)

    def test_imutavel(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            Limites().rajada = 1


class TestCrescimento(unittest.TestCase):
    def setUp(self):
        self.g = Governanca()

    def tearDown(self):
        self.g.fechar()

    def repo(self, **limites):
        return self.g.repositorio(limites=Limites(**limites))

    def arquivos(self):
        return sorted(str(a.relative_to(self.g.registros)) for a in (self.g.registros / "premissas").rglob("*")
                      if a.is_file())

    def test_versao_acima_do_limite_de_bytes_e_recusada_sem_gravar(self):
        repo = self.repo(max_bytes_por_versao=1024)
        with self.assertRaises(LimiteExcedido):
            repo.propor(premissa(descricao="x" * 4096), PROPONENTE)
        self.assertEqual(self.arquivos(), [])
        repo.propor(premissa(), PROPONENTE)

    def test_limite_de_versoes_por_premissa(self):
        repo = self.repo(max_versoes_por_premissa=3)
        for versao in (1, 2, 3):
            repo.propor(premissa(versao=versao, valor=float(versao)), PROPONENTE)
        with self.assertRaises(LimiteExcedido):
            repo.propor(premissa(versao=4), PROPONENTE)
        self.assertEqual(len(self.arquivos()), 3)

    def test_limite_de_premissas_nao_impede_novas_versoes_das_existentes(self):
        repo = self.repo(max_premissas=2)
        repo.propor(premissa(id="PREM-001"), PROPONENTE)
        repo.propor(premissa(id="PREM-002"), PROPONENTE)
        with self.assertRaises(LimiteExcedido):
            repo.propor(premissa(id="PREM-003"), PROPONENTE)
        repo.propor(premissa(id="PREM-002", versao=2, valor=1.0), PROPONENTE)
        self.assertFalse((self.g.registros / "premissas" / "PREM-003").exists())

    def test_limite_total_de_bytes_conta_tambem_temporarios_orfaos(self):
        repo = self.repo(max_bytes_total=1_048_576)
        repo.propor(premissa(), PROPONENTE)
        (self.g.registros / "premissas" / "PREM-001" / ".v9.json.00.tmp").write_bytes(b"x" * 1_048_000)
        with self.assertRaises(LimiteExcedido):
            repo.propor(premissa(versao=2, valor=2.0), PROPONENTE)
        self.assertEqual(len(repo.recuperar()), 1)
        repo.propor(premissa(versao=2, valor=2.0), PROPONENTE)           # recuperado: volta a caber

    def test_limites_padrao_nao_atrapalham_o_uso_normal(self):
        repo = self.g.repositorio()                                      # sem limites explícitos
        for versao in range(1, 6):
            repo.propor(premissa(versao=versao, valor=float(versao)), PROPONENTE)
        self.assertEqual(repo.limites, Limites())


class TestLerLinha(unittest.TestCase):
    def setUp(self):
        self.servidor, self.cliente = socket.socketpair()

    def tearDown(self):
        self.servidor.close()
        self.cliente.close()

    def test_linha_normal(self):
        self.cliente.sendall(b'{"op": "estado"}\n')
        self.assertEqual(ler_linha(self.servidor, 1024, 1), b'{"op": "estado"}\n')

    def test_requisicao_acima_do_limite(self):
        self.cliente.sendall(b"x" * 600)
        with self.assertRaises(LimiteExcedido):
            ler_linha(self.servidor, 512, 1)

    def test_limite_vale_mesmo_com_o_envio_em_pedacos(self):
        def enviar():
            for _ in range(20):
                self.cliente.sendall(b"y" * 100)
                time.sleep(0.01)
        threading.Thread(target=enviar, daemon=True).start()
        with self.assertRaises(LimiteExcedido):
            ler_linha(self.servidor, 512, 2)

    def test_cliente_parado_estoura_o_prazo(self):
        inicio = time.monotonic()
        with self.assertRaises(TimeoutError):
            ler_linha(self.servidor, 1024, 0.3)
        self.assertLess(time.monotonic() - inicio, 1.5)

    def test_gotejamento_nao_prorroga_o_prazo_total(self):
        def gotejar():
            try:
                for _ in range(50):
                    self.cliente.sendall(b"a")
                    time.sleep(0.1)
            except OSError:
                pass
        threading.Thread(target=gotejar, daemon=True).start()
        inicio = time.monotonic()
        with self.assertRaises(TimeoutError):
            ler_linha(self.servidor, 1024, 0.5)
        self.assertLess(time.monotonic() - inicio, 1.5)

    def test_prazo_vencido_entre_duas_leituras_e_timeout_limpo_e_nao_valueerror(self):
        """Borda: o prazo vence entre iterações; settimeout(negativo) daria ValueError obscuro."""
        tempos = iter([0.0, 0.1, 5.0, 5.0, 5.0])         # fim = 1.0; 1ª leitura ok; depois o prazo já passou
        self.cliente.sendall(b"a")                       # chega algo, sem quebra de linha
        with mock.patch("guardiao.time.monotonic", side_effect=lambda: next(tempos)):
            with self.assertRaises(TimeoutError):
                ler_linha(self.servidor, 1024, 1.0)

    def test_fim_de_conexao_sem_quebra_de_linha_devolve_o_que_chegou(self):
        self.cliente.sendall(b"{}")
        self.cliente.shutdown(socket.SHUT_WR)
        self.assertEqual(ler_linha(self.servidor, 1024, 1), b"{}")


if __name__ == "__main__":
    unittest.main()
