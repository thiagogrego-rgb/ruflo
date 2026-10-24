"""GOV-04: ferramenta do humano (assinar-registro / assinar-referencia) recusa reduzir a série.

Usa pseudo-terminal e chaves sintéticas fora do pacote. A exigência de terminal e de
confirmação é atrito, não segurança; o que se testa aqui é a lógica de proteção da série.
"""
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "scripts"))

import aprovacao  # noqa: E402
from ancora import chave_hex  # noqa: E402
from governanca import canonico  # noqa: E402
from serie import PoliticaSerie  # noqa: E402

FERRAMENTA = RAIZ / "scripts" / "assinar_aprovacao.py"
SENHA = b"frase-sintetica-123"
PROMPTS = re.compile(rb": $")

try:
    import pty
except ImportError:                                    # pragma: no cover (Windows)
    pty = None


def rodar_no_terminal(argumentos, respostas, timeout=60):
    """Executa a ferramenta num pty; `respostas` é consumida a cada prompt. Retorna (código, saída)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, "-I", "-B", str(FERRAMENTA), *argumentos])
    saida, fila = b"", list(respostas)
    import select
    fim = __import__("time").monotonic() + timeout
    while __import__("time").monotonic() < fim:
        if not select.select([fd], [], [], 1)[0]:
            continue
        try:
            dados = os.read(fd, 4096)
        except OSError:
            break
        if not dados:
            break
        saida += dados
        if fila and PROMPTS.search(saida[-3:]):
            os.write(fd, fila.pop(0) + b"\n")
    _, estado = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(estado), saida.decode(errors="replace")


@unittest.skipIf(pty is None, "requer pseudo-terminal (POSIX)")
class TestAssinaturaDeSerie(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.pasta = Path(self._tmp.name)
        self.raiz = Ed25519PrivateKey.generate()
        self.chave = self.pasta / "raiz.pem"
        self.chave.write_bytes(self.raiz.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(SENHA)))
        self.publica = chave_hex(self.raiz)

    def tearDown(self):
        self._tmp.cleanup()

    def cadastro(self, nome, serie=None, extra=None):
        dados = {"formato": 1, "aprovadores": []}
        if serie is not None:
            dados["serie"] = serie
        dados.update(extra or {})
        caminho = self.pasta / nome
        caminho.write_bytes(json.dumps(dados, sort_keys=True).encode())
        return caminho

    def assinado(self, nome, serie, chave=None):
        caminho = self.cadastro(nome, serie)
        Path(f"{caminho}.sig").write_text(
            base64.b64encode((chave or self.raiz).sign(caminho.read_bytes())).decode("ascii"))
        return caminho

    @staticmethod
    def prefixo(caminho):
        return hashlib.sha256(Path(caminho).read_bytes()).hexdigest()[:8].encode()

    def assinar_registro(self, caminho, *flags, confirmar=None):
        return rodar_no_terminal(
            ["assinar-registro", "--chave", str(self.chave), "--registro", str(caminho), *flags],
            [confirmar or self.prefixo(caminho), SENHA])

    def assinar_referencia(self, registro, saida, *flags, confirmar=None):
        return rodar_no_terminal(
            ["assinar-referencia", "--chave", str(self.chave), "--registro", str(registro),
             "--saida", str(saida), *flags], [confirmar or self.prefixo(registro), SENHA])

    def sig_valida(self, caminho):
        return aprovacao.verificar_assinatura(self.publica, Path(f"{caminho}.sig").read_text().strip(),
                                              Path(caminho).read_bytes())

    # -- assinar-registro ------------------------------------------------------------------
    def test_primeiro_cadastro_e_cadastro_com_serie_maior_sao_assinados(self):
        v1 = self.cadastro("v1.json", 1)
        codigo, saida = self.assinar_registro(v1, "--primeiro")
        self.assertEqual(codigo, 0, saida)
        self.assertTrue(self.sig_valida(v1))
        v2 = self.cadastro("v2.json", 2)
        codigo, saida = self.assinar_registro(v2, "--anterior", str(v1))
        self.assertEqual(codigo, 0, saida)
        self.assertIn("Série: 1 -> 2", saida)
        self.assertTrue(self.sig_valida(v2))

    def test_recusa_assinar_serie_que_diminui_ou_repete(self):
        anterior = self.assinado("v5.json", 5)
        for serie in (5, 4, 1):
            with self.subTest(serie=serie):
                novo = self.cadastro(f"novo-{serie}.json", serie, extra={"aprovadores": []})
                codigo, saida = self.assinar_registro(novo, "--anterior", str(anterior))
                self.assertNotEqual(codigo, 0, saida)
                self.assertIn("não pode diminuir nem repetir", saida)
                self.assertFalse(Path(f"{novo}.sig").exists(), "nada pode ser assinado")

    def test_recusa_cadastro_sem_serie_e_sem_referencia_de_comparacao(self):
        sem_serie = self.cadastro("sem-serie.json")
        codigo, saida = self.assinar_registro(sem_serie, "--primeiro")
        self.assertNotEqual(codigo, 0)
        self.assertIn("sem 'serie'", saida)
        com_serie = self.cadastro("com-serie.json", 1)
        codigo, saida = self.assinar_registro(com_serie)                    # nem --anterior nem --primeiro
        self.assertNotEqual(codigo, 0)
        self.assertIn("--anterior", saida)
        self.assertFalse(Path(f"{com_serie}.sig").exists())
        for invalida in (0, -1, True, "2"):
            with self.subTest(serie=invalida):
                ruim = self.cadastro("ruim.json", extra={"serie": invalida})
                codigo, saida = self.assinar_registro(ruim, "--primeiro")
                self.assertNotEqual(codigo, 0, saida)

    def test_sem_serie_so_com_opcao_explicita_do_perfil_legado(self):
        legado = self.cadastro("legado.json")
        codigo, saida = self.assinar_registro(legado, "--sem-serie")
        self.assertEqual(codigo, 0, saida)
        self.assertTrue(self.sig_valida(legado))

    def test_confirmacao_divergente_nao_assina(self):
        v1 = self.cadastro("v1.json", 1)
        codigo, saida = self.assinar_registro(v1, "--primeiro", confirmar=b"00000000")
        self.assertNotEqual(codigo, 0)
        self.assertIn("confirmação divergente", saida)
        self.assertFalse(Path(f"{v1}.sig").exists())

    def test_cadastro_anterior_de_outra_raiz_e_recusado(self):
        anterior = self.assinado("v1.json", 1, chave=Ed25519PrivateKey.generate())
        v2 = self.cadastro("v2.json", 2)
        codigo, saida = self.assinar_registro(v2, "--anterior", str(anterior))
        self.assertNotEqual(codigo, 0)
        self.assertIn("não tem assinatura válida desta chave da raiz", saida)
        self.assertFalse(Path(f"{v2}.sig").exists())

    def test_nao_sobrescreve_assinatura_existente(self):
        v1 = self.assinado("v1.json", 1)
        antes = Path(f"{v1}.sig").read_text()
        codigo, _ = self.assinar_registro(v1, "--primeiro")
        self.assertNotEqual(codigo, 0)
        self.assertEqual(Path(f"{v1}.sig").read_text(), antes)

    def test_chave_dentro_do_projeto_e_recusada(self):
        dentro = RAIZ / "chave-de-teste-nao-deve-existir.pem"
        v1 = self.cadastro("v1.json", 1)
        codigo, saida = rodar_no_terminal(
            ["assinar-registro", "--chave", str(dentro), "--registro", str(v1), "--primeiro"], [])
        self.assertNotEqual(codigo, 0)
        self.assertIn("não pode ficar dentro do projeto", saida)

    # -- assinar-referencia ---------------------------------------------------------------------
    def test_referencia_emitida_e_aceita_pela_politica_de_serie(self):
        v3 = self.assinado("v3.json", 3)
        saida_ref = self.pasta / "ref.json"
        codigo, saida = self.assinar_referencia(v3, saida_ref, "--primeira")
        self.assertEqual(codigo, 0, saida)
        politica = PoliticaSerie(saida_ref, self.pasta / "estado" / "m.json", self.publica)
        payload = politica.carregar_referencia()
        self.assertEqual((payload["serie_minima"], payload["sha256_cadastro"]),
                         (3, hashlib.sha256(v3.read_bytes()).hexdigest()))
        self.assertEqual(politica.validar(3, payload["sha256_cadastro"]), 3)

    def test_referencia_nao_diminui_nem_repete_com_outro_conteudo(self):
        v5 = self.assinado("v5.json", 5)
        ref5 = self.pasta / "ref5.json"
        self.assertEqual(self.assinar_referencia(v5, ref5, "--primeira")[0], 0)
        v3 = self.assinado("v3.json", 3)
        codigo, saida = self.assinar_referencia(v3, self.pasta / "ref3.json", "--anterior-referencia", str(ref5))
        self.assertNotEqual(codigo, 0)
        self.assertIn("não pode diminuir nem repetir", saida)
        outro = self.cadastro("outro5.json", 5, extra={"aprovadores": [], "nota": "outro"})
        Path(f"{outro}.sig").write_text(base64.b64encode(self.raiz.sign(outro.read_bytes())).decode())
        codigo, saida = self.assinar_referencia(outro, self.pasta / "refx.json", "--anterior-referencia", str(ref5))
        self.assertNotEqual(codigo, 0)
        self.assertFalse((self.pasta / "refx.json").exists())
        v6 = self.assinado("v6.json", 6)
        codigo, saida = self.assinar_referencia(v6, self.pasta / "ref6.json", "--anterior-referencia", str(ref5))
        self.assertEqual(codigo, 0, saida)

    def test_referencia_exige_cadastro_assinado_pela_mesma_raiz_e_com_serie(self):
        de_outra = self.assinado("alheio.json", 2, chave=Ed25519PrivateKey.generate())
        codigo, saida = self.assinar_referencia(de_outra, self.pasta / "r1.json", "--primeira")
        self.assertNotEqual(codigo, 0)
        self.assertIn("não tem assinatura válida desta chave da raiz", saida)
        sem_serie = self.cadastro("legado.json")
        codigo, saida = self.assinar_referencia(sem_serie, self.pasta / "r2.json", "--primeira")
        self.assertNotEqual(codigo, 0)
        self.assertIn("não tem 'serie'", saida)
        v1 = self.assinado("v1.json", 1)
        codigo, saida = self.assinar_referencia(v1, self.pasta / "r3.json")           # sem --primeira/--anterior
        self.assertNotEqual(codigo, 0)
        self.assertIn("--anterior-referencia", saida)
        self.assertFalse(any((self.pasta / n).exists() for n in ("r1.json", "r2.json", "r3.json")))

    def test_referencia_com_confirmacao_divergente_ou_saida_existente(self):
        v1 = self.assinado("v1.json", 1)
        codigo, saida = self.assinar_referencia(v1, self.pasta / "r.json", "--primeira", confirmar=b"zzzzzzzz")
        self.assertNotEqual(codigo, 0)
        self.assertIn("confirmação divergente", saida)
        existente = self.pasta / "r.json"
        existente.write_bytes(b"{}")
        codigo, _ = self.assinar_referencia(v1, existente, "--primeira")
        self.assertNotEqual(codigo, 0)
        self.assertEqual(existente.read_bytes(), b"{}")


if __name__ == "__main__":
    unittest.main()
