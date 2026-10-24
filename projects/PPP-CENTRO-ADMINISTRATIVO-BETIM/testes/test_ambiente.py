"""GOV-04: ambiente Python reproduzível e verificável (risco R10)."""
import base64
import hashlib
import importlib.metadata as metadata
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "scripts"))

import ambiente  # noqa: E402
from ambiente import AmbienteInvalido  # noqa: E402
from protecao import ConfiguracaoInsegura  # noqa: E402

LOCK_DISTRIBUIDO = RAIZ / "requirements.lock"
HASH = "sha256:" + "ab" * 32


def _b64(dados):
    return base64.urlsafe_b64encode(hashlib.sha256(dados).digest()).rstrip(b"=").decode()


def criar_distribuicao(site, nome, versao, arquivos):
    """Distribuição mínima instalada em `site`, com RECORD no formato do pip."""
    info = site / f"{nome}-{versao}.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {nome}\nVersion: {versao}\n")
    registros = []
    for relativo, dados in arquivos.items():
        (site / relativo).parent.mkdir(parents=True, exist_ok=True)
        (site / relativo).write_bytes(dados)
        registros.append(f"{relativo},sha256={_b64(dados)},{len(dados)}")
    registros += [f"{info.name}/METADATA,,", f"{info.name}/RECORD,,"]
    (info / "RECORD").write_text("\n".join(registros) + "\n")


def escrever_lock(caminho, linhas):
    caminho.write_text("\n".join(linhas) + "\n")


class TestLock(unittest.TestCase):
    def test_lock_distribuido_e_valido_e_completo(self):
        entradas = ambiente.ler_lock(LOCK_DISTRIBUIDO.read_text(encoding="utf-8"))
        self.assertTrue({"jsonschema", "cryptography", "cffi", "pycparser", "attrs", "referencing",
                         "rpds-py", "jsonschema-specifications", "typing-extensions"} <= set(entradas))
        for nome, entrada in entradas.items():
            self.assertTrue(entrada["hashes"], nome)
            self.assertTrue(all(re.fullmatch(r"sha256:[0-9a-f]{64}", h) for h in entrada["hashes"]), nome)
        self.assertEqual(entradas["typing-extensions"]["marcador"], 'python_version < "3.13"')

    def test_lock_cobre_as_dependencias_declaradas_pelos_metadados(self):
        entradas = ambiente.ler_lock(LOCK_DISTRIBUIDO.read_text(encoding="utf-8"))
        for nome in ("jsonschema", "cryptography", "referencing", "cffi", "jsonschema-specifications"):
            try:
                requisitos = metadata.requires(nome) or []
            except metadata.PackageNotFoundError:
                self.skipTest(f"{nome} não instalado; completude do lock não conferível")
            for requisito in requisitos:
                if "extra ==" in requisito:
                    continue
                dependencia = ambiente.normalizar(re.split(r"[ ;<>=!~(\[]", requisito, maxsplit=1)[0])
                marcador = requisito.split(";", 1)[1] if ";" in requisito else ""
                # exceções declaradas: PyPy e Python < 3.11 (o pacote exige 3.11+)
                if "PyPy" in marcador or "python_full_version < '3.11'" in marcador:
                    continue
                self.assertIn(dependencia, entradas, f"{nome} requer {dependencia}, ausente do lock")

    def test_lock_malformado_e_recusado(self):
        casos = {
            "vazio": "# só comentário\n",
            "linha_estranha": "isso nao e requisito\n",
            "sem_hash": "pacote==1.0\n",
            "hash_md5": "pacote==1.0 \\\n    --hash=md5:" + "a" * 32 + "\n",
            "hash_curto": "pacote==1.0 \\\n    --hash=sha256:abc\n",
            "duplicado": f"pacote==1.0 \\\n    --hash={HASH}\npacote==2.0 \\\n    --hash={HASH}\n",
            "sem_versao_exata": f"pacote>=1.0 \\\n    --hash={HASH}\n",
        }
        for nome, texto in casos.items():
            with self.subTest(nome), self.assertRaises(AmbienteInvalido):
                ambiente.ler_lock(texto)

    def test_marcadores(self):
        self.assertTrue(ambiente.marcador_aplica(None, (3, 13)))
        self.assertTrue(ambiente.marcador_aplica('python_version < "3.13"', (3, 12)))
        self.assertFalse(ambiente.marcador_aplica('python_version < "3.13"', (3, 13)))
        self.assertTrue(ambiente.marcador_aplica('python_version >= "3.11" and python_version < "3.13"', (3, 12)))
        self.assertFalse(ambiente.marcador_aplica('python_version >= "3.11" and python_version < "3.13"', (3, 13)))
        for nao_suportado in ('sys_platform == "win32"', 'python_version < "3.13" or os_name == "nt"',
                              'platform_python_implementation != "PyPy"', "python_version < 3.13"):
            with self.subTest(nao_suportado), self.assertRaises(AmbienteInvalido):
                ambiente.marcador_aplica(nao_suportado, (3, 13))


class TestVerificacaoDeDistribuicoes(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.site = self.base / "site"
        self.site.mkdir()
        self.lock = self.base / "requirements.lock"
        criar_distribuicao(self.site, "pacotefalso", "1.2.3", {
            "pacotefalso/__init__.py": b"VALOR = 1\n", "pacotefalso/nucleo.py": b"def f():\n    return 2\n"})
        escrever_lock(self.lock, [f"pacotefalso==1.2.3 \\", f"    --hash={HASH}"])

    def tearDown(self):
        self._tmp.cleanup()

    def verificar(self, **kw):
        return ambiente.verificar(self.lock, caminhos=[self.site], **kw)

    def test_ambiente_conforme(self):
        self.assertEqual(self.verificar(), {"pacotefalso": "1.2.3"})

    def test_dependencia_ausente(self):
        escrever_lock(self.lock, [f"pacotefalso==1.2.3 \\", f"    --hash={HASH}",
                                  f"outrapacote==9.0 \\", f"    --hash={HASH}"])
        with self.assertRaisesRegex(AmbienteInvalido, "outrapacote.*ausente"):
            self.verificar()

    def test_versao_incompativel(self):
        for travada in ("1.2.4", "1.2", "2.0.0"):
            escrever_lock(self.lock, [f"pacotefalso=={travada} \\", f"    --hash={HASH}"])
            with self.subTest(travada), self.assertRaisesRegex(AmbienteInvalido, "incompatível"):
                self.verificar()

    def test_arquivo_adulterado_e_detectado_pelo_record(self):
        (self.site / "pacotefalso" / "nucleo.py").write_bytes(b"def f():\n    return 'malicioso'\n")
        with self.assertRaisesRegex(AmbienteInvalido, "nucleo.py.*difere"):
            self.verificar()

    def test_arquivo_removido_do_pacote(self):
        (self.site / "pacotefalso" / "nucleo.py").unlink()
        with self.assertRaisesRegex(AmbienteInvalido, "ausente"):
            self.verificar()

    def test_arquivo_de_codigo_injetado_no_pacote(self):
        for nome in ("injetado.py", "extensao.so", "gancho.pth"):
            with self.subTest(nome):
                alvo = self.site / "pacotefalso" / nome
                alvo.write_bytes(b"import os\n")
                with self.assertRaisesRegex(AmbienteInvalido, "não listado"):
                    self.verificar()
                alvo.unlink()
        self.assertEqual(self.verificar(), {"pacotefalso": "1.2.3"})

    def test_bytecode_em_pycache_nao_e_hash_verificavel_mas_nao_dispara_falso_positivo(self):
        pycache = self.site / "pacotefalso" / "__pycache__"
        pycache.mkdir()
        (pycache / "nucleo.cpython-313.pyc").write_bytes(b"\x00bytecode")
        self.assertEqual(self.verificar(), {"pacotefalso": "1.2.3"})

    def test_sem_record_nao_ha_como_conferir(self):
        (self.site / "pacotefalso-1.2.3.dist-info" / "RECORD").unlink()
        with self.assertRaisesRegex(AmbienteInvalido, "RECORD"):
            self.verificar()

    def test_hash_diferente_de_sha256_e_recusado(self):
        info = self.site / "pacotefalso-1.2.3.dist-info" / "RECORD"
        info.write_text(info.read_text().replace("sha256=", "md5=", 1))
        with self.assertRaisesRegex(AmbienteInvalido, "só sha256"):
            self.verificar()

    def test_dependencia_com_marcador_falso_nao_e_exigida(self):
        escrever_lock(self.lock, [f"pacotefalso==1.2.3 \\", f"    --hash={HASH}",
                                  f'tipos-extra==1.0 ; python_version < "3.0" \\', f"    --hash={HASH}"])
        self.assertEqual(self.verificar(), {"pacotefalso": "1.2.3"})
        escrever_lock(self.lock, [f"pacotefalso==1.2.3 \\", f"    --hash={HASH}",
                                  f'tipos-extra==1.0 ; python_version < "99.0" \\', f"    --hash={HASH}"])
        with self.assertRaisesRegex(AmbienteInvalido, "tipos-extra.*ausente"):
            self.verificar()

    def test_lock_inexistente(self):
        with self.assertRaises(AmbienteInvalido):
            ambiente.verificar(self.base / "nao-existe.lock", caminhos=[self.site])

    # -- interpretador -------------------------------------------------------------
    def test_modo_isolado_exigido(self):
        with mock.patch.object(sys.flags.__class__, "isolated", 0, create=True) if False else \
                mock.patch("ambiente.sys") as sys_falso:
            sys_falso.flags.isolated = 0
            sys_falso.version_info = sys.version_info
            sys_falso.pycache_prefix = "/x"
            sys_falso.path = []
            with self.assertRaisesRegex(AmbienteInvalido, "isolado"):
                self.verificar(exigir_isolado=True)
            sys_falso.flags.isolated = 1
            self.assertEqual(self.verificar(exigir_isolado=True), {"pacotefalso": "1.2.3"})

    def test_bytecode_em_disco_exige_pycache_prefix(self):
        with mock.patch("ambiente.sys") as sys_falso:
            sys_falso.version_info = sys.version_info
            sys_falso.flags.isolated = 1
            sys_falso.path = []
            sys_falso.pycache_prefix = None
            with self.assertRaisesRegex(AmbienteInvalido, "pycache_prefix"):
                self.verificar(exigir_sem_pyc=True)
            sys_falso.pycache_prefix = "/prefixo-inexistente-ppp"
            self.assertEqual(self.verificar(exigir_sem_pyc=True), {"pacotefalso": "1.2.3"})

    def test_pycache_prefix_gravavel_por_terceiros_e_recusado(self):
        prefixo = self.base / "prefixo"
        prefixo.mkdir()
        os.chmod(prefixo, 0o777)
        with mock.patch("ambiente.sys") as sys_falso:
            sys_falso.version_info = sys.version_info
            sys_falso.flags.isolated = 1
            sys_falso.path = []
            sys_falso.pycache_prefix = str(prefixo)
            with self.assertRaises(ConfiguracaoInsegura):
                self.verificar(exigir_sem_pyc=True, uid_servico=os.getuid())

    # -- proteção contra escrita de terceiros ----------------------------------------
    def test_diretorio_do_pacote_gravavel_por_terceiros_e_recusado(self):
        uid = os.getuid()
        self.assertEqual(self.verificar(uid_servico=uid), {"pacotefalso": "1.2.3"})
        os.chmod(self.site / "pacotefalso", 0o777)
        with self.assertRaises(ConfiguracaoInsegura):
            self.verificar(uid_servico=uid)

    def test_arquivo_do_pacote_gravavel_por_terceiros_e_recusado(self):
        os.chmod(self.site / "pacotefalso" / "nucleo.py", 0o666)
        with self.assertRaises(ConfiguracaoInsegura):
            self.verificar(uid_servico=os.getuid())

    def test_diretorio_de_importacao_gravavel_e_recusado(self):
        os.chmod(self.site, 0o777)
        with self.assertRaises(ConfiguracaoInsegura):
            self.verificar(uid_servico=os.getuid())

    def test_pth_e_sitecustomize_gravaveis_sao_recusados(self):
        uid = os.getuid()
        for nome in ("injecao.pth", "sitecustomize.py", "usercustomize.py"):
            with self.subTest(nome):
                alvo = self.site / nome
                alvo.write_text("import os\n")
                os.chmod(alvo, 0o644)
                self.assertEqual(self.verificar(uid_servico=uid), {"pacotefalso": "1.2.3"})
                os.chmod(alvo, 0o666)
                with self.assertRaises(ConfiguracaoInsegura):
                    self.verificar(uid_servico=uid)
                alvo.unlink()

    def test_link_simbolico_dentro_do_pacote_e_recusado(self):
        os.symlink("/etc/hostname", self.site / "pacotefalso" / "atalho")
        with self.assertRaises(ConfiguracaoInsegura):
            self.verificar(uid_servico=os.getuid())


def _ambiente_real_conforme():
    try:
        ambiente.verificar(LOCK_DISTRIBUIDO)
        return True, ""
    except AmbienteInvalido as erro:
        return False, str(erro)


CONFORME, MOTIVO_NAO_CONFORME = _ambiente_real_conforme()


class TestAmbienteReal(unittest.TestCase):
    @unittest.skipUnless(CONFORME, "ambiente fora do lock (" + MOTIVO_NAO_CONFORME[:80] +
                         "): instale o requirements.lock em um venv")
    def test_ambiente_atual_conforme_ao_lock(self):
        self.assertIn("jsonschema", ambiente.verificar(LOCK_DISTRIBUIDO))

    def test_cli_recusa_lock_inexistente_e_ambiente_incompativel(self):
        with tempfile.TemporaryDirectory() as pasta:
            lock = Path(pasta) / "x.lock"
            escrever_lock(lock, [f"pacote-que-nao-existe==1.0 \\", f"    --hash={HASH}"])
            resultado = subprocess.run(
                [sys.executable, "-I", "-B", str(RAIZ / "scripts" / "ambiente.py"), "--lock", str(lock),
                 "--sem-protecao"], capture_output=True, text=True, timeout=60)
            self.assertEqual(resultado.returncode, 1)
            self.assertIn("ausente", resultado.stderr)
            resultado = subprocess.run(
                [sys.executable, "-I", "-B", str(RAIZ / "scripts" / "ambiente.py"), "--lock",
                 str(Path(pasta) / "nao-existe"), "--sem-protecao"], capture_output=True, text=True, timeout=60)
            self.assertEqual(resultado.returncode, 1)

    @unittest.skipUnless(CONFORME, "ambiente fora do lock")
    def test_cli_aceita_ambiente_conforme(self):
        resultado = subprocess.run(
            [sys.executable, "-I", "-B", str(RAIZ / "scripts" / "ambiente.py"), "--lock",
             str(LOCK_DISTRIBUIDO), "--sem-protecao"], capture_output=True, text=True, timeout=60)
        self.assertEqual(resultado.returncode, 0, resultado.stderr)
        self.assertIn("ok jsonschema==", resultado.stdout)


class TestGerarLock(unittest.TestCase):
    """O gerador do lock (ferramenta de manutenção) testado sem rede, com metadados falsos."""

    @staticmethod
    def falso(metadados):
        def buscar(nome, versao):
            return metadados[(nome, versao)]
        return buscar

    @staticmethod
    def arquivo(tipo, sha, yanked=False):
        return {"packagetype": tipo, "digests": {"sha256": sha}, "yanked": yanked}

    def test_so_wheels_entram_no_lock_e_o_resultado_e_legivel_pelo_verificador(self):
        import gerar_lock
        h1, h2, hsdist, hyank = "a" * 64, "b" * 64, "c" * 64, "d" * 64
        texto = gerar_lock.gerar(
            ["Pacote_Um==1.0", 'outro==2.5;python_version < "3.13"'],
            buscar=self.falso({
                ("Pacote_Um", "1.0"): {"urls": [self.arquivo("bdist_wheel", h2), self.arquivo("bdist_wheel", h1),
                                                 self.arquivo("sdist", hsdist),
                                                 self.arquivo("bdist_wheel", hyank, yanked=True)]},
                ("outro", "2.5"): {"urls": [self.arquivo("bdist_wheel", h1)]}}))
        entradas = ambiente.ler_lock(texto)
        self.assertEqual(entradas["pacote-um"]["hashes"], [f"sha256:{h1}", f"sha256:{h2}"])
        self.assertNotIn(hsdist, texto)
        self.assertNotIn(hyank, texto)
        self.assertEqual(entradas["outro"]["marcador"], 'python_version < "3.13"')
        self.assertTrue(texto.startswith("# GOV-04"))

    def test_sem_wheel_ou_entrada_invalida_e_recusada(self):
        import gerar_lock
        so_sdist = self.falso({("p", "1"): {"urls": [self.arquivo("sdist", "a" * 64)]}})
        with self.assertRaisesRegex(ValueError, "nenhum wheel"):
            gerar_lock.gerar(["p==1"], buscar=so_sdist)
        for invalida in ("p>=1", "p", "==1", "p==", "p==1 extra"):
            with self.subTest(invalida), self.assertRaises(ValueError):
                gerar_lock.gerar([invalida], buscar=so_sdist)

    def test_saida_nunca_sobrescreve(self):
        import gerar_lock
        with tempfile.TemporaryDirectory() as pasta:
            destino = Path(pasta) / "x.lock"
            destino.write_text("existente")
            with mock.patch.object(gerar_lock, "gerar", return_value="novo"):
                with self.assertRaises(FileExistsError):
                    gerar_lock.main(["--saida", str(destino), "p==1"])
            self.assertEqual(destino.read_text(), "existente")


if __name__ == "__main__":
    unittest.main()
