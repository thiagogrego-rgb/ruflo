"""GOV-04: ferramenta INDEPENDENTE de conferência de checkpoints (scripts/verificar_ancora.py)."""
import ast
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from apoio import PROPONENTE, Ambiente, premissa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ancora
import aprovacao
from governanca import canonico

RAIZ = Path(__file__).resolve().parents[1]
FERRAMENTA = RAIZ / "scripts" / "verificar_ancora.py"
sys.path.insert(0, str(RAIZ / "scripts"))
import verificar_ancora as va  # noqa: E402  (também exercitada como processo independente)

CADASTRO_1 = {"serie": 1, "sha256": "a" * 64}


class Cadeia:
    """Checkpoints reais (emitidos por `ancora.emitir_checkpoint`) copiados para um 'meio externo'."""

    def __init__(self):
        self.amb = Ambiente()
        self.chave = Ed25519PrivateKey.generate()
        self.publica = ancora.chave_hex(self.chave)
        self._tmp = tempfile.TemporaryDirectory()
        self.externo = Path(self._tmp.name) / "externo"
        self.externo.mkdir()
        self.emitidos = []

    def propor(self, versao=1, premissa_id="PREM-001", valor=42.5):
        self.amb.repo.propor(premissa(id=premissa_id, versao=versao, valor=valor), PROPONENTE)

    def aprovar(self, versao=1, premissa_id="PREM-001"):
        self.amb.repo.registrar_aprovacao(self.amb.aprovacao(premissa_id=premissa_id, versao=versao))

    def checkpoint(self, cadastro=None):
        anterior = self.emitidos[-1] if self.emitidos else None
        novo = ancora.emitir_checkpoint(self.amb.repo, self.chave, anterior, cadastro)
        self.emitidos.append(novo)
        self.salvar(novo)
        return novo

    def salvar(self, checkpoint, nome=None):
        nome = nome or f"seq-{checkpoint['payload']['seq']}.json"
        (self.externo / nome).write_bytes(canonico(checkpoint))

    def assinar(self, payload):
        """Checkpoint com assinatura VÁLIDA e conteúdo arbitrário (guardião defeituoso/comprometido)."""
        return aprovacao.assinar(payload, self.chave)

    def rodar(self, *argumentos, chave=None, extras=()):
        return subprocess.run(
            [sys.executable, "-I", "-B", str(FERRAMENTA), "--chave-guardiao", chave or self.publica,
             "--checkpoints", *argumentos, *extras], capture_output=True, text=True, timeout=60)

    def verificar(self, **kw):
        return va.verificar(va.carregar([self.externo]), kw.pop("chave", self.publica), **kw)

    def fechar(self):
        self.amb.fechar()
        self._tmp.cleanup()


class TestVerificarAncora(unittest.TestCase):
    def setUp(self):
        self.c = Cadeia()

    def tearDown(self):
        self.c.fechar()

    def cadeia_basica(self):
        self.c.propor(1)
        self.c.checkpoint(CADASTRO_1)
        self.c.aprovar(1)
        self.c.propor(2, valor=44.0)
        self.c.checkpoint(CADASTRO_1)
        self.c.propor(3, valor=46.0)
        self.c.checkpoint({"serie": 2, "sha256": "b" * 64})

    def assertViolacao(self, relatorio, trecho):
        self.assertFalse(relatorio["ok"], relatorio)
        self.assertTrue(any(trecho in v for v in relatorio["violacoes"]), relatorio["violacoes"])

    # -- checkpoint válido -------------------------------------------------------
    def test_cadeia_valida_passa(self):
        self.cadeia_basica()
        relatorio = self.c.verificar()
        self.assertTrue(relatorio["ok"], relatorio)
        self.assertEqual((relatorio["checkpoints"], relatorio["ultimo_seq"]), (3, 3))

    def test_processo_independente_devolve_codigos_de_saida(self):
        self.cadeia_basica()
        ok = self.c.rodar(str(self.c.externo))
        self.assertEqual((ok.returncode, ok.stdout.strip().splitlines()[-1]),
                         (0, "OK: 3 checkpoint(s) conferido(s); último seq 3"))
        saida_json = self.c.rodar(str(self.c.externo), extras=("--json",))
        self.assertTrue(json.loads(saida_json.stdout)["ok"])
        (self.c.externo / "seq-2.json").unlink()
        falha = self.c.rodar(str(self.c.externo))
        self.assertEqual(falha.returncode, 1)
        self.assertIn("VIOLAÇÃO", falha.stdout)
        erro_de_uso = self.c.rodar(str(self.c.externo / "nao-existe"))
        self.assertEqual(erro_de_uso.returncode, 2)

    def test_arquivos_diretos_e_ultimo_json_e_ignorado(self):
        self.cadeia_basica()
        shutil.copy(self.c.externo / "seq-3.json", self.c.externo / "ultimo.json")
        self.assertTrue(self.c.verificar()["ok"])
        arquivos = [str(self.c.externo / f"seq-{n}.json") for n in (1, 2, 3)]
        self.assertEqual(self.c.rodar(*arquivos).returncode, 0)

    def test_seq_duplicado_identico_e_aceito_mas_diferente_e_violacao(self):
        self.cadeia_basica()
        shutil.copy(self.c.externo / "seq-2.json", self.c.externo / "copia-do-seq-2.json")
        self.assertTrue(self.c.verificar()["ok"])
        outro = copy.deepcopy(self.c.emitidos[1])
        outro["payload"]["emitido_em"] = "2030-01-01T00:00:00+00:00"
        self.c.salvar(self.c.assinar(outro["payload"]), "outro-seq-2.json")
        self.assertViolacao(self.c.verificar(), "duplicado com conteúdo diferente")

    # -- checkpoint inválido: assinatura e formato -------------------------------------
    def test_assinatura_e_chave(self):
        self.cadeia_basica()
        self.assertViolacao(self.c.verificar(chave=ancora.chave_hex(Ed25519PrivateKey.generate())),
                            "assinatura inválida")
        adulterado = json.loads((self.c.externo / "seq-2.json").read_bytes())
        adulterado["payload"]["estado"]["PREM-001"]["versoes"].pop()
        (self.c.externo / "seq-2.json").write_bytes(canonico(adulterado))
        self.assertViolacao(self.c.verificar(), "assinatura inválida")

    def test_formato_invalido(self):
        self.cadeia_basica()
        base = copy.deepcopy(self.c.emitidos[-1]["payload"])
        casos = {
            "campo_extra": dict(base, extra=1),
            "tipo_errado": dict(base, tipo="outro"),
            "seq_texto": dict(base, seq="3"),
            "seq_booleano": dict(base, seq=True),
            "anterior_invalido": dict(base, anterior="xyz"),
            "estado_nao_objeto": dict(base, estado=[]),
            "estado_malformado": dict(base, estado={"PREM-001": {"versoes": ["x"], "aprovacoes": {}}}),
            "id_malformado": dict(base, estado={"../etc": {"versoes": [], "aprovacoes": {}}}),
            "aprovacao_de_versao_inexistente": dict(
                base, estado={"PREM-001": {"versoes": ["a" * 64], "aprovacoes": {"9": "b" * 64}}}),
            "cadastro_malformado": dict(base, cadastro={"serie": 0, "sha256": "a" * 64}),
        }
        for nome, payload in casos.items():
            with self.subTest(nome):
                pasta = Path(tempfile.mkdtemp(dir=self.c.externo.parent))
                (pasta / "cp.json").write_bytes(canonico(self.c.assinar(payload)))
                relatorio = va.verificar(va.carregar([pasta]), self.c.publica)
                self.assertFalse(relatorio["ok"], nome)
        for lixo in (b"nao e json", b"[]", b'{"payload": {}}', b'{"payload": {}, "assinatura": 1}'):
            with self.subTest(lixo=lixo):
                pasta = Path(tempfile.mkdtemp(dir=self.c.externo.parent))
                (pasta / "cp.json").write_bytes(lixo)
                self.assertFalse(va.verificar(va.carregar([pasta]), self.c.publica)["ok"])

    def test_chave_informada_invalida_e_erro_de_uso(self):
        self.cadeia_basica()
        for ruim in ("", "abc", "G" * 64, "A" * 64):
            with self.subTest(ruim=ruim), self.assertRaises(va.ErroDeUso):
                self.c.verificar(chave=ruim)
        self.assertEqual(self.c.rodar(str(self.c.externo), chave="abc").returncode, 2)

    def test_sem_checkpoints_e_erro_de_uso(self):
        vazio = Path(tempfile.mkdtemp(dir=self.c.externo.parent))
        with self.assertRaises(va.ErroDeUso):
            va.carregar([vazio])

    # -- encadeamento e sequência -----------------------------------------------------------
    def test_lacuna_na_sequencia(self):
        self.cadeia_basica()
        (self.c.externo / "seq-2.json").unlink()
        self.assertViolacao(self.c.verificar(), "lacuna na sequência")

    def test_encadeamento_rompido_com_assinatura_valida(self):
        self.cadeia_basica()
        forjado = copy.deepcopy(self.c.emitidos[2]["payload"])
        forjado["anterior"] = "0" * 64
        self.c.salvar(self.c.assinar(forjado), "seq-3.json")
        self.assertViolacao(self.c.verificar(), "encadeamento por hash rompido")

    def test_primeiro_checkpoint_e_inicio(self):
        self.cadeia_basica()
        (self.c.externo / "seq-1.json").unlink()
        (self.c.externo / "seq-2.json").unlink()
        relatorio = self.c.verificar()
        self.assertTrue(relatorio["ok"])
        self.assertTrue(any("cadeia anterior não conferida" in a for a in relatorio["avisos"]))
        self.assertViolacao(self.c.verificar(inicio=1), "esperado 1")
        self.assertTrue(self.c.verificar(inicio=3)["ok"])

    def test_seq_1_nao_pode_ter_anterior(self):
        self.cadeia_basica()
        forjado = copy.deepcopy(self.c.emitidos[0]["payload"])
        forjado["anterior"] = "1" * 64
        pasta = Path(tempfile.mkdtemp(dir=self.c.externo.parent))
        (pasta / "cp.json").write_bytes(canonico(self.c.assinar(forjado)))
        self.assertViolacao(va.verificar(va.carregar([pasta]), self.c.publica), "seq 1 não pode")

    # -- monotonicidade (guardião defeituoso/comprometido assina conteúdo regressivo) ---------
    def regressivo(self, transformar, indice=2):
        self.cadeia_basica()
        forjado = copy.deepcopy(self.c.emitidos[indice]["payload"])
        transformar(forjado)
        # o checkpoint forjado é encadeado de forma correta ao anterior
        forjado["anterior"] = va.sha256(canonico(self.c.emitidos[indice - 1]))
        self.c.salvar(self.c.assinar(forjado), f"seq-{indice + 1}.json")
        return self.c.verificar()

    def test_versao_ancorada_removida(self):
        # O seq 2 já ancorou v1 e v2; um seq 3 que volta a só v1 perdeu algo ancorado.
        r = self.regressivo(lambda p: p["estado"]["PREM-001"]["versoes"].__delitem__(slice(1, None)))
        self.assertViolacao(r, "versão ancorada removida ou alterada")

    def test_versao_nunca_ancorada_antes_nao_e_detectavel_pela_cadeia(self):
        """Limite documentado: só se detecta o desaparecimento do que JÁ foi ancorado."""
        r = self.regressivo(lambda p: p["estado"]["PREM-001"]["versoes"].pop())
        self.assertTrue(r["ok"], "v3 foi ancorada pela primeira vez no próprio seq 3")

    def test_versao_ancorada_alterada(self):
        def alterar(p):
            p["estado"]["PREM-001"]["versoes"][0] = "f" * 64
        self.assertViolacao(self.regressivo(alterar), "versão ancorada removida ou alterada")

    def test_aprovacao_ancorada_removida_ou_trocada(self):
        self.assertViolacao(self.regressivo(lambda p: p["estado"]["PREM-001"]["aprovacoes"].clear()),
                            "aprovação ancorada removida ou alterada")
        self.tearDown()
        self.setUp()
        self.assertViolacao(
            self.regressivo(lambda p: p["estado"]["PREM-001"]["aprovacoes"].__setitem__("1", "e" * 64)),
            "aprovação ancorada removida ou alterada")

    def test_premissa_ancorada_desapareceu(self):
        self.assertViolacao(self.regressivo(lambda p: p["estado"].clear()), "desapareceu")

    def _forjar_apos(self, indice, cadastro, seq):
        forjado = copy.deepcopy(self.c.emitidos[indice]["payload"])
        forjado["seq"], forjado["cadastro"] = seq, cadastro
        forjado["anterior"] = va.sha256(canonico(self.c.emitidos[indice]))
        self.c.salvar(self.c.assinar(forjado), f"seq-{seq}.json")

    def test_serie_do_cadastro_diminuiu(self):
        self.c.propor(1)
        self.c.checkpoint({"serie": 1, "sha256": "a" * 64})
        self.c.checkpoint({"serie": 2, "sha256": "b" * 64})
        self._forjar_apos(1, {"serie": 1, "sha256": "a" * 64}, seq=3)
        self.assertViolacao(self.c.verificar(), "série do cadastro diminuiu (2 -> 1)")

    def test_serie_repetida_com_conteudo_diferente(self):
        self.c.propor(1)
        self.c.checkpoint({"serie": 2, "sha256": "b" * 64})
        self._forjar_apos(0, {"serie": 2, "sha256": "f" * 64}, seq=2)
        self.assertViolacao(self.c.verificar(), "série 2 do cadastro com conteúdo diferente")

    def test_serie_igual_com_o_mesmo_conteudo_e_crescente_sao_aceitas(self):
        self.c.propor(1)
        self.c.checkpoint({"serie": 1, "sha256": "a" * 64})
        self.c.checkpoint({"serie": 1, "sha256": "a" * 64})
        self.c.checkpoint({"serie": 3, "sha256": "c" * 64})
        self.assertTrue(self.c.verificar()["ok"])

    def test_checkpoint_que_deixa_de_atestar_o_cadastro(self):
        self.assertViolacao(self.regressivo(lambda p: p.pop("cadastro")), "deixou de atestar o cadastro")

    # -- armazenamento atual contra o último checkpoint ---------------------------------------
    def test_armazenamento_integro_e_versoes_novas_geram_apenas_aviso(self):
        self.cadeia_basica()
        self.c.propor(4, valor=50.0)                                      # posterior ao último checkpoint
        relatorio = self.c.verificar(registros=self.c.amb.registros)
        self.assertTrue(relatorio["ok"], relatorio)
        self.assertTrue(any("ainda não ancorada" in a for a in relatorio["avisos"]))

    def test_rollback_no_armazenamento_e_detectado(self):
        self.cadeia_basica()
        pasta = self.c.amb.registros / "premissas" / "PREM-001"
        (pasta / "v3.json").chmod(0o644)
        (pasta / "v3.json").unlink()
        self.assertViolacao(self.c.verificar(registros=self.c.amb.registros), "versão ancorada removida")

    def test_remocao_da_aprovacao_no_armazenamento_e_detectada(self):
        self.cadeia_basica()
        (self.c.amb.registros / "premissas" / "PREM-001" / "v1.aprovacao.json").unlink()
        self.assertViolacao(self.c.verificar(registros=self.c.amb.registros), "aprovação ancorada removida")

    def test_adulteracao_de_versao_e_lacuna_no_armazenamento(self):
        self.cadeia_basica()
        pasta = self.c.amb.registros / "premissas" / "PREM-001"
        (pasta / "v2.json").chmod(0o644)
        (pasta / "v2.json").write_bytes(b"{}")
        self.assertViolacao(self.c.verificar(registros=self.c.amb.registros), "alterada")
        (pasta / "v2.json").unlink()
        self.assertViolacao(self.c.verificar(registros=self.c.amb.registros), "lacuna")

    def test_premissa_inteira_removida_do_armazenamento(self):
        self.cadeia_basica()
        shutil.rmtree(self.c.amb.registros / "premissas" / "PREM-001")
        self.assertViolacao(self.c.verificar(registros=self.c.amb.registros), "desapareceu")

    def test_armazenamento_inexistente_e_violacao(self):
        self.cadeia_basica()
        self.assertViolacao(self.c.verificar(registros=self.c.externo.parent / "nada"), "inexistente")

    # -- série mínima --------------------------------------------------------------------------------
    def test_serie_minima_exigida(self):
        self.cadeia_basica()
        self.assertTrue(self.c.verificar(serie_minima=2)["ok"])
        self.assertViolacao(self.c.verificar(serie_minima=3), "abaixo da mínima")
        pasta = Path(tempfile.mkdtemp(dir=self.c.externo.parent))
        sem_cadastro = copy.deepcopy(self.c.emitidos[0]["payload"])
        sem_cadastro.pop("cadastro")
        (pasta / "cp.json").write_bytes(canonico(self.c.assinar(sem_cadastro)))
        self.assertViolacao(va.verificar(va.carregar([pasta]), self.c.publica, serie_minima=1),
                            "não atesta o cadastro")

    # -- independência -----------------------------------------------------------------------------------
    def test_ferramenta_nao_importa_modulos_do_projeto(self):
        arvore = ast.parse(FERRAMENTA.read_text(encoding="utf-8"))
        importados = set()
        for no in ast.walk(arvore):
            if isinstance(no, ast.Import):
                importados |= {a.name.split(".")[0] for a in no.names}
            elif isinstance(no, ast.ImportFrom) and no.module:
                importados.add(no.module.split(".")[0])
        projeto = {p.stem for p in (RAIZ / "scripts").glob("*.py")} - {"verificar_ancora"}
        self.assertEqual(importados & projeto, set(), "a ferramenta deve ser autônoma")
        self.assertTrue(importados <= set(sys.stdlib_module_names) | {"cryptography"}, importados)

    def test_funciona_copiada_sozinha_para_fora_do_projeto(self):
        self.cadeia_basica()
        with tempfile.TemporaryDirectory() as pasta:
            copia = Path(pasta) / "verificar_ancora.py"
            shutil.copy(FERRAMENTA, copia)
            resultado = subprocess.run(
                [sys.executable, "-I", "-B", str(copia), "--chave-guardiao", self.c.publica,
                 "--checkpoints", str(self.c.externo)], capture_output=True, text=True, cwd=pasta, timeout=60)
            self.assertEqual(resultado.returncode, 0, resultado.stderr)

    def test_ferramenta_somente_le(self):
        self.cadeia_basica()
        antes = {a.name: a.read_bytes() for a in self.c.externo.iterdir()}
        for a in self.c.externo.iterdir():
            os.chmod(a, 0o444)
        os.chmod(self.c.externo, 0o555)
        try:
            self.assertTrue(self.c.verificar(registros=self.c.amb.registros)["ok"])
        finally:
            os.chmod(self.c.externo, 0o755)
        self.assertEqual({a.name: a.read_bytes() for a in self.c.externo.iterdir()}, antes)


if __name__ == "__main__":
    unittest.main()
