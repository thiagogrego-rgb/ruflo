import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from governanca import validar_premissa, aprovar_decisao, autorizar_publicacao

BASE = dict(id="PREM-001", versao=1, produto="P3",
            natureza="HIPOTESE", unidade="BRL/m2/mes",
            status="PROPOSTA", justificativa_hipotese="Teste sintético")

class TestGovernanca(unittest.TestCase):
    def test_hipotese_valida(self):
        self.assertTrue(validar_premissa(BASE.copy()))
    def test_hipotese_sem_justificativa(self):
        p = BASE.copy()
        p.pop("justificativa_hipotese")
        with self.assertRaises(ValueError):
            validar_premissa(p)
    def test_dado_sem_fonte(self):
        p = BASE.copy()
        p["natureza"] = "OBSERVADO"
        with self.assertRaises(ValueError):
            validar_premissa(p)
    def test_aprovacao_bloqueada(self):
        p = BASE.copy()
        p["status"] = "APROVADA"
        with self.assertRaises(PermissionError):
            validar_premissa(p)
    def test_decisao_bloqueada(self):
        with self.assertRaises(PermissionError):
            aprovar_decisao()
    def test_publicacao_bloqueada(self):
        with self.assertRaises(PermissionError):
            autorizar_publicacao()
