"""GOV-09 integrado: cenário sintético TESTE-INTEGRACAO-001, pacotes de transferência, cadeia rastreável e pacote de contexto do Chat.

Estes testes exercitam a MECÂNICA em código. Não provam o comportamento de agentes (exige modelo real) nem de conversas do Claude Chat
(sem acesso): isso é NÃO EXECUTADO e está declarado no relatório do cenário.
"""
import copy
import json
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import integracao_chat as IC  # noqa: E402


class TestCalculo(unittest.TestCase):
    def test_valores_conferem_com_calculo_independente(self):
        r = IC.calculo_p4(IC.fixture_cenario())["saida"]
        receita = 150 * 85 * 12 * 0.92
        fator = sum(1 / 1.1 ** t for t in range(1, 21))
        self.assertEqual(Decimal(r["delta_receita_anual_brl"]), Decimal("140760.00"))
        self.assertAlmostEqual(float(r["vpl_receita_brl"]), receita * fator, delta=0.5)
        self.assertEqual(Decimal(r["capex_brl"]), Decimal("480000.00"))
        self.assertEqual(Decimal(r["vpl_liquido_brl"]), Decimal(r["vpl_receita_brl"]) - Decimal(r["capex_brl"]))

    def test_mesma_entrada_mesma_saida_e_hashes_estaveis(self):
        a, b = IC.calculo_p4(IC.fixture_cenario()), IC.calculo_p4(IC.fixture_cenario())
        self.assertEqual(a, b)
        f = IC.fixture_cenario()
        f["premissas"][1]["valor"] = "86.00"
        c = IC.calculo_p4(f)
        self.assertNotEqual(a["sha256_entrada"], c["sha256_entrada"])
        self.assertNotEqual(a["sha256_saida"], c["sha256_saida"])


class TestPacote(unittest.TestCase):
    def setUp(self):
        self.fix = IC.fixture_cenario()
        self.p = IC.montar_pacote("C", "P1", 1, self.fix, "2026-10-25", "esperado", "tarefa")

    def test_pacote_completo_e_valido(self):
        self.assertEqual(IC.validar_pacote(self.p), [])

    def test_cada_campo_obrigatorio_e_exigido(self):
        for campo in IC.CAMPOS_PACOTE:
            q = copy.deepcopy(self.p)
            del q[campo]
            self.assertTrue(IC.validar_pacote(q), campo)

    def test_pacote_nao_sintetico_ou_sigiloso_ou_aprovado_e_recusado(self):
        for campo, valor in (("natureza_dados", "REAL"), ("classificacao_sigilo", "RESTRITO"), ("estado_aprovacao", "APROVADA"),
                             ("produto_origem", "HERMES"), ("data", "25/10/2026"), ("referencias_premissas", ["x"])):
            q = copy.deepcopy(self.p)
            q[campo] = valor
            q["sha256"] = IC.sha({k: v for k, v in q.items() if k != "sha256"})          # hash coerente: o que reprova é a regra, não o hash
            self.assertTrue(IC.validar_pacote(q), campo)

    def test_material_proibido_e_recusado(self):
        for texto in ("ver DR-01 original", "CPF 123.456.789-09", "CNPJ 12.345.678/0001-90", "fulano@exemplo.com.br", "dados/restritos/x",
                      "produtos/DR/saida/y", "sk-ant-api03-abc"):
            q = copy.deepcopy(self.p)
            q["corpo"]["tarefa"] = texto
            q["sha256"] = IC.sha({k: v for k, v in q.items() if k != "sha256"})
            self.assertTrue(any("proibido" in x for x in IC.validar_pacote(q)), texto)

    def test_pacote_adulterado_apos_emissao_e_detectado(self):
        q = copy.deepcopy(self.p)
        q["resultado_esperado"] = "outro"
        self.assertTrue(any("sha256" in x for x in IC.validar_pacote(q)))

    def test_nao_objeto_e_recusado(self):
        self.assertTrue(IC.validar_pacote("texto"))
        self.assertTrue(IC.validar_pacote(None))


class TestCenario(unittest.TestCase):
    def setUp(self):
        self.pasta = Path(tempfile.mkdtemp(prefix="cenario-"))
        self.rel = IC.executar_cenario(self.pasta, "2026-10-25")

    def test_toda_verificacao_mecanica_passa(self):
        self.assertTrue(self.rel["verificacoes_mecanicas"])
        self.assertEqual({v for v in self.rel["verificacoes_mecanicas"].values()}, {"PASSOU"}, self.rel["verificacoes_mecanicas"])

    def test_o_que_nao_foi_possivel_fica_declarado_nao_executado(self):
        self.assertTrue(self.rel["execucao_por_agentes_reais"].startswith("NAO_EXECUTADO"))
        self.assertTrue(self.rel["transferencia_para_o_claude_chat"].startswith("NAO_EXECUTADO"))

    def test_nove_encaminhamentos_na_ordem_pedida(self):
        arqs = sorted((self.pasta / "pacotes").glob("*.json"))
        self.assertEqual([a.name for a in arqs], ["01-C-para-P1.json", "02-P1-para-P2.json", "03-P2-para-P3.json", "04-P3-para-P4.json",
                                                  "05-P4-para-P5.json", "06-P5-para-P6.json", "07-P6-para-P7.json", "08-P7-para-REV.json",
                                                  "09-REV-para-C.json"])
        for a in arqs:
            self.assertEqual(IC.validar_pacote(json.loads(a.read_text())), [], a.name)

    def test_cadeia_de_transferencias_detecta_adulteracao_e_remocao(self):
        arq = self.pasta / "cadeia-de-transferencias.jsonl"
        self.assertEqual(IC.verificar_cadeia_arquivo(arq), [])
        linhas = arq.read_text().splitlines()
        arq.write_text("\n".join(linhas[:3] + linhas[4:]) + "\n")
        self.assertTrue(IC.verificar_cadeia_arquivo(arq))
        arq.write_text("\n".join(linhas).replace('"destino": "P4"', '"destino": "P5"') + "\n")
        self.assertTrue(IC.verificar_cadeia_arquivo(arq))

    def test_proposta_final_nao_e_aprovada_e_aponta_portao_humano(self):
        prop = json.loads((self.pasta / "proposta-de-decisao.json").read_text())
        self.assertFalse(prop["aprovada"])
        self.assertEqual(prop["estado"], "PROPOSTA")
        self.assertIn("Coordenador humano", prop["portao_humano_aplicavel"])

    def test_fixture_e_marcada_como_teste_e_sintetica(self):
        f = json.loads((self.pasta / "fixture.json").read_text())
        self.assertEqual(f["fonte"]["tipo"], "FIXTURE_DE_TESTE")
        self.assertEqual(f["natureza_dados"], "SINTETICO")
        self.assertEqual({p["status"] for p in f["premissas"]}, {"PROPOSTA"})


class TestContexto(unittest.TestCase):
    def setUp(self):
        self.pasta = Path(tempfile.mkdtemp(prefix="ctx-"))
        self.m = IC.construir_contexto(self.pasta, ROOT, "2026-10-25")

    def test_manifesto_confere_e_so_tem_material_sintetico(self):
        self.assertEqual(IC.verificar_contexto(self.pasta), [])
        self.assertEqual(self.m["natureza_dados"], "SINTETICO")
        self.assertEqual(set(self.m["arquivos"]), set(IC.ARQUIVOS_DO_CONTEXTO) | {"INSTRUCOES-GLOBAIS-SUGERIDAS.md"})
        for rx in IC.PROIBIDO:
            for arq in self.pasta.iterdir():
                self.assertIsNone(rx.search(arq.read_text(encoding="utf-8")), f"{arq.name}: {rx.pattern}")

    def test_arquivo_alterado_ou_estranho_e_detectado(self):
        (self.pasta / "MATRIZ-DE-AGENTES.md").write_text("alterado")
        (self.pasta / "documento-real.pdf").write_text("x")
        problemas = IC.verificar_contexto(self.pasta)
        self.assertTrue(any("alterado" in p for p in problemas))
        self.assertTrue(any("fora do manifesto" in p for p in problemas))

    def test_instrucoes_declaram_o_repositorio_como_fonte_e_a_transferencia_manual(self):
        t = (self.pasta / "INSTRUCOES-GLOBAIS-SUGERIDAS.md").read_text()
        self.assertIn("REPOSITÓRIO", t)
        self.assertIn("manual", t)
        self.assertIn("PROPOSTA", t)

    def test_matriz_lista_os_dez_agentes(self):
        t = (self.pasta / "MATRIZ-DE-AGENTES.md").read_text()
        for ag in ("c-orquestrador", "controlador-dr", "revisor-independente", "p1-diagnostico", "p7-licitacao"):
            self.assertIn(ag, t)
        self.assertEqual(len([l for l in t.splitlines() if l.startswith("| ") and not l.startswith(("| Agente", "|---"))]), 10)
        self.assertNotIn("produtos/DR", t)                                        # caminho de área restrita não vai para o Chat


if __name__ == "__main__":
    unittest.main()
