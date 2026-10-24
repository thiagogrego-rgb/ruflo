"""GOV-04: robustez do núcleo com o guardião REAL (formato 2) e uids sintéticos sem privilégio.

Cobre rollback do cadastro com a referência externa, ambiente Python, limites de tamanho,
frequência e crescimento, checkpoints e recuperação após interrupção. Pulado sem Linux+root ou
com um Python fora do requirements.lock; nesse caso a fronteira NÃO está validada.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

from apoio import premissa
from apoio_guardiao import (APTO_PARA_INTEGRACAO, MOTIVO_NAO_APTO, UID_AGENTE, UID_ANCORA, UID_GUARDIAO,
                            UID_HUMANO, UID_OUTRO, Cenario, Mundo, ambiente_conforme)

RAIZ = Path(__file__).resolve().parents[1]
CONFORME, MOTIVO_NAO_CONFORME = ambiente_conforme() if APTO_PARA_INTEGRACAO else (False, "")
PULAR = (not APTO_PARA_INTEGRACAO) or (not CONFORME)
MOTIVO = MOTIVO_NAO_APTO if not APTO_PARA_INTEGRACAO else (
    "ambiente fora do requirements.lock (" + MOTIVO_NAO_CONFORME[:90] + "): use o venv do lock")


def propor(versao=1, pid="PREM-001", **campos):
    return {"op": "propor", "premissa": premissa(id=pid, versao=versao, **campos)}


def estado(pid="PREM-001", versao=1):
    return {"op": "estado", "id": pid, "versao": versao}


def registrar(aprovacao):
    return {"op": "registrar_aprovacao", "aprovacao": aprovacao}


CHECKPOINT = {"op": "checkpoint"}


@unittest.skipIf(PULAR, MOTIVO)
class TestRobustezGuardiao(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mundo = Mundo()

    @classmethod
    def tearDownClass(cls):
        cls.mundo.fechar()

    def cenario(self, **kw):
        self.mundo.contador += 1
        return Cenario(self.mundo, f"c{self.mundo.contador}-{self._testMethodName[5:30]}", **kw)

    def assertErro(self, resposta, tipo):
        self.assertFalse(resposta["ok"], resposta)
        self.assertEqual(resposta["erro"], tipo, resposta)

    def assertOk(self, resposta):
        self.assertTrue(resposta["ok"], resposta)
        return resposta["resultado"]

    def assertRecusaInicio(self, cen, trecho, **opcoes):
        codigo, erro = cen.tentar_iniciar(**opcoes)
        self.assertEqual(codigo, 3, f"o guardião NÃO deveria iniciar; stderr={erro!r}")
        self.assertIn("RECUSADO", erro)
        self.assertIn(trecho, erro)

    # ================= inicialização: cadastro, referência externa e série =================
    def test_inicia_com_cadastro_serie_e_referencia_coerentes(self):
        cen = self.cenario(serie=1)
        codigo, erro = cen.tentar_iniciar()
        self.assertIsNone(codigo, erro)
        self.assertNotIn("AVISO", erro)
        self.assertEqual(json.loads(cen.estado.read_text())["serie"], 1)
        self.assertEqual(cen.estado.stat().st_uid, UID_GUARDIAO)

    def test_recusa_sem_referencia_externa(self):
        cen = self.cenario(serie=1)
        cen.referencia.unlink()
        self.assertRecusaInicio(cen, "referencia-serie.json")

    def test_recusa_referencia_externa_adulterada_ou_de_outra_raiz(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        cen = self.cenario(serie=3)
        documento = json.loads(cen.referencia.read_bytes())
        documento["payload"]["serie_minima"] = 1
        cen.referencia.write_text(json.dumps(documento))
        self.assertRecusaInicio(cen, "sem assinatura válida da raiz")
        cen.publicar_referencia(3, documento["payload"]["sha256_cadastro"], chave=Ed25519PrivateKey.generate())
        self.assertRecusaInicio(cen, "sem assinatura válida da raiz")

    def test_recusa_referencia_sob_controle_do_proprio_guardiao(self):
        cen = self.cenario(serie=1)
        os.chown(cen.referencia, UID_GUARDIAO, UID_GUARDIAO)
        self.assertRecusaInicio(cen, "deve pertencer a root")
        os.chown(cen.referencia, 0, 0)
        dentro = cen.registros / "referencia-serie.json"
        shutil.copy(cen.referencia, dentro)
        os.chown(dentro, 0, 0)
        configuracao = cen.escrever_config("dentro.json", referencia_serie=str(dentro))
        self.assertRecusaInicio(cen, "não pode ficar dentro do armazenamento", config=configuracao)

    def test_recusa_referencia_gravavel_por_terceiros(self):
        cen = self.cenario(serie=1)
        os.chmod(cen.referencia, 0o666)
        self.assertRecusaInicio(cen, "protegido")

    def test_recusa_cadastro_antigo_reapresentado_antes_de_iniciar(self):
        cen = self.cenario(serie=3)
        cen.publicar_cadastro(2, com_referencia=False)                  # rollback: a referência diz 3
        self.assertRecusaInicio(cen, "abaixo do piso")

    def test_recusa_serie_duplicada_com_conteudo_diferente(self):
        cen = self.cenario(serie=3)
        cen.publicar_cadastro(3, ("ana.aprovadora", "bruno.aprovador"), com_referencia=False)
        self.assertRecusaInicio(cen, "conteúdo diferente")

    def test_recusa_cadastro_sem_serie(self):
        cen = self.cenario(serie=1)
        cen.publicar_cadastro(None, com_referencia=False)
        self.assertRecusaInicio(cen, "série")

    def test_recusa_cadastro_com_assinatura_de_outra_raiz(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        cen = self.cenario(serie=1)
        cen.publicar_cadastro(5, com_referencia=False, chave=Ed25519PrivateKey.generate())
        self.assertRecusaInicio(cen, "assinatura válida")

    # ================= ambiente Python =================
    def test_recusa_sem_modo_isolado_ou_sem_pycache_prefix(self):
        cen = self.cenario(serie=1)
        self.assertRecusaInicio(cen, "modo isolado", isolado=False)
        self.assertRecusaInicio(cen, "pycache_prefix", prefixo=None)

    def test_recusa_dependencia_ausente_ou_incompativel(self):
        cen = self.cenario(serie=1)
        original = (RAIZ / "requirements.lock").read_text()
        h = "sha256:" + "ab" * 32
        ausente = original + f"\npacote-inexistente-ppp==1.0 \\\n    --hash={h}\n"
        self.assertRecusaInicio(cen, "dependência ausente", codigo=self.mundo.codigo_com_lock(ausente))
        incompativel = original.replace("jsonschema==4.26.0", "jsonschema==0.0.1", 1)
        self.assertNotEqual(incompativel, original)
        self.assertRecusaInicio(cen, "incompatível", codigo=self.mundo.codigo_com_lock(incompativel))

    def test_recusa_lock_malformado(self):
        cen = self.cenario(serie=1)
        self.assertRecusaInicio(cen, "lock não reconhecida", codigo=self.mundo.codigo_com_lock("isto nao e um lock\n"))

    # ================= perfil legado x estrito =================
    def test_estrito_recusa_formato_1_e_legado_inicia_com_aviso_explicito(self):
        cen = self.cenario(serie=None, formato=1)
        self.assertRecusaInicio(cen, "--estrito exige", estrito=True, prefixo=None)
        codigo, erro = cen.tentar_iniciar(prefixo=None)
        self.assertIsNone(codigo, erro)
        self.assertIn("AVISO: perfil legado", erro)

    def test_formato_1_nao_aceita_chaves_do_formato_2(self):
        cen = self.cenario(serie=None, formato=1)
        for chaves in ({"referencia_serie": str(cen.referencia)}, {"limites": {"rajada": 5}}):
            with self.subTest(chaves=chaves):
                configuracao = cen.escrever_config("misto.json", **chaves)
                self.assertRecusaInicio(cen, "Configuração inválida", config=configuracao, prefixo=None)

    def test_formato_2_exige_referencia(self):
        cen = self.cenario(serie=1)
        configuracao = cen.escrever_config("sem-ref.json", referencia_serie=None)
        self.assertRecusaInicio(cen, "Configuração inválida", config=configuracao)

    # ================= rollback do cadastro com o guardião em execução =================
    def test_replay_de_cadastro_antigo_em_execucao_bloqueia_aprovacoes_e_checkpoints(self):
        cen = self.cenario(serie=1, nomes=("ana.aprovadora", "carla.revogada"),
                           limites={"intervalo_minimo_checkpoint_s": 0})
        antigo, antiga_sig = cen.cadastro.read_bytes(), Path(f"{cen.cadastro}.sig").read_text()
        with cen.servir():
            self.assertOk(cen.chamar(UID_AGENTE, propor()))
            self.assertOk(cen.chamar(UID_AGENTE, registrar(cen.aprovar("PREM-001", 1, "carla.revogada"))))
            self.assertEqual(self.assertOk(cen.chamar(UID_AGENTE, estado())), "APROVADA")
            revogado = cen.publicar_cadastro(2, ("ana.aprovadora", "carla.revogada"),
                                             inativos=("carla.revogada",))
            self.assertErro(cen.chamar(UID_AGENTE, estado()), "AprovacaoInvalida")
            cen.cadastro.write_bytes(antigo)                                   # replay (root do host)
            Path(f"{cen.cadastro}.sig").write_text(antiga_sig)
            for pedido, uid in ((estado(), UID_AGENTE), ({"op": "ler_aprovada", "id": "PREM-001"}, UID_AGENTE),
                                (CHECKPOINT, UID_ANCORA)):
                self.assertErro(cen.chamar(uid, pedido), "RetrocessoDeSerie")
            self.assertEqual(json.loads(cen.estado.read_text())["serie"], 2, "a marca d'água não recua")
            cen.cadastro.write_bytes(revogado)                                  # restabelecido
            Path(f"{cen.cadastro}.sig").write_text(
                __import__("base64").b64encode(self.mundo.raiz.sign(revogado)).decode())
            self.assertErro(cen.chamar(UID_AGENTE, estado()), "AprovacaoInvalida")  # volta ao normal
            self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))

    def test_referencia_removida_ou_adulterada_em_execucao_bloqueia(self):
        cen = self.cenario(serie=2)
        with cen.servir():
            self.assertOk(cen.chamar(UID_AGENTE, propor()))
            self.assertOk(cen.chamar(UID_AGENTE, registrar(cen.aprovar("PREM-001", 1))))
            original = cen.referencia.read_bytes()
            cen.referencia.unlink()
            self.assertErro(cen.chamar(UID_AGENTE, estado()), "ReferenciaIndisponivel")
            documento = json.loads(original)
            documento["payload"]["serie_minima"] = 1
            cen.referencia.write_text(json.dumps(documento))
            self.assertErro(cen.chamar(UID_AGENTE, estado()), "ReferenciaIndisponivel")
            cen.referencia.write_bytes(original)
            self.assertEqual(self.assertOk(cen.chamar(UID_AGENTE, estado())), "APROVADA")

    def test_agente_nao_altera_referencia_marca_dagua_cadastro_nem_lock(self):
        cen = self.cenario(serie=1)
        alvos = {"referencia": cen.referencia, "cadastro": cen.cadastro,
                 "lock": self.mundo.codigo / "requirements.lock",
                 "verificador": self.mundo.codigo / "scripts" / "serie.py"}
        with cen.servir():
            self.assertOk(cen.chamar(UID_AGENTE, propor()))
            marca = cen.estado
            codigo = "import json, os\nr = {}\n" + "\n".join(
                f"try:\n    open({str(caminho)!r}, 'a').write(' ')\n    r[{nome!r}] = 'PERMITIDO'\n"
                f"except Exception as e:\n    r[{nome!r}] = 'NEGADO:' + type(e).__name__"
                for nome, caminho in {**alvos, "marca": marca}.items()) + (
                "\ntry:\n    os.unlink(%r)\n    r['remover_marca'] = 'PERMITIDO'\n"
                "except Exception as e:\n    r['remover_marca'] = 'NEGADO:' + type(e).__name__\nprint(json.dumps(r))"
                % str(marca))
            resultado = json.loads(cen.executar_como(UID_AGENTE, codigo))
            self.assertTrue(all(v.startswith("NEGADO") for v in resultado.values()), resultado)

    def test_serie_nova_e_aceita_em_execucao_e_a_marca_dagua_avanca(self):
        cen = self.cenario(serie=1)
        with cen.servir():
            self.assertOk(cen.chamar(UID_AGENTE, propor()))
            self.assertOk(cen.chamar(UID_AGENTE, registrar(cen.aprovar("PREM-001", 1))))
            cen.publicar_cadastro(2, ("ana.aprovadora", "bruno.aprovador"))
            self.assertEqual(self.assertOk(cen.chamar(UID_AGENTE, estado())), "APROVADA")
            self.assertEqual(json.loads(cen.estado.read_text())["serie"], 2)

    # ================= requisição acima do limite =================
    def test_requisicao_acima_do_limite_e_recusada_e_o_guardiao_segue_operando(self):
        cen = self.cenario(serie=1, limites={"max_requisicao_bytes": 4096})
        with cen.servir():
            grande = propor(descricao="x" * 8000)
            resposta = cen.chamar(UID_AGENTE, grande)
            self.assertFalse(resposta["ok"])
            self.assertEqual(resposta["erro"], "LimiteExcedido", resposta)
            self.assertFalse((cen.registros / "premissas" / "PREM-001").exists())
            enorme = cen.executar_como(UID_AGENTE, (
                "import socket, json\ns = socket.socket(socket.AF_UNIX)\ns.settimeout(10)\n"
                f"s.connect({cen.socket!r})\ntry:\n    s.sendall(b'x' * 8_000_000)\n"
                "except OSError as e:\n    pass\ntry:\n    d = s.recv(4096)\nexcept OSError:\n    d = b''\n"
                "print(json.dumps({'resposta': d.decode(errors='replace')[:200]}))"))
            self.assertNotIn('"ok":true', enorme)
            self.assertOk(cen.chamar(UID_AGENTE, propor()))                      # segue operando

    # ================= excesso de operações por identidade =================
    def test_excesso_de_operacoes_por_identidade_nao_afeta_outras_identidades(self):
        cen = self.cenario(serie=1, limites={"rajada": 5, "operacoes_por_minuto": 1})
        with cen.servir():
            respostas = cen.chamar(UID_AGENTE, *[estado() for _ in range(9)])
            tipos = [r.get("erro") for r in respostas]
            self.assertEqual(tipos[:5], ["PremissaInvalida"] * 5, tipos)          # dentro da rajada
            self.assertEqual(tipos[5:], ["LimiteExcedido"] * 4, tipos)            # acima: recusado
            self.assertIn("agente", json.dumps(respostas[-1]) + "agente")
            self.assertOk(cen.chamar(UID_OUTRO, propor(pid="PREM-002")))          # outro proponente livre
            self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))                     # e o ancorador também
            self.assertErro(cen.chamar(UID_AGENTE, propor(pid="PREM-003")), "LimiteExcedido")
            self.assertFalse((cen.registros / "premissas" / "PREM-003").exists())

    def test_uid_sem_papel_e_recusado_sem_ler_a_requisicao(self):
        cen = self.cenario(serie=1)
        with cen.servir():
            resposta = cen.chamar(UID_HUMANO, propor())
            self.assertErro(resposta, "PermissionError")
            self.assertIn("não autorizado", resposta["mensagem"])
            inicio = time.monotonic()
            lento = cen.executar_como(UID_HUMANO, (
                "import socket, json, time\ns = socket.socket(socket.AF_UNIX)\ns.settimeout(10)\n"
                f"s.connect({cen.socket!r})\nt = time.monotonic()\nd = s.recv(4096)\n"
                "print(json.dumps({'espera': time.monotonic() - t, 'resp': d.decode()[:120]}))"))
            self.assertLess(json.loads(lento)["espera"], 1.0, "sem papel: resposta imediata, sem esperar a leitura")
            self.assertLess(time.monotonic() - inicio, 5)

    # ================= clientes lentos e conexões simultâneas =================
    def segurar_conexoes(self, cen, uid, quantidade, segundos):
        """Subprocesso que abre `quantidade` conexões e as mantém paradas por `segundos`."""
        codigo = (
            "import socket, sys, time\nconexoes = []\nfor _ in range(%d):\n"
            "    s = socket.socket(socket.AF_UNIX)\n    s.connect(%r)\n    conexoes.append(s)\n"
            "print('prontas', flush=True)\ntime.sleep(%f)\nfor s in conexoes:\n    s.close()\n"
            % (quantidade, cen.socket, segundos))
        processo = subprocess.Popen([sys.executable, "-I", "-B", "-c", codigo], preexec_fn=__import__(
            "apoio_guardiao").como(uid), stdout=subprocess.PIPE, text=True, cwd="/", env={"PATH": "/usr/bin:/bin"})
        self.mundo.processos.append(processo)
        self.assertEqual(processo.stdout.readline().strip(), "prontas")
        return processo

    def test_cliente_lento_nao_bloqueia_outras_identidades(self):
        cen = self.cenario(serie=1, limites={"prazo_leitura_s": 2, "max_conexoes_por_identidade": 2})
        with cen.servir():
            self.segurar_conexoes(cen, UID_AGENTE, 2, 6)
            inicio = time.monotonic()
            self.assertOk(cen.chamar(UID_OUTRO, propor(pid="PREM-002")))
            self.assertLess(time.monotonic() - inicio, 1.5, "o guardião deve atender outros durante a espera")

    def test_limite_de_conexoes_por_identidade_e_global(self):
        cen = self.cenario(serie=1, limites={"prazo_leitura_s": 4, "max_conexoes_por_identidade": 2,
                                             "max_conexoes": 3, "rajada": 100})
        with cen.servir():
            self.segurar_conexoes(cen, UID_AGENTE, 2, 5)
            self.assertErro(cen.chamar(UID_AGENTE, propor()), "ServidorOcupado")      # teto da identidade
            self.assertOk(cen.chamar(UID_OUTRO, propor(pid="PREM-002")))              # outra identidade passa
            self.segurar_conexoes(cen, UID_OUTRO, 1, 5)
            self.assertErro(cen.chamar(UID_ANCORA, CHECKPOINT), "ServidorOcupado")    # teto global (3)

    def test_cliente_parado_recebe_erro_de_prazo_e_nada_e_gravado(self):
        cen = self.cenario(serie=1, limites={"prazo_leitura_s": 1})
        with cen.servir():
            saida = cen.executar_como(UID_AGENTE, (
                "import socket, json, time\ns = socket.socket(socket.AF_UNIX)\ns.settimeout(10)\n"
                f"s.connect({cen.socket!r})\ns.sendall(b'{{\"op\": \"propor\", ')\nt = time.monotonic()\n"
                "d = s.recv(4096)\nprint(json.dumps({'espera': time.monotonic() - t, 'resp': d.decode()}))"))
            dados = json.loads(saida)
            self.assertIn("TimeoutError", dados["resp"])
            self.assertGreaterEqual(dados["espera"], 0.9)
            self.assertLess(dados["espera"], 3)
            self.assertFalse((cen.registros / "premissas").exists() and any((cen.registros / "premissas").iterdir()))

    # ================= crescimento dos registros =================
    def test_limites_de_crescimento_no_guardiao(self):
        cen = self.cenario(serie=1, limites={"max_versoes_por_premissa": 3, "max_bytes_por_versao": 2048,
                                             "max_premissas": 2, "rajada": 100})
        with cen.servir():
            for versao in (1, 2, 3):
                self.assertOk(cen.chamar(UID_AGENTE, propor(versao=versao, valor=float(versao))))
            self.assertErro(cen.chamar(UID_AGENTE, propor(versao=4)), "LimiteExcedido")        # versões
            self.assertErro(cen.chamar(UID_AGENTE, propor(pid="PREM-002", descricao="y" * 4000)),
                            "LimiteExcedido")                                                  # bytes
            self.assertOk(cen.chamar(UID_AGENTE, propor(pid="PREM-002")))
            self.assertErro(cen.chamar(UID_AGENTE, propor(pid="PREM-003")), "LimiteExcedido")  # premissas
            self.assertEqual(len(list((cen.registros / "premissas").iterdir())), 2)

    def test_limites_de_checkpoint_intervalo_e_quantidade(self):
        cen = self.cenario(serie=1, limites={"intervalo_minimo_checkpoint_s": 3600})
        with cen.servir():
            self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
            self.assertErro(cen.chamar(UID_ANCORA, CHECKPOINT), "LimiteExcedido")
        cen = self.cenario(serie=1, limites={"intervalo_minimo_checkpoint_s": 0, "max_checkpoints": 2,
                                             "rajada": 100})
        with cen.servir():
            self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
            self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
            self.assertErro(cen.chamar(UID_ANCORA, CHECKPOINT), "LimiteExcedido")
            self.assertEqual(len(list(cen.ancora.glob("seq-*.json"))), 2)
        cen = self.cenario(serie=1, limites={"intervalo_minimo_checkpoint_s": 0, "max_bytes_checkpoints": 1024,
                                             "rajada": 100})
        with cen.servir():
            emitidos = 0
            for _ in range(10):
                resposta = cen.chamar(UID_ANCORA, CHECKPOINT)
                if not resposta["ok"]:
                    break
                emitidos += 1
            self.assertErro(resposta, "LimiteExcedido")
            ocupado = sum(a.stat().st_size for a in cen.ancora.glob("seq-*.json"))
            self.assertGreaterEqual(ocupado, 1024, "só recusa ao atingir o teto")
            self.assertGreater(emitidos, 1, "antes do teto os checkpoints são aceitos")
            anterior = ocupado - cen.ancora.joinpath(f"seq-{emitidos}.json").stat().st_size
            self.assertLess(anterior, 1024, "o último aceito ainda estava abaixo do teto")
            self.assertEqual(len(list(cen.ancora.glob("seq-*.json"))), emitidos)

    # ================= checkpoints do guardião x ferramenta independente =================
    def verificar_externo(self, cen, externo, *extras, chave=None):
        return subprocess.run(
            [sys.executable, "-I", "-B", str(RAIZ / "scripts" / "verificar_ancora.py"),
             "--chave-guardiao", chave or cen.publica_guardiao, "--checkpoints", str(externo), *extras],
            capture_output=True, text=True, timeout=60)

    def copiar_para_externo(self, cen, destino):
        destino.mkdir(exist_ok=True)
        for arquivo in cen.ancora.glob("seq-*.json"):
            shutil.copy(arquivo, destino / arquivo.name)
        return destino

    def test_checkpoints_atestam_o_cadastro_e_passam_na_ferramenta_independente(self):
        cen = self.cenario(serie=1, limites={"intervalo_minimo_checkpoint_s": 0, "rajada": 100})
        with cen.servir():
            self.assertOk(cen.chamar(UID_AGENTE, propor()))
            primeiro = self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
            self.assertOk(cen.chamar(UID_AGENTE, registrar(cen.aprovar("PREM-001", 1))))
            cen.publicar_cadastro(2, ("ana.aprovadora", "bruno.aprovador"))
            self.assertOk(cen.chamar(UID_AGENTE, propor(versao=2, valor=44.0)))
            segundo = self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
        self.assertEqual(primeiro["payload"]["cadastro"]["serie"], 1)
        self.assertEqual(segundo["payload"]["cadastro"]["serie"], 2)
        externo = self.copiar_para_externo(cen, cen.dir / "externo-copia")
        ok = self.verificar_externo(cen, externo, "--registros", str(cen.registros), "--serie-minima", "2")
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        # rollback no host do guardião (versão e aprovação apagadas): só a âncora externa denuncia
        pasta = cen.registros / "premissas" / "PREM-001"
        (pasta / "v2.json").unlink()
        (pasta / "v1.aprovacao.json").unlink()
        falha = self.verificar_externo(cen, externo, "--registros", str(cen.registros))
        self.assertEqual(falha.returncode, 1, falha.stdout)
        self.assertIn("versão ancorada removida", falha.stdout)
        self.assertIn("aprovação ancorada removida", falha.stdout)
        errada = self.verificar_externo(cen, externo, chave="0" * 64)
        self.assertEqual(errada.returncode, 1)
        self.assertIn("assinatura inválida", errada.stdout)

    def test_reset_total_da_cadeia_local_so_e_detectado_pela_copia_externa(self):
        """Limite documentado: apagar TODA a cadeia local reinicia o seq em 1, sem rastro local."""
        cen = self.cenario(serie=1, limites={"intervalo_minimo_checkpoint_s": 0, "rajada": 100})
        with cen.servir():
            self.assertOk(cen.chamar(UID_AGENTE, propor()))
            self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
            self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
        externo = self.copiar_para_externo(cen, cen.dir / "externo-copia")
        shutil.rmtree(cen.ancora)                                             # root apaga a cadeia local
        codigo, erro = cen.tentar_iniciar()
        self.assertIsNone(codigo, "localmente nada denuncia o reset: " + erro)
        with cen.servir():
            self.assertEqual(self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))["payload"]["seq"], 1)
        novo = cen.ancora / "seq-1.json"
        shutil.copy(novo, externo / "seq-1-recriado.json")
        falha = self.verificar_externo(cen, externo)
        self.assertEqual(falha.returncode, 1, falha.stdout)
        self.assertIn("duplicado com conteúdo diferente", falha.stdout)

    # ================= interrupção durante gravação e recuperação =================
    def test_reinicio_recupera_temporarios_e_conclui_checkpoint_gravado_pela_metade(self):
        cen = self.cenario(serie=1, limites={"intervalo_minimo_checkpoint_s": 0, "rajada": 100})
        with cen.servir():
            self.assertOk(cen.chamar(UID_AGENTE, propor()))
            for _ in range(3):
                self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
        # queda entre gravar seq-3.json e atualizar ultimo.json, mais restos de gravações interrompidas
        seq2 = json.loads((cen.ancora / "seq-2.json").read_bytes())
        (cen.ancora / "ultimo.json").write_text(json.dumps(seq2, sort_keys=True, separators=(",", ":")))
        restos = [cen.ancora / ".ultimo.json.deadbeef.tmp", cen.estado.parent / ".serie-cadastro.json.beef.tmp",
                  cen.registros / "premissas" / "PREM-001" / ".v2.json.cafe.tmp"]
        for resto in restos:
            resto.write_bytes(b'{"parcial"')
            os.chown(resto, UID_GUARDIAO, UID_GUARDIAO)
        vazia = cen.registros / "premissas" / "PREM-777"                      # queda entre mkdir e a publicação
        vazia.mkdir()
        os.chown(vazia, UID_GUARDIAO, UID_GUARDIAO)
        codigo, erro = cen.tentar_iniciar()
        self.assertIsNone(codigo, erro)
        self.assertIn("ultimo.json atualizado para seq 3", erro)
        self.assertEqual(erro.count("removido temporário"), 3, erro)
        self.assertIn("removida pasta vazia", erro)
        self.assertFalse(any(r.exists() for r in restos) or vazia.exists())
        self.assertTrue((cen.registros / "premissas" / "PREM-001").is_dir(), "pasta com conteúdo é preservada")
        with cen.servir():
            seguinte = self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
        self.assertEqual(seguinte["payload"]["seq"], 4, "a ancoragem não pode ficar travada após a queda")
        externo = self.copiar_para_externo(cen, cen.dir / "externo-copia")
        self.assertEqual(self.verificar_externo(cen, externo, "--registros", str(cen.registros)).returncode, 0)

    def test_reinicio_recusa_cadeia_local_de_checkpoints_adulterada_ou_com_lacuna(self):
        cen = self.cenario(serie=1, limites={"intervalo_minimo_checkpoint_s": 0, "rajada": 100})
        with cen.servir():
            self.assertOk(cen.chamar(UID_AGENTE, propor()))
            for _ in range(3):
                self.assertOk(cen.chamar(UID_ANCORA, CHECKPOINT))
        copia = cen.dir / "backup-ancora"
        shutil.copytree(cen.ancora, copia)

        def restaurar():
            shutil.rmtree(cen.ancora)
            shutil.copytree(copia, cen.ancora)
            for item in [cen.ancora, *cen.ancora.rglob("*")]:
                os.chown(item, UID_GUARDIAO, UID_GUARDIAO)

        (cen.ancora / "seq-2.json").unlink()
        self.assertRecusaInicio(cen, "lacuna")
        restaurar()
        adulterado = json.loads((cen.ancora / "seq-1.json").read_bytes())
        adulterado["payload"]["estado"] = {"PREM-009": {"versoes": [], "aprovacoes": {}}}
        (cen.ancora / "seq-1.json").write_text(json.dumps(adulterado, sort_keys=True, separators=(",", ":")))
        self.assertRecusaInicio(cen, "inválido ou adulterado")
        restaurar()
        (cen.ancora / "ultimo.json").write_text("{corrompido")
        self.assertRecusaInicio(cen, "ultimo.json ilegível")
        restaurar()
        (cen.ancora / "seq-3.json").unlink()                                   # ultimo.json aponta seq 3
        self.assertRecusaInicio(cen, "ultimo.json aponta seq 3")
        restaurar()
        (cen.ancora / "ultimo.json").unlink()                                  # perda benigna: readotado
        codigo, erro = cen.tentar_iniciar()
        self.assertIsNone(codigo, erro)
        self.assertIn("ultimo.json atualizado para seq 3", erro)

    def test_queda_forcada_durante_gravacoes_preserva_a_integridade(self):
        cen = self.cenario(serie=1, limites={"rajada": 5000, "operacoes_por_minuto": 100000})
        with cen.servir() as processo:
            escritor = subprocess.Popen(
                [sys.executable, "-I", "-B", "-c", (
                    "import sys, json\nsys.path.insert(0, %r)\nimport cliente_guardiao as c\n"
                    "for n in range(1, 400):\n    p = dict(id='PREM-%%03d' %% n, versao=1, produto='P3', "
                    "natureza='OBSERVADO', unidade='u', status='PROPOSTA', fonte_id='FONTE-001', valor=float(n))\n"
                    "    try:\n        c.propor(p, caminho_socket=%r, timeout=2)\n    except Exception:\n        break\n"
                    % (str(self.mundo.codigo / "scripts"), cen.socket))],
                preexec_fn=__import__("apoio_guardiao").como(UID_AGENTE), cwd="/",
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"})
            self.mundo.processos.append(escritor)
            time.sleep(0.6)
            processo.kill()                                                     # SIGKILL no meio das gravações
            escritor.wait(timeout=30)
        repo = cen.repositorio_de_root()
        gravadas = sorted(p.name for p in (cen.registros / "premissas").iterdir())
        self.assertTrue(gravadas, "o escritor deveria ter gravado algo antes da queda")
        for premissa_id in gravadas:                                              # nada parcial nem corrompido
            self.assertIn(len(repo.historico(premissa_id)), (0, 1), premissa_id)  # 0 = pasta vazia da queda
        codigo, erro = cen.tentar_iniciar()
        self.assertIsNone(codigo, erro)
        self.assertFalse(list((cen.registros / "premissas").rglob(".*.tmp")), "temporários devem ser removidos")
        restantes = sorted(p.name for p in (cen.registros / "premissas").iterdir())
        self.assertFalse(any(not any((cen.registros / "premissas" / n).iterdir()) for n in restantes),
                         "pastas vazias da queda devem ser removidas")
        for premissa_id in restantes:
            self.assertEqual(len(repo.historico(premissa_id)), 1, premissa_id)
        with cen.servir():
            self.assertOk(cen.chamar(UID_AGENTE, propor(pid="PREM-900")))


if __name__ == "__main__":
    unittest.main()
