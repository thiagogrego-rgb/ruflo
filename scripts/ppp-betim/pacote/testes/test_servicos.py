"""GOV-08: serviço de log encadeado, gateway de rede e proteção da credencial.

Tudo com dados sintéticos e processos reais rebaixados para as contas sintéticas (setpriv). Sem root/Linux os testes são
PULADOS (NÃO EXECUTADO). O destino da API é um servidor local falso: nenhuma credencial real é usada.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

from apoio_servicos import (CHAVE_DO_AGENTE, CHAVE_REAL, PULAR, ROOT, Ambiente, I, prefixo_de, rodar_como)

sys.path.insert(0, str(ROOT / "scripts"))
import gateway as GW  # noqa: E402
import logd  # noqa: E402
import entrada_jaula  # noqa: E402,F401

HOOK = "guarda_ferramentas.py"


def chama_hook(ambiente, papel, evento, obrigatorio=True, com_servico=True):
    """Executa o hook real do projeto COMO a conta do papel, com o ambiente que o lançador entrega."""
    env = {"PATH": "/usr/bin:/bin", "PPP_PAPEL": papel}
    if com_servico:
        env["PPP_LOGD_SOCKET"] = str(ambiente.logd_socket)
    if obrigatorio:
        env["PPP_LOGD_OBRIGATORIO"] = "1"
    return rodar_como(papel, ambiente.spec, "import subprocess,sys\nr=subprocess.run([sys.executable,'-B',sys.argv[1]],input=sys.stdin.read(),"
                      "text=True,capture_output=True)\nsys.stdout.write(r.stdout);sys.stderr.write(r.stderr);sys.exit(r.returncode)",
                      env=env, entrada=json.dumps(evento), args=(str(ambiente.raiz / ".claude/hooks" / HOOK),))


def leitura(ambiente, caminho):
    return {"tool_name": "Read", "tool_input": {"file_path": str(ambiente.raiz / caminho)}, "cwd": str(ambiente.raiz)}


@PULAR
class TestLogEncadeado(Ambiente):
    def setUp(self):
        super().setUp()
        if any("chattr" in a for a in self.avisos):
            self.skipTest("filesystem sem chattr +a")
        self.sobe_logd()

    def verifica(self, nome):
        return logd.verificar(self.raiz / "logs" / nome)

    def test_hook_grava_pelo_servico_e_a_origem_vem_do_kernel(self):
        r = chama_hook(self, "p3", leitura(self, "produtos/P3/x.md"))
        self.assertEqual(r.returncode, 0, r.stderr)
        linhas = [json.loads(x) for x in self.le_log("guarda-p3.jsonl").splitlines()]
        self.assertEqual(len(linhas), 1)
        self.assertEqual(linhas[0]["origem"], "p3")
        self.assertEqual(linhas[0]["dados"]["decisao"], "permitido")
        self.assertEqual(linhas[0]["seq"], 1)
        self.assertEqual(self.verifica("guarda-p3.jsonl"), [])
        self.assertEqual(self.le_log("guarda-revisor.jsonl"), "")

    def test_agente_nao_consegue_gravar_em_nome_de_outro_papel(self):
        forjado = ("import socket,json\ns=socket.socket(socket.AF_UNIX); s.connect(%r)\n"
                   "s.sendall((json.dumps({'origem':'revisor','papel':'revisor','dados':{'decisao':'permitido','agente':'revisor'}})+'\\n').encode())\n"
                   "print(s.makefile().readline().strip())\n" % str(self.logd_socket))
        r = rodar_como("p3", self.spec, forjado)
        self.assertEqual(r.stdout.strip(), "ok")
        self.assertIn('"origem":"p3"', self.le_log("guarda-p3.jsonl"))            # gravou no log do PRÓPRIO papel
        self.assertEqual(self.le_log("guarda-revisor.jsonl"), "")                  # nunca no de outro

    def test_cadeia_cresce_e_verifica_para_varios_papeis_e_sobrevive_a_reinicio(self):
        for papel in ("p1", "p3", "coordenador", "revisor"):
            for i in range(3):
                self.assertEqual(chama_hook(self, papel, leitura(self, f"produtos/P1/a{i}.md")).returncode, 0)
        for papel in ("p1", "p3", "coordenador", "revisor"):
            self.assertEqual(self.verifica(f"guarda-{papel}.jsonl"), [], papel)
            self.assertEqual([json.loads(x)["seq"] for x in self.le_log(f"guarda-{papel}.jsonl").splitlines()], [1, 2, 3])
        self.derruba("logd")
        self.sobe_logd()
        chama_hook(self, "p1", leitura(self, "produtos/P1/depois.md"))
        self.assertEqual(self.verifica("guarda-p1.jsonl"), [])
        self.assertEqual(len(self.le_log("guarda-p1.jsonl").splitlines()), 4)

    def test_adulteracao_remocao_e_reordenacao_sao_detectadas(self):
        for i in range(4):
            chama_hook(self, "p2", leitura(self, f"produtos/P2/a{i}.md"))
        arq = self.raiz / "logs/guarda-p2.jsonl"
        original = arq.read_text(encoding="utf-8")
        I._chattr("-a", arq)
        linhas = original.splitlines()
        casos = {
            "conteúdo alterado": [linhas[0], linhas[1].replace("permitido", "recusado"), *linhas[2:]],
            "linha removida": [linhas[0], *linhas[2:]],
            "linhas trocadas": [linhas[0], linhas[2], linhas[1], linhas[3]],
            "linha inserida": [*linhas, linhas[1]],
        }
        for nome, novas in casos.items():
            arq.write_text("\n".join(novas) + "\n", encoding="utf-8")
            self.assertTrue(logd.verificar(arq), nome)
        arq.write_text(original, encoding="utf-8")
        self.assertEqual(logd.verificar(arq), [])
        I._chattr("+a", arq)

    def test_servico_nao_inicia_com_cadeia_corrompida(self):
        chama_hook(self, "p4", leitura(self, "produtos/P4/a.md"))
        chama_hook(self, "p4", leitura(self, "produtos/P4/b.md"))
        self.derruba("logd")
        arq = self.raiz / "logs/guarda-p4.jsonl"
        I._chattr("-a", arq)
        arq.write_text(arq.read_text().replace("permitido", "recusado", 1), encoding="utf-8")
        I._chattr("+a", arq)
        uid = self.spec["contas"]["ppp-guardiao"]
        r = subprocess.run([*prefixo_de(uid, uid, [uid, self.spec["grupos"]["ppp-leitura"]]), sys.executable, "-I", "-B",
                            str(self.svc / "scripts/logd.py"), "--raiz", str(self.raiz), "--spec", str(self.svc / "governanca/papeis.json"),
                            "--socket", str(self.logd_socket)], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("corrompida", r.stderr + r.stdout)

    def test_log_indisponivel_recusa_a_operacao_quando_obrigatorio(self):
        self.assertEqual(chama_hook(self, "p3", leitura(self, "produtos/P3/x.md")).returncode, 0)        # controle positivo
        self.derruba("logd")
        r = chama_hook(self, "p3", leitura(self, "produtos/P3/x.md"))
        self.assertEqual(r.returncode, 2, "sem trilha confirmada a operação não pode seguir")
        self.assertIn("log indisponível", r.stderr)
        # modo legado (sem o lançador): sem log obrigatório a decisão não muda por causa do log
        r = chama_hook(self, "p3", leitura(self, "produtos/P3/x.md"), obrigatorio=False, com_servico=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        # e a recusa por política continua recusando
        negado = {"tool_name": "Write", "tool_input": {"file_path": str(self.raiz / "registros/x.json")}, "cwd": str(self.raiz)}
        self.assertEqual(chama_hook(self, "p3", negado).returncode, 2)

    def test_uid_desconhecido_e_mensagem_grande_demais_sao_negados(self):
        antes = {n: self.le_log(n) for n in I.nomes_de_log(self.spec)}
        cliente = ("import sys; sys.path.insert(0, %r)\nimport logd\nprint(logd.enviar(%r, {'x': 'y' * %d}))\n")
        r = subprocess.run([*prefixo_de(65000, 65000, []), sys.executable, "-B", "-c", cliente % (str(self.svc / "scripts"), str(self.logd_socket), 10)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "False")                                  # sem permissão no socket (DAC do próprio socket)
        r = subprocess.run([*prefixo_de(65000, 65000, [65000, self.spec["grupos"]["ppp-leitura"]]), sys.executable, "-B", "-c",
                            cliente % (str(self.svc / "scripts"), str(self.logd_socket), 10)], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "False")                                  # no grupo, mas o uid não tem papel: negado pelo serviço
        r = rodar_como("p3", self.spec, cliente % (str(self.svc / "scripts"), str(self.logd_socket), 40000))
        self.assertEqual(r.stdout.strip(), "False")                                  # acima do limite: nada é gravado
        self.assertEqual(antes, {n: self.le_log(n) for n in I.nomes_de_log(self.spec)})

    def test_papeis_nao_escrevem_no_log_nem_com_o_servico_parado(self):
        self.derruba("logd")
        for papel in self.spec["papeis"]:
            r = rodar_como(papel, self.spec, f"import os\nfor n in os.listdir('{self.raiz}/logs') if os.access('{self.raiz}/logs', os.R_OK) else []: pass\n"
                           f"try:\n os.open('{self.raiz}/logs/guarda-{papel}.jsonl', os.O_WRONLY|os.O_APPEND); print('ESCREVEU')\n"
                           "except OSError: print('NEGADO')\n")
            self.assertEqual(r.stdout.strip(), "NEGADO", papel)


@PULAR
class TestGateway(Ambiente):
    def setUp(self):
        super().setUp()
        if any("chattr" in a for a in self.avisos):
            self.skipTest("filesystem sem chattr +a")
        self.sobe_logd()
        self.sobe_gateway()

    def test_injeta_a_credencial_e_descarta_a_do_cliente(self):
        status, corpo = self.requisicao_como("p3", cabecalhos={"x-api-key": CHAVE_DO_AGENTE, "Authorization": "Bearer " + CHAVE_DO_AGENTE,
                                                                "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
                                             corpo=b'{"mensagem":"MARCADOR-DO-CORPO"}')
        self.assertEqual(status, 200)
        self.assertIn('"ok": true', corpo)
        self.assertEqual(len(self.destino.recebidos), 1)
        rec = self.destino.recebidos[0]
        self.assertEqual(rec["cabecalhos"]["x-api-key"], CHAVE_REAL)
        self.assertNotIn("authorization", rec["cabecalhos"])
        self.assertEqual(rec["cabecalhos"]["anthropic-version"], "2023-06-01")
        self.assertEqual(rec["corpo"], b'{"mensagem":"MARCADOR-DO-CORPO"}')
        self.assertNotIn(CHAVE_DO_AGENTE, json.dumps(rec["cabecalhos"]))

    def test_corpo_em_pedacos_e_resposta_em_fluxo_atravessam(self):
        status, _ = self.requisicao_como("p3", corpo=b"corpo-em-pedacos-de-cinco", chunked=True)
        self.assertEqual(status, 200)
        self.assertEqual(self.destino.recebidos[-1]["corpo"], b"corpo-em-pedacos-de-cinco")
        status, corpo = self.requisicao_como("p3", metodo="GET", caminho="/v1/stream", corpo=b"")
        self.assertEqual(status, 200)
        self.assertEqual(corpo.count("data: bloco-"), 3)

    def test_destinos_e_metodos_fora_da_lista_nao_chegam_ao_destino(self):
        for metodo, caminho in (("POST", "/"), ("POST", "/admin"), ("POST", "/v1/../etc/passwd"), ("POST", "/v2/messages"),
                                ("DELETE", "/v1/messages"), ("POST", "//evil.example/v1/messages"), ("POST", "http://evil.example/v1/x")):
            status, _ = self.requisicao_como("p3", metodo=metodo, caminho=caminho)
            self.assertIn(status, (403, 400, 404), (metodo, caminho))
        self.assertEqual(self.destino.recebidos, [], "nenhuma dessas requisições pode chegar ao destino")
        log = self.le_log("rede.jsonl")
        self.assertIn("destino ou método fora da lista", log)

    def test_chamador_sem_papel_e_negado(self):
        status, _ = self.requisicao_como(None, uid_avulso=65000)
        self.assertEqual(status, 403)
        self.assertEqual(self.destino.recebidos, [])
        self.assertIn("uid sem papel", self.le_log("rede.jsonl"))

    def test_auditoria_encadeada_sem_credencial_nem_corpo(self):
        self.requisicao_como("p3", cabecalhos={"x-api-key": CHAVE_DO_AGENTE}, corpo=b'{"m":"MARCADOR-DO-CORPO"}')
        self.requisicao_como("coordenador", caminho="/proibido")
        self.assertEqual(logd.verificar(self.raiz / "logs/rede.jsonl"), [])
        eventos = [json.loads(x)["dados"] for x in self.le_log("rede.jsonl").splitlines()]
        tipos = [(e["papel"], e["evento"]) for e in eventos]
        self.assertIn(("p3", "inicio"), tipos)
        self.assertIn(("p3", "fim"), tipos)
        self.assertIn(("coordenador", "negado"), tipos)
        fim = next(e for e in eventos if e["evento"] == "fim")
        self.assertEqual((fim["status"], fim["metodo"], fim["caminho"]), (200, "POST", "/v1/messages"))
        todos = " ".join((self.raiz / "logs" / n).read_text() for n in I.nomes_de_log(self.spec))
        for segredo in (CHAVE_REAL, CHAVE_DO_AGENTE, "MARCADOR-DO-CORPO"):
            self.assertNotIn(segredo, todos)

    def test_credencial_nao_aparece_em_argv_ambiente_nem_e_legivel_por_papeis(self):
        pid = self.procs["gateway"].pid
        self.assertNotIn(CHAVE_REAL.encode(), Path(f"/proc/{pid}/cmdline").read_bytes())
        self.assertNotIn(CHAVE_REAL.encode(), Path(f"/proc/{pid}/environ").read_bytes())
        for papel in ("p3", "revisor", "coordenador"):
            r = rodar_como(papel, self.spec, f"for f in ('environ','mem','maps','fd'):\n try:\n  open('/proc/{pid}/'+f,'rb').read(1) if f!='fd' else __import__('os').listdir('/proc/{pid}/fd'); print(f,'LEU')\n except OSError: print(f,'NEGADO')\n")
            self.assertNotIn("LEU", r.stdout, (papel, r.stdout))
            r = rodar_como(papel, self.spec, f"try:\n print(open({str(self.chave_arquivo)!r}).read())\nexcept OSError: print('NEGADO')\n")
            self.assertEqual(r.stdout.strip(), "NEGADO", papel)
            self.assertNotIn(CHAVE_REAL, r.stdout)

    def test_chave_so_vem_de_arquivo_protegido_ou_descritor(self):
        arq = self.base / "chave-frouxa"
        arq.write_text("x\n", encoding="utf-8")
        os.chmod(arq, 0o644)
        with self.assertRaises(SystemExit):
            GW.ler_chave(arquivo=str(arq))                                       # modo aberto a outros: recusada
        with self.assertRaises(SystemExit):
            GW.ler_chave()                                                       # sem fonte: não há variável de ambiente de reserva
        os.chmod(arq, 0o600)
        self.assertEqual(GW.ler_chave(arquivo=str(arq)), "x")
        r = subprocess.run([sys.executable, "-I", "-B", str(self.svc / "scripts/gateway.py"), "--raiz", str(self.raiz), "--chave", "x"],
                           capture_output=True, text=True, timeout=20)
        self.assertNotEqual(r.returncode, 0)                                     # não existe opção para passar a chave em argv

    def test_sem_auditoria_nada_e_enviado(self):
        self.derruba("logd")
        status, _ = self.requisicao_como("p3")
        self.assertEqual(status, 503)
        self.assertEqual(self.destino.recebidos, [], "fail-closed: sem registro confirmado, a requisição não sai")

    def test_destino_indisponivel_vira_502_com_auditoria_de_falha(self):
        self.destino.fechar()
        self.destino = None
        # recria o gateway apontando para uma porta fechada
        self.derruba("gateway")
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        porta = s.getsockname()[1]
        s.close()
        uid = self.spec["contas"]["ppp-rede"]
        p = subprocess.Popen([*prefixo_de(uid, uid, [uid, self.spec["grupos"]["ppp-leitura"]]), sys.executable, "-I", "-B",
                              str(self.svc / "scripts/gateway.py"), "--raiz", str(self.raiz), "--spec", str(self.svc / "governanca/papeis.json"),
                              "--socket", str(self.gw_socket), "--logd-socket", str(self.logd_socket), "--upstream", f"http://127.0.0.1:{porta}",
                              "--chave-arquivo", str(self.chave_arquivo)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.procs["gateway"] = p
        self.assertIn("pronto", p.stdout.readline())
        status, _ = self.requisicao_como("p3")
        self.assertEqual(status, 502)
        self.assertIn('"evento":"falha"', self.le_log("rede.jsonl"))

    def test_de_ponta_a_ponta_dentro_da_jaula_a_sessao_so_alcanca_o_gateway(self):
        if not shutil.which("bwrap"):
            self.skipTest("bwrap ausente")
        cliente = (
            "import os,json,socket,urllib.request\n"
            "r={'chave_no_env':os.environ.get('ANTHROPIC_API_KEY'),'tem_real':any(%r in v for v in os.environ.values())}\n"
            "def direto(porta):\n"
            "    s=socket.socket(); s.settimeout(3)\n"
            "    try: s.connect(('127.0.0.1',porta)); return True\n"
            "    except OSError: return False\n"
            "r['direto_ao_destino']=direto(%d)\n"
            "req=urllib.request.Request(os.environ['ANTHROPIC_BASE_URL']+'/v1/messages',data=b'{}',headers={'x-api-key':os.environ['ANTHROPIC_API_KEY']})\n"
            "r['via_gateway']=urllib.request.urlopen(req,timeout=10).status\n"
            "print(json.dumps(r))\n") % (CHAVE_REAL, self.destino.porta)
        spec = self.spec
        uid, gid, gids = I.ids_papel(spec, "p3")
        vetor = [*prefixo_de(uid, gid, gids), sys.executable, "-B", str(self.raiz / "scripts/jaula.py"), "--papel", "p3", "--raiz", str(self.raiz),
                 "--home", str(self.homes / "p3"), "--extra-ro", str(self.run), "--",
                 sys.executable, "-I", "-B", str(self.raiz / "scripts/entrada_jaula.py"), "--gateway", str(self.gw_socket), "--",
                 sys.executable, "-B", "-c", cliente]
        r = subprocess.run(vetor, capture_output=True, text=True, timeout=60, cwd=self.raiz)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(out["via_gateway"], 200)
        self.assertFalse(out["direto_ao_destino"], "o destino do host é alcançável a partir da jaula: a rede não está isolada")
        self.assertFalse(out["tem_real"])
        self.assertEqual(out["chave_no_env"], "gateway-local-sem-valor")
        self.assertEqual(self.destino.recebidos[-1]["cabecalhos"]["x-api-key"], CHAVE_REAL)
        self.assertIn('"papel":"p3"', self.le_log("rede.jsonl"))

    def test_lancador_completo_entrega_sessao_sem_credencial_e_com_rede_so_pelo_gateway(self):
        if not shutil.which("bwrap"):
            self.skipTest("bwrap ausente")
        stub = self.base / "claude-stub"
        stub.write_text(
            "#!/bin/sh\n"
            "echo AMB=$(env | grep -c '" + CHAVE_REAL + "') CMD=$(tr '\\0' ' ' < /proc/self/cmdline | grep -c '" + CHAVE_REAL + "')\n"
            "python3 -c \"import os,urllib.request\n"
            "req=urllib.request.Request(os.environ['ANTHROPIC_BASE_URL']+'/v1/messages',data=b'{}',headers={'x-api-key':os.environ['ANTHROPIC_API_KEY']})\n"
            "print('STATUS',urllib.request.urlopen(req,timeout=10).status)\"\n"
            "echo LOGD=$PPP_LOGD_SOCKET OBRIG=$PPP_LOGD_OBRIGATORIO\n", encoding="utf-8")
        os.chmod(stub, 0o755)
        env = dict(os.environ, ANTHROPIC_API_KEY=CHAVE_REAL)
        r = subprocess.run([sys.executable, "-B", str(self.raiz / "scripts/iniciar_sessao.py"), "--papel", "p3", "--claude", str(stub),
                            "--home-base", str(self.homes), "--logd-socket", str(self.logd_socket), "--gateway-socket", str(self.gw_socket)],
                           capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("AMB=0 CMD=0", r.stdout)
        self.assertIn("STATUS 200", r.stdout)
        self.assertIn("OBRIG=1", r.stdout)
        self.assertNotIn(CHAVE_REAL, r.stdout + r.stderr)
        self.assertEqual(self.destino.recebidos[-1]["cabecalhos"]["x-api-key"], CHAVE_REAL)


class TestPontaDaJaula(unittest.TestCase):
    """Sem root: o cliente que liga a sessão ao gateway só repassa bytes e entrega marcadores, nunca uma chave."""

    def test_variaveis_de_credencial_do_operador_sao_removidas_e_substituidas(self):
        env = {k: v for k, v in os.environ.items()}
        env.update({"ANTHROPIC_API_KEY": "chave-do-operador", "ANTHROPIC_AUTH_TOKEN": "t", "HTTPS_PROXY": "http://u:s@p"})
        r = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/entrada_jaula.py"), "--gateway", __file__, "--", sys.executable, "-c",
                            "import os,json;print(json.dumps({k:v for k,v in os.environ.items() if 'ANTHROPIC' in k or 'PROXY' in k.upper()}))"],
                           capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        vistas = json.loads(r.stdout)
        self.assertNotIn("chave-do-operador", r.stdout)
        self.assertEqual(vistas["ANTHROPIC_API_KEY"], entrada_jaula.MARCADOR)
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", vistas)
        self.assertNotIn("HTTPS_PROXY", vistas)
        self.assertTrue(vistas["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:"))

    def test_sem_gateway_a_sessao_nao_inicia(self):
        r = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/entrada_jaula.py"), "--gateway", "/nao/existe.sock", "--", "true"],
                           capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("gateway indisponível", r.stderr)


if __name__ == "__main__":
    unittest.main()
