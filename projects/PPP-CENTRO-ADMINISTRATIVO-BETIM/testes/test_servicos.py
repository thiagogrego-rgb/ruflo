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
    if not obrigatorio:
        env["PPP_LOG_LEGADO"] = "1"          # o padrão é fechado; o modo legado precisa ser pedido
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

    def test_separadores_unicode_no_conteudo_nao_quebram_a_cadeia_nem_o_reinicio(self):
        separadores = "a\u2028b\u2029c\u0085d\x0be\x0cf\x1cg"
        cliente = ("import sys; sys.path.insert(0, %r)\nimport logd\nprint(logd.enviar(%r, {'alvo': %r, 'motivo': 'x'}))\n"
                   % (str(self.svc / "scripts"), str(self.logd_socket), separadores))
        r = rodar_como("p3", self.spec, cliente)
        self.assertEqual(r.stdout.strip(), "True")
        self.assertEqual(self.verifica("guarda-p3.jsonl"), [])
        self.derruba("logd")
        self.sobe_logd()                                                     # antes: serviço se recusava a iniciar
        chama_hook(self, "p3", leitura(self, "produtos/P3/x.md"))
        self.assertEqual(self.verifica("guarda-p3.jsonl"), [])
        self.assertEqual(len(self.le_log("guarda-p3.jsonl").split("\n")) - 1, 2)

    def test_taxa_por_origem_e_truncamento_com_hash(self):
        cliente = ("import sys; sys.path.insert(0, %r)\nimport logd\nok = sum(logd.enviar(%r, {'i': i}) for i in range(400))\nprint(ok)\n"
                   % (str(self.svc / "scripts"), str(self.logd_socket)))
        r = rodar_como("p3", self.spec, cliente)
        aceitos = int(r.stdout.strip())
        self.assertLess(aceitos, 400, "um papel não pode inundar a trilha sem limite")
        self.assertGreater(aceitos, 0)
        self.assertEqual(chama_hook(self, "revisor", leitura(self, "produtos/P3/x.md")).returncode, 0)        # os outros não são afetados
        longo = "x" * 5000
        cliente = ("import sys; sys.path.insert(0, %r)\nimport logd\nprint(logd.enviar(%r, {'comando': %r}))\n"
                   % (str(self.svc / "scripts"), str(self.logd_socket), longo))
        rodar_como("coordenador", self.spec, cliente)
        gravado = self.le_log("guarda-coordenador.jsonl")
        self.assertIn("truncado: 5000 caracteres, sha256=", gravado)
        import hashlib
        self.assertIn(hashlib.sha256(longo.encode()).hexdigest(), gravado)

    def test_cabeca_da_cadeia_permite_ancora_externa_contra_truncamento(self):
        for i in range(3):
            chama_hook(self, "p2", leitura(self, f"produtos/P2/{i}.md"))
        seq, h = logd.cabeca(self.raiz / "logs/guarda-p2.jsonl")
        self.assertEqual(seq, 3)
        arq = self.raiz / "logs/guarda-p2.jsonl"
        I._chattr("-a", arq)
        linhas = arq.read_text().split("\n")
        arq.write_text("\n".join(linhas[:2]) + "\n")                          # truncamento do fim: a cadeia restante continua íntegra...
        I._chattr("+a", arq)
        self.assertEqual(logd.verificar(arq), [])
        self.assertNotEqual(logd.cabeca(arq), (seq, h))                        # ...mas a cabeça publicada fora do serviço denuncia

    def test_servidor_impostor_no_socket_nao_vale_como_confirmacao(self):
        self.derruba("logd")
        impostor = ("import socket,os\ns=socket.socket(socket.AF_UNIX); s.bind(%r); s.listen(5)\n"
                    "for _ in range(5):\n c,_=s.accept(); c.recv(65536); c.sendall(b'ok\\n'); c.close()\n" % str(self.logd_socket))
        p = subprocess.Popen([sys.executable, "-c", impostor])
        try:
            for _ in range(50):
                if self.logd_socket.exists():
                    break
                time.sleep(0.1)
            os.chmod(self.logd_socket, 0o666)
            r = chama_hook(self, "p3", leitura(self, "produtos/P3/x.md"))
            self.assertEqual(r.returncode, 2, "um processo que não é a conta do serviço de log não pode confirmar a trilha")
        finally:
            p.kill()
            p.wait()

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
        status, corpo = self.requisicao_como("p3", corpo=b'{"stream": true}')
        self.assertEqual(status, 200)
        self.assertEqual(corpo.count("data: bloco-"), 3)

    def test_destinos_e_metodos_fora_da_lista_nao_chegam_ao_destino(self):
        for metodo, caminho in (("POST", "/"), ("POST", "/admin"), ("POST", "/v1/../etc/passwd"), ("POST", "/v2/messages"),
                                ("DELETE", "/v1/messages"), ("POST", "//evil.example/v1/messages"), ("POST", "http://evil.example/v1/x")):
            status, _ = self.requisicao_como("p3", metodo=metodo, caminho=caminho)
            self.assertIn(status, (403, 400, 404), (metodo, caminho))
        self.assertEqual(self.destino.recebidos, [], "nenhuma dessas requisições pode chegar ao destino")
        log = self.le_log("rede.jsonl")
        self.assertIn("fora da lista", log)

    def bruto(self, papel, requisicao):
        codigo = ("import socket,sys\ns=socket.socket(socket.AF_UNIX); s.settimeout(20); s.connect(sys.argv[1])\n"
                  "s.sendall(bytes.fromhex(sys.stdin.read()))\ns.shutdown(socket.SHUT_WR)\nr=b''\n"
                  "while True:\n b=s.recv(65536)\n if not b: break\n r+=b\nprint(r.split(b' ')[1].decode() if r else 'sem-resposta')\n")
        r = rodar_como(papel, self.spec, codigo, entrada=requisicao.hex(), args=(str(self.gw_socket),))
        return r.stdout.strip()

    def test_requisicoes_malformadas_sao_rejeitadas_antes_de_chegar_ao_destino(self):
        base = b"POST /v1/messages HTTP/1.0\r\nHost: x\r\n"
        casos = {
            "chunk negativo": base + b"Transfer-Encoding: chunked\r\n\r\n-5\r\nabcde\r\n0\r\n\r\n",
            "chunk com 0x": base + b"Transfer-Encoding: chunked\r\n\r\n0x5\r\nabcde\r\n0\r\n\r\n",
            "content-length duplicado": base + b"Content-Length: 2\r\nContent-Length: 2\r\n\r\nab",
            "content-length com sinal": base + b"Content-Length: +2\r\n\r\nab",
            "content-length e chunked": base + b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n",
            "corpo mais curto que o declarado": base + b"Content-Length: 50\r\n\r\nab",
        }
        for nome, req in casos.items():
            self.assertEqual(self.bruto("p3", req), "400", nome)
        for caminho in ("/v1/%2e%2e/etc", "/v1/messages;x", "/v1/messages%2f..", "/v1/messages/../x", "/v1/messages/", "/v1/other"):
            req = f"POST {caminho} HTTP/1.0\r\nHost: x\r\nContent-Length: 0\r\n\r\n".encode()
            self.assertEqual(self.bruto("p3", req), "403", caminho)
        self.assertEqual(self.destino.recebidos, [])

    def test_inundacao_de_um_papel_nao_derruba_a_auditoria_dos_outros(self):
        for _ in range(150):                                     # p3 dispara muitas requisições proibidas
            self.requisicao_como("p3", caminho="/proibido")
        status, _ = self.requisicao_como("coordenador")          # outro papel segue sendo atendido e auditado
        self.assertEqual(status, 200)
        self.assertIn('"papel":"coordenador"', self.le_log("rede.jsonl"))

    def test_somente_cabecalhos_necessarios_sao_encaminhados(self):
        self.requisicao_como("p3", cabecalhos={"Cookie": "sessao=1", "X-Forwarded-For": "1.2.3.4", "Authorization": "Bearer x",
                                              "X-Api-Key": CHAVE_DO_AGENTE, "anthropic-version": "2023-06-01", "X-Stainless-Lang": "js",
                                              "Content-Type": "application/json", "Proxy-Authorization": "z"})
        rec = self.destino.recebidos[-1]["cabecalhos"]
        for ausente in ("cookie", "x-forwarded-for", "authorization", "proxy-authorization"):
            self.assertNotIn(ausente, rec)
        self.assertEqual(rec["x-api-key"], CHAVE_REAL)
        self.assertEqual(rec["anthropic-version"], "2023-06-01")
        self.assertEqual(rec["x-stainless-lang"], "js")

    def test_destino_precisa_ser_https_e_o_host_da_especificacao(self):
        spec = self.spec
        with self.assertRaises(SystemExit):
            GW.validar_upstream("http://api.anthropic.com", spec)
        with self.assertRaises(SystemExit):
            GW.validar_upstream("https://evil.example", spec)
        self.assertEqual(GW.validar_upstream("https://api.anthropic.com", spec).hostname, "api.anthropic.com")
        self.assertEqual(GW.validar_upstream("http://127.0.0.1:9", spec, permitir_http=True).port, 9)

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
                              "--socket", str(self.gw_socket), "--logd-socket", str(self.logd_socket), "--permitir-http-de-teste", "--upstream", f"http://127.0.0.1:{porta}",
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
            "echo LOGD=$PPP_LOGD_SOCKET\n", encoding="utf-8")
        os.chmod(stub, 0o755)
        env = dict(os.environ, ANTHROPIC_API_KEY=CHAVE_REAL)
        r = subprocess.run([sys.executable, "-B", str(self.raiz / "scripts/iniciar_sessao.py"), "--papel", "p3", "--claude", str(stub),
                            "--home-base", str(self.homes), "--logd-socket", str(self.logd_socket), "--gateway-socket", str(self.gw_socket)],
                           capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("AMB=0 CMD=0", r.stdout)
        self.assertIn("STATUS 200", r.stdout)
        self.assertNotIn(CHAVE_REAL, r.stdout + r.stderr)
        self.assertEqual(self.destino.recebidos[-1]["cabecalhos"]["x-api-key"], CHAVE_REAL)


class TestLimitesDoGateway(unittest.TestCase):
    """Sem root: limites de tempo e de taxa do gateway."""

    def test_leitura_do_corpo_tem_prazo_total(self):
        import io
        m = GW.Manipulador.__new__(GW.Manipulador)

        class Gotejante(io.BytesIO):
            def read(self, n=-1):
                return b"x"                           # um byte por chamada: nunca termina sozinho
        m.rfile = Gotejante()
        with self.assertRaises(ValueError):
            m._ler_exato(1000, time.monotonic() - 1)       # prazo já vencido
        self.assertEqual(len(m._ler_exato(10, time.monotonic() + 30)), 10)

    def test_taxa_por_papel_descarta_sem_auditar_cada_tentativa(self):
        taxa = GW.Taxa(1.0, 3)
        self.assertEqual([taxa.permite() for _ in range(5)], [True, True, True, False, False])
        self.assertEqual(taxa.resumo_devido(), 2)               # um único resumo para as duas descartadas
        self.assertEqual(taxa.resumo_devido(), 0)               # e nada de novo antes de 10 s


class TestPontaDaJaula(unittest.TestCase):
    """Sem root: a ponte só entrega marcadores (nunca uma chave) e recusa rodar fora de um namespace de rede isolado."""

    def setUp(self):
        import tempfile
        self.dir = Path(tempfile.mkdtemp(prefix="ponte-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.sock = self.dir / "gw.sock"
        self.escuta = socket.socket(socket.AF_UNIX)
        self.escuta.bind(str(self.sock))
        self.addCleanup(self.escuta.close)

    def roda(self, comando, env_extra=None, gateway=None):
        env = {k: v for k, v in os.environ.items()}
        env.update(env_extra or {})
        return subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/entrada_jaula.py"), "--gateway", str(gateway or self.sock), "--",
                               *comando], capture_output=True, text=True, timeout=30, env=env)

    def test_variaveis_de_credencial_do_operador_sao_removidas_e_substituidas(self):
        r = self.roda([sys.executable, "-c", "import os,json;print(json.dumps(dict(os.environ)))"],
                      {"ANTHROPIC_API_KEY": "chave-do-operador", "ANTHROPIC_AUTH_TOKEN": "t", "HTTPS_PROXY": "http://u:s@p",
                       "GH_TOKEN": "gh", "AWS_SECRET_ACCESS_KEY": "aws", "ANTHROPIC_CUSTOM_HEADERS": "x: y",
                       "PPP_PONTE_SEM_ISOLAMENTO_DE_TESTE": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        vistas = json.loads(r.stdout)
        for segredo in ("chave-do-operador", "u:s", "gh", "aws"):
            self.assertNotIn(segredo, r.stdout)
        self.assertEqual(vistas["ANTHROPIC_API_KEY"], entrada_jaula.MARCADOR)         # lista de PERMISSÃO: nada além do necessário
        for ausente in ("ANTHROPIC_AUTH_TOKEN", "HTTPS_PROXY", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "ANTHROPIC_CUSTOM_HEADERS"):
            self.assertNotIn(ausente, vistas)
        self.assertTrue(vistas["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:"))

    def test_sem_gateway_ou_com_arquivo_que_nao_e_socket_a_sessao_nao_inicia(self):
        for alvo in ("/nao/existe.sock", __file__):
            r = self.roda(["true"], {"PPP_PONTE_SEM_ISOLAMENTO_DE_TESTE": "1"}, gateway=alvo)
            self.assertNotEqual(r.returncode, 0, alvo)
            self.assertIn("gateway indisponível", r.stderr)

    def test_recusa_rodar_fora_de_um_namespace_de_rede_isolado(self):
        interfaces = set(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else {"lo"}
        if interfaces <= {"lo"}:
            self.skipTest("este ambiente já tem namespace de rede vazio")
        r = self.roda(["true"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("não está isolado", r.stderr)


if __name__ == "__main__":
    unittest.main()
