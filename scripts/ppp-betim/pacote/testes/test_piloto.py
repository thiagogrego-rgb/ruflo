"""GOV-09: ferramental do piloto — âncoras externas de log, gateway com HTTPS/CA/proxy, credencial, varredura, supervisor, comparação.

Dados sintéticos e servidores locais; nenhuma credencial real. Os testes que dependem de root/Linux são PULADOS (NÃO EXECUTADO).
"""
import datetime
import http.server
import json
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from apoio_servicos import PULAR, ROOT, Ambiente, I, prefixo_de, spec_base

sys.path.insert(0, str(ROOT / "scripts"))
import ancora_logs as ANC  # noqa: E402
import gateway as GW  # noqa: E402
import iniciar_sessao as L  # noqa: E402
import logd  # noqa: E402
import piloto  # noqa: E402
import piloto_ambiente as AMB  # noqa: E402
import piloto_cenarios as CEN  # noqa: E402

CANARIO = b"sk-ant-SINTETICO-CANARIO-0123456789abcdef"


def _raiz_com_logs(spec, registros=3):
    raiz = Path(tempfile.mkdtemp(prefix="anc-"))
    (raiz / "logs").mkdir()
    for nome in I.nomes_de_log(spec):
        (raiz / "logs" / nome).write_text("")
        cadeia = logd.Cadeia(raiz / "logs" / nome, exigir_so_anexar=False)
        for i in range(registros):
            cadeia.anexar("p3", {"evento": "x", "i": i})
    return raiz


@PULAR
class TestAncoras(unittest.TestCase):
    def setUp(self):
        self.spec = spec_base()
        self.raiz = _raiz_com_logs(self.spec)
        self.destino = Path(tempfile.mkdtemp(prefix="anc-dest-"))
        os.chmod(self.destino, 0o755)

    def anexa(self, nome="rede.jsonl", n=1):
        cadeia = logd.Cadeia(self.raiz / "logs" / nome, exigir_so_anexar=False)
        for i in range(n):
            cadeia.anexar("p3", {"evento": "novo", "i": i})

    def test_sem_ancora_e_um_problema_declarado(self):
        self.assertTrue(any("nenhuma âncora" in p for p in ANC.verificar(self.raiz, self.spec, self.destino)))

    def test_publicar_e_verificar_e_novos_registros_continuam_ok(self):
        ANC.publicar(self.raiz, self.spec, self.destino)
        self.assertEqual(ANC.verificar(self.raiz, self.spec, self.destino), [])
        self.anexa(n=4)
        self.assertEqual(ANC.verificar(self.raiz, self.spec, self.destino), [])

    def test_ancora_e_somente_leitura_e_nao_sobrescreve(self):
        ts, _ = ANC.publicar(self.raiz, self.spec, self.destino)
        arq = self.destino / f"ancora-{ts}.json"
        self.assertEqual(arq.stat().st_mode & 0o777, 0o444)
        self.assertNotIn("SINTETICO-SEGREDO", arq.read_text())

    def test_truncagem_da_cauda_e_detectada(self):
        ANC.publicar(self.raiz, self.spec, self.destino)
        alvo = self.raiz / "logs/rede.jsonl"
        linhas = alvo.read_text().splitlines()
        alvo.write_text("\n".join(linhas[:-2]) + "\n")
        self.assertEqual(logd.verificar(alvo), [])                             # a cadeia sozinha NÃO denuncia a truncagem
        self.assertTrue(any("TRUNCADA" in p for p in ANC.verificar(self.raiz, self.spec, self.destino)))

    def test_reescrita_com_mesma_extensao_e_detectada(self):
        ANC.publicar(self.raiz, self.spec, self.destino)
        alvo = self.raiz / "logs/guarda-p3.jsonl" if (self.raiz / "logs/guarda-p3.jsonl").exists() else self.raiz / "logs/rede.jsonl"
        alvo.unlink()
        alvo.write_text("")
        cadeia = logd.Cadeia(alvo, exigir_so_anexar=False)
        for i in range(3):
            cadeia.anexar("p3", {"evento": "reescrito", "i": i})
        self.assertTrue(any("REESCRITA" in p for p in ANC.verificar(self.raiz, self.spec, self.destino)))

    def test_cadeia_corrompida_nao_e_ancorada(self):
        alvo = self.raiz / "logs/rede.jsonl"
        alvo.write_text(alvo.read_text().replace('"evento":"x"', '"evento":"y"', 1))
        with self.assertRaises(SystemExit):
            ANC.publicar(self.raiz, self.spec, self.destino)

    def test_destino_inseguro_e_recusado(self):
        os.chmod(self.destino, 0o777)
        with self.assertRaises(SystemExit):
            ANC.publicar(self.raiz, self.spec, self.destino)


# ------------------------------------------------------------------------------------------------ TLS e proxy
def _certificados(pasta):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def par(nome, emissor=None, chave_emissor=None, ca=False, san=None, chave_pub_emissor=None):
        chave = ec.generate_private_key(ec.SECP256R1())
        assunto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome)])
        agora = datetime.datetime.now(datetime.timezone.utc)
        b = (x509.CertificateBuilder().subject_name(assunto).issuer_name(emissor or assunto).public_key(chave.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(agora - datetime.timedelta(hours=1))
             .not_valid_after(agora + datetime.timedelta(hours=2)).add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(chave.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(chave_pub_emissor or chave.public_key()), critical=False)
             .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                          key_agreement=False, key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        return chave, b.sign(chave_emissor or chave, hashes.SHA256()), assunto

    chave_ca, cert_ca, nome_ca = par("CA sintetica do piloto", ca=True)
    chave_srv, cert_srv, _ = par("localhost", emissor=nome_ca, chave_emissor=chave_ca, san="localhost", chave_pub_emissor=chave_ca.public_key())
    _, cert_outra, _ = par("Outra CA sintetica", ca=True)
    pem = serialization.Encoding.PEM
    (pasta / "ca.pem").write_bytes(cert_ca.public_bytes(pem))
    (pasta / "outra-ca.pem").write_bytes(cert_outra.public_bytes(pem))
    (pasta / "srv.pem").write_bytes(cert_srv.public_bytes(pem))
    (pasta / "srv.key").write_bytes(chave_srv.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    for arq in pasta.glob("*"):
        os.chmod(arq, 0o644)


class DestinoTLS:
    def __init__(self, pasta):
        self.recebidos = []
        registro = self.recebidos

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_):
                pass

            def do_POST(self):
                tam = int(self.headers.get("Content-Length") or 0)
                corpo = self.rfile.read(tam) if tam else b""
                registro.append({"caminho": self.path, "cab": {k.lower(): v for k, v in self.headers.items()}, "corpo": corpo})
                r = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(r)))
                self.end_headers()
                self.wfile.write(r)

        self.servidor = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pasta / "srv.pem", pasta / "srv.key")
        self.servidor.socket = ctx.wrap_socket(self.servidor.socket, server_side=True)
        self.porta = self.servidor.server_address[1]
        threading.Thread(target=self.servidor.serve_forever, daemon=True).start()

    def fechar(self):
        self.servidor.shutdown()
        self.servidor.server_close()


class ProxyConnect:
    """Proxy HTTP mínimo que só aceita CONNECT e registra o que o gateway lhe envia."""

    def __init__(self):
        self.pedidos = []
        pedidos = self.pedidos

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                dados = b""
                while b"\r\n\r\n" not in dados:
                    c = self.request.recv(4096)
                    if not c:
                        return
                    dados += c
                linhas = dados.decode("latin-1").split("\r\n")
                cab = {x.split(":", 1)[0].lower(): x.split(":", 1)[1].strip() for x in linhas[1:] if ":" in x}
                pedidos.append({"linha": linhas[0], "cab": cab})
                metodo, alvo, _ = linhas[0].split()
                if metodo != "CONNECT":
                    self.request.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                    return
                host, porta = alvo.rsplit(":", 1)
                destino = socket.create_connection((host, int(porta)), timeout=10)
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                def bomba(a, b):
                    try:
                        while True:
                            c = a.recv(65536)
                            if not c:
                                break
                            b.sendall(c)
                    except OSError:
                        pass
                    finally:
                        try:
                            b.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                t = threading.Thread(target=bomba, args=(destino, self.request), daemon=True)
                t.start()
                bomba(self.request, destino)
                t.join(5)
                destino.close()

        class S(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.servidor = S(("127.0.0.1", 0), H)
        self.porta = self.servidor.server_address[1]
        threading.Thread(target=self.servidor.serve_forever, daemon=True).start()

    def fechar(self):
        self.servidor.shutdown()
        self.servidor.server_close()


@PULAR
class TestGatewayTLS(Ambiente):
    def setUp(self):
        super().setUp()
        self.certs = self.base / "certs"
        self.certs.mkdir()
        os.chmod(self.certs, 0o755)
        _certificados(self.certs)
        self.tls = DestinoTLS(self.certs)
        self.addCleanup(self.tls.fechar)
        self.sobe_logd()

    def gateway(self, ca="ca.pem", proxy=None):
        cmd = [str(self.svc / "scripts/gateway.py"), "--raiz", str(self.raiz), "--spec", str(self.svc / "governanca/papeis.json"),
               "--socket", str(self.gw_socket), "--logd-socket", str(self.logd_socket), "--permitir-http-de-teste",
               "--upstream", f"https://localhost:{self.tls.porta}", "--chave-arquivo", str(self.chave_arquivo), "--ca-arquivo", str(self.certs / ca)]
        if proxy:
            cmd += ["--proxy-arquivo", str(proxy)]
        self._subir("gateway", "ppp-rede", cmd)

    def test_https_com_ca_correta_entrega_com_a_chave_injetada(self):
        self.gateway()
        status, _ = self.requisicao_como("p3")
        self.assertEqual(status, 200)
        self.assertEqual(len(self.tls.recebidos), 1)
        self.assertEqual(self.tls.recebidos[0]["cab"].get("x-api-key"), "chave-real-sintetica-9f3a")

    def test_https_com_ca_errada_falha_fechado_e_nada_e_entregue(self):
        self.gateway(ca="outra-ca.pem")
        status, _ = self.requisicao_como("p3")
        self.assertEqual(status, 502)
        self.assertEqual(self.tls.recebidos, [])

    def test_https_via_proxy_connect_com_credencial_do_proxy_em_arquivo(self):
        proxy = ProxyConnect()
        self.addCleanup(proxy.fechar)
        arq = self.base / "proxy.url"
        arq.write_text(f"http://usuario-sintetico:senha-sintetica@127.0.0.1:{proxy.porta}\n")
        uid = self.spec["contas"]["ppp-rede"]
        os.chown(arq, uid, uid)
        os.chmod(arq, 0o600)
        self.gateway(proxy=arq)
        status, _ = self.requisicao_como("p3")
        self.assertEqual(status, 200)
        self.assertEqual(self.tls.recebidos[0]["cab"].get("x-api-key"), "chave-real-sintetica-9f3a")
        self.assertEqual(len(proxy.pedidos), 1)
        self.assertEqual(proxy.pedidos[0]["linha"], f"CONNECT localhost:{self.tls.porta} HTTP/1.1")
        self.assertTrue(proxy.pedidos[0]["cab"]["proxy-authorization"].startswith("Basic "))
        # a credencial do proxy nunca aparece no log de rede nem no processo
        self.assertNotIn("senha-sintetica", self.le_log("rede.jsonl"))
        cmdline = (Path("/proc") / str(self.procs["gateway"].pid) / "cmdline").read_bytes()
        self.assertNotIn(b"senha-sintetica", cmdline)

    def test_arquivo_de_proxy_inseguro_e_recusado(self):
        arq = self.base / "proxy-aberto.url"
        arq.write_text("http://u:p@127.0.0.1:1\n")
        os.chmod(arq, 0o644)
        with self.assertRaises(SystemExit):
            GW.ler_proxy(arq)

    def test_ler_proxy_valido(self):
        arq = Path(tempfile.mkdtemp()) / "p.url"
        arq.write_text("http://a:b@proxy.exemplo:3128\n")
        os.chmod(arq, 0o600)
        host, porta, cab = GW.ler_proxy(arq)
        self.assertEqual((host, porta), ("proxy.exemplo", 3128))
        self.assertTrue(cab["Proxy-Authorization"].startswith("Basic "))


# ------------------------------------------------------------------------------------------------ ambiente do piloto
class TestAmbiente(unittest.TestCase):
    def setUp(self):
        self.spec = spec_base()
        self.pasta = Path(tempfile.mkdtemp(prefix="piloto-"))
        os.chmod(self.pasta, 0o755)
        for alvo, valor in (("EVIDENCIAS", self.pasta / "ev"), ("REGISTRO_CREDENCIAL", self.pasta / "ev/registro.jsonl")):
            p = mock.patch.object(AMB, alvo, valor)
            p.start()
            self.addCleanup(p.stop)
        (self.pasta / "ev").mkdir()
        self.chave = self.pasta / "chave-api"

    def test_dados_nao_sinteticos_sao_recusados_e_sinteticos_aceitos(self):
        dados = self.pasta / "dados"
        dados.mkdir()
        (dados / "doc.txt").write_text("conteudo qualquer da prefeitura\n")
        self.assertTrue(AMB.verificar_dados_sinteticos(dados))
        (dados / "doc.txt").write_text("SINTETICO conteudo inventado\n")
        self.assertEqual(AMB.verificar_dados_sinteticos(dados), [])

    @PULAR
    def test_credencial_instalada_com_dono_modo_e_registro_sem_segredo(self):
        reg = AMB.instalar_credencial(self.spec, CANARIO + b"\n", "ticket-123", destino=self.chave)
        v = AMB.verificar_credencial(self.spec, destino=self.chave)
        self.assertTrue(v["ok"], v)
        st = self.chave.stat()
        self.assertEqual((st.st_uid, st.st_mode & 0o777), (self.spec["contas"]["ppp-rede"], 0o600))
        registro = AMB.REGISTRO_CREDENCIAL.read_text()
        self.assertNotIn(CANARIO.decode(), registro)
        self.assertNotIn(CANARIO.decode(), json.dumps(reg))
        self.assertEqual(reg["impressao"], v["impressao"])
        self.assertEqual(len(reg["impressao"]), 8)

    @PULAR
    def test_credencial_com_modo_ou_dono_errado_nao_passa(self):
        AMB.instalar_credencial(self.spec, CANARIO, "t", destino=self.chave)
        os.chmod(self.chave, 0o644)
        self.assertFalse(AMB.verificar_credencial(self.spec, destino=self.chave)["ok"])
        os.chmod(self.chave, 0o600)
        os.chown(self.chave, 0, 0)
        self.assertFalse(AMB.verificar_credencial(self.spec, destino=self.chave)["ok"])

    def test_credencial_ausente_nao_passa(self):
        self.assertFalse(AMB.verificar_credencial(self.spec, destino=self.chave)["ok"])

    def test_credencial_invalida_e_recusada(self):
        for ruim in (b"curta", b"com espaco no meio e comprimento suficiente", b"x" * 500, b"nao\x00imprimivel-comprimento-ok"):
            with self.subTest(ruim=ruim[:12]):
                with self.assertRaises(SystemExit):
                    AMB.instalar_credencial(self.spec, ruim, "t", destino=self.chave)
        self.assertFalse(self.chave.exists())

    @PULAR
    def test_revogacao_remove_o_arquivo_e_registra(self):
        AMB.instalar_credencial(self.spec, CANARIO, "t", destino=self.chave)
        AMB.revogar_credencial(destino=self.chave, motivo="teste")
        self.assertFalse(self.chave.exists())
        acoes = [json.loads(l)["acao"] for l in AMB.REGISTRO_CREDENCIAL.read_text().splitlines()]
        self.assertEqual(acoes, ["instalada", "revogada"])

    def test_cli_nao_aceita_credencial_por_argumento(self):
        with self.assertRaises(SystemExit):
            piloto.main(["credencial", "instalar", "--chave", "qualquer"])
        with self.assertRaises(SystemExit):
            piloto.main(["credencial", "instalar"])                              # sem --rotulo a instalação é recusada antes de ler o segredo

    def test_varredura_acha_arquivo_ambiente_e_argv_e_respeita_ignorar(self):
        (self.pasta / "vazou.txt").write_bytes(b"x " + CANARIO + b" y")
        achados = AMB.varredura_de_credencial(CANARIO, [self.pasta])
        self.assertEqual([a["onde"] for a in achados], [str(self.pasta / "vazou.txt")])
        self.assertEqual(AMB.varredura_de_credencial(CANARIO, [self.pasta], ignorar=[self.pasta / "vazou.txt"]), [])
        (self.pasta / "vazou.txt").unlink()
        p1 = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], env={"X": CANARIO.decode(), "PATH": os.environ["PATH"]})
        p2 = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)", CANARIO.decode()])
        try:
            time.sleep(0.5)
            onde = {a["onde"] for a in AMB.varredura_de_credencial(CANARIO, [])}
            self.assertIn(f"/proc/{p1.pid}/environ", onde)
            self.assertIn(f"/proc/{p2.pid}/cmdline", onde)
        finally:
            p1.kill()
            p2.kill()
            p1.wait()
            p2.wait()
        self.assertEqual(AMB.varredura_de_credencial(CANARIO, []), [])

    def test_varredura_nao_devolve_o_segredo(self):
        (self.pasta / "v.txt").write_bytes(CANARIO)
        self.assertNotIn(CANARIO.decode(), json.dumps(AMB.varredura_de_credencial(CANARIO, [self.pasta])))

    def test_supervisor_reinicia_servico_e_nao_sobe_gateway_sem_credencial(self):
        status = self.pasta / "status.json"
        chave = self.pasta / "chave-gw"
        cfg = self.pasta / "servicos.json"
        cfg.write_text(json.dumps({"gateway": {"chave_arquivo": str(chave)}}))
        curto = [sys.executable, "-c", "import time;time.sleep(0.4)"]
        with mock.patch.object(AMB, "CONFIG_SERVICOS", cfg), mock.patch.object(AMB, "STATUS_SUPERVISOR", status), \
                mock.patch.object(AMB, "comando_de_servico", lambda spec, nome, config: curto):
            threading.Timer(2.2, lambda: chave.write_text("x")).start()
            amostra = {}

            def amostrar():
                time.sleep(1.2)
                amostra["antes"] = json.loads(status.read_text())
            threading.Thread(target=amostrar, daemon=True).start()
            reinicios = AMB.supervisionar(self.spec, parar_apos=5)
        self.assertTrue(amostra["antes"]["gateway_sem_credencial"])
        self.assertIsNone(amostra["antes"]["pids"].get("gateway"))
        self.assertGreaterEqual(reinicios["logd"], 2)
        self.assertGreaterEqual(reinicios["gateway"], 1)                         # depois que a credencial existe, o gateway sobe e é reiniciado

    def test_comando_de_servico_rebaixa_privilegio_e_nao_leva_segredo(self):
        for nome in ("logd", "gateway"):
            cmd = AMB.comando_de_servico(self.spec, nome, {"gateway": {"chave_arquivo": "/etc/ppp-betim/chave-api", "upstream": "https://api.anthropic.com"}})
            self.assertEqual(cmd[0], "setpriv")
            for opcao in ("--no-new-privs", "--inh-caps=-all", "--bounding-set=-all", "-I"):
                self.assertIn(opcao, cmd)
            self.assertFalse(any("sk-ant" in c for c in cmd))
        gw = AMB.comando_de_servico(self.spec, "gateway", {"gateway": {"upstream": "https://api.anthropic.com"}})
        self.assertNotIn("--permitir-http-de-teste", gw)                         # produção nunca recebe a exceção de teste


class TestVivacidadeDoServico(unittest.TestCase):
    def test_socket_remanescente_nao_e_considerado_vivo(self):
        pasta = Path(tempfile.mkdtemp())
        caminho = pasta / "s.sock"
        s = socket.socket(socket.AF_UNIX)
        s.bind(str(caminho))
        s.close()                                                                # arquivo fica, ninguém escuta
        self.assertFalse(L._vivo(str(caminho)))
        s = socket.socket(socket.AF_UNIX)
        caminho.unlink()
        s.bind(str(caminho))
        s.listen(1)
        try:
            self.assertTrue(L._vivo(str(caminho)))
        finally:
            s.close()


class TestComparacaoEResultados(unittest.TestCase):
    def rodada(self, rotulo, extra=None):
        c = [{"id": "S02", "titulo": "t", "resultado": "PASSOU", "evidencia": {"a": True, "n": 3}, "volatil": {"duracao_s": 1.0}}]
        if extra:
            c.append(extra)
        return {"rotulo": rotulo, "cenarios": c}

    def comparar(self, a, b):
        pasta = Path(tempfile.mkdtemp())
        (pasta / "a.json").write_text(json.dumps(a))
        (pasta / "b.json").write_text(json.dumps(b))
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            return piloto.main(["comparar", str(pasta / "a.json"), str(pasta / "b.json")])

    def test_rodadas_iguais_exceto_o_volatil_sao_reprodutiveis(self):
        b = self.rodada("r2")
        b["cenarios"][0]["volatil"]["duracao_s"] = 99
        self.assertEqual(self.comparar(self.rodada("r1"), b), 0)

    def test_diferenca_de_evidencia_ou_de_resultado_reprova(self):
        b = self.rodada("r2")
        b["cenarios"][0]["evidencia"]["n"] = 4
        self.assertEqual(self.comparar(self.rodada("r1"), b), 1)
        c = self.rodada("r2")
        c["cenarios"][0]["resultado"] = "FALHOU"
        self.assertEqual(self.comparar(self.rodada("r1"), c), 1)
        self.assertEqual(self.comparar(self.rodada("r1"), self.rodada("r2", {"id": "S09", "resultado": "PASSOU", "evidencia": {}, "volatil": {}})), 1)

    def test_resultado_nao_executado_carrega_o_motivo(self):
        r = CEN.resultado("S04", "t", None, {"x": 1}, motivo="sem credencial")
        self.assertEqual(r["resultado"], "NAO_EXECUTADO")
        self.assertEqual(r["evidencia"]["motivo"], "sem credencial")

    def test_s04_em_laboratorio_nunca_conta_como_chamada_real(self):
        ctx = CEN.Contexto(spec_base(), None, "laboratorio-modelo-simulado")
        with mock.patch.object(CEN, "_egresso_tls", side_effect=AssertionError("não pode tocar a rede no laboratório")):
            r = CEN.s04_chamada_real_a_api(ctx)
        self.assertEqual(r["resultado"], "NAO_EXECUTADO")
        self.assertIn("nenhuma chamada real", r["evidencia"]["motivo"])

    def test_s04_api_real_sem_credencial_humana_nao_executa(self):
        ctx = CEN.Contexto(spec_base(), None, "api-real")
        with mock.patch.object(AMB, "verificar_credencial", return_value={"ok": False, "problemas": ["credencial não provisionada"], "tamanho": None, "impressao": None}):
            r = CEN.s04_chamada_real_a_api(ctx)
        self.assertEqual(r["resultado"], "NAO_EXECUTADO")


if __name__ == "__main__":
    unittest.main()
