"""Apoio dos testes de serviços (GOV-08): árvore aplicada, serviço de log, gateway e destino falso.

Exige Linux e root (rebaixa para as contas sintéticas dos papéis e dos serviços com `setpriv`). Sem isso os testes são
PULADOS e o resultado fica NÃO EXECUTADO.
"""
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import isolamento as I  # noqa: E402

KERNEL = sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("setpriv")
PULAR = unittest.skipUnless(KERNEL, "exige Linux, root e setpriv: serviços NÃO validados")
CHAVE_REAL = "chave-real-sintetica-9f3a"
CHAVE_DO_AGENTE = "chave-forjada-pelo-agente-77"


def spec_base():
    return I.carregar(ROOT / "governanca" / "papeis.json")


def prefixo_de(uid, gid, grupos):
    suplementares = [str(g) for g in grupos if g != gid]
    return ["setpriv", f"--reuid={uid}", f"--regid={gid}", "--groups=" + ",".join(suplementares) if suplementares else "--clear-groups"]


def prefixo_do_papel(spec, papel):
    uid, gid, gids = I.ids_papel(spec, papel)
    return prefixo_de(uid, gid, gids)


def rodar_como(papel, spec, codigo, env=None, entrada=None, args=()):
    return subprocess.run([*prefixo_do_papel(spec, papel), sys.executable, "-B", "-c", codigo, *args], capture_output=True, text=True,
                          timeout=60, env=env, input=entrada)


class DestinoFalso:
    """Servidor HTTP local que registra o que recebe (faz o papel de api.anthropic.com)."""

    def __init__(self):
        self.recebidos = []
        registro = self.recebidos

        class Manipulador(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_):
                pass

            def _tratar(self):
                tam = int(self.headers.get("Content-Length") or 0)
                corpo = self.rfile.read(tam) if tam else b""
                registro.append({"metodo": self.command, "caminho": self.path, "cabecalhos": {k.lower(): v for k, v in self.headers.items()},
                                 "corpo": corpo})
                if self.path.startswith("/v1/messages") and b'"stream"' in corpo:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    for i in range(3):
                        self.wfile.write(f"data: bloco-{i}\n\n".encode())
                        self.wfile.flush()
                        time.sleep(0.05)
                    return
                resposta = json.dumps({"ok": True, "eco": len(corpo)}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resposta)))
                self.end_headers()
                self.wfile.write(resposta)

            do_GET = do_POST = do_DELETE = do_PUT = _tratar

        self.servidor = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Manipulador)
        self.porta = self.servidor.server_address[1]
        threading.Thread(target=self.servidor.serve_forever, daemon=True).start()

    def fechar(self):
        self.servidor.shutdown()
        self.servidor.server_close()


class Ambiente(unittest.TestCase):
    """Árvore aplicada em /tmp, diretório de serviços e funções para subir/derrubar logd e gateway com as contas certas."""

    def setUp(self):
        self.spec = spec_base()
        self.base = Path(tempfile.mkdtemp(prefix="svc-"))
        self.addCleanup(self.limpa)
        os.chmod(self.base, 0o755)
        self.raiz = self.base / "proj"
        shutil.copytree(ROOT, self.raiz, ignore=shutil.ignore_patterns("__pycache__", "*.zip", "logs"), symlinks=True)
        for a in self.spec["areas"]:
            (self.raiz / a["caminho"]).mkdir(parents=True, exist_ok=True)
        self.homes = self.base / "homes"
        self.homes.mkdir()
        os.chmod(self.homes, 0o755)
        self.avisos = I.aplicar(self.raiz, self.spec, self.homes)
        # cópia do código dos serviços fora do projeto (em produção: instalação imutável do administrador)
        self.svc = self.base / "svc"
        (self.svc / "scripts").mkdir(parents=True)
        (self.svc / "governanca").mkdir()
        for f in (ROOT / "scripts").glob("*.py"):
            shutil.copy(f, self.svc / "scripts" / f.name)
        shutil.copy(ROOT / "governanca/papeis.json", self.svc / "governanca/papeis.json")
        for pasta in (self.svc, self.svc / "scripts", self.svc / "governanca"):
            os.chmod(pasta, 0o755)
        self.run = self.base / "run"
        for sub, conta in (("log", "ppp-guardiao"), ("gw", "ppp-rede")):
            (self.run / sub).mkdir(parents=True)
            os.chown(self.run / sub, self.spec["contas"][conta], self.spec["contas"][conta])
            os.chmod(self.run / sub, 0o755)
        os.chmod(self.run, 0o755)
        self.logd_socket = self.run / "log/logd.sock"
        self.gw_socket = self.run / "gw/gateway.sock"
        self.chave_arquivo = self.svc / "chave-api"
        self.chave_arquivo.write_text(CHAVE_REAL + "\n", encoding="utf-8")
        os.chown(self.chave_arquivo, self.spec["contas"]["ppp-rede"], self.spec["contas"]["ppp-rede"])
        os.chmod(self.chave_arquivo, 0o600)
        self.procs = {}
        self.destino = None

    def limpa(self):
        for p in self.procs.values():
            self._encerra(p)
        if self.destino:
            self.destino.fechar()
        for arq in (self.raiz / "logs").glob("*.jsonl"):
            I._chattr("-a", arq)
        shutil.rmtree(self.base, ignore_errors=True)

    @staticmethod
    def _encerra(p):
        p.kill()
        p.wait()
        for f in (p.stdout, p.stderr):
            if f:
                f.close()

    def _subir(self, nome, conta, comando):
        uid = self.spec["contas"][conta]
        grupos = [self.spec["grupos"][g] for g in self.spec["servicos"]["grupos_contas_servico"]]
        p = subprocess.Popen([*prefixo_de(uid, uid, [uid, *grupos]), sys.executable, "-I", "-B", *comando], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        self.procs[nome] = p
        linha = p.stdout.readline()
        if "pronto" not in linha:
            p.kill()
            self.fail(f"{nome} não subiu: {linha!r} {p.stderr.read()}")
        return p

    def sobe_logd(self):
        return self._subir("logd", "ppp-guardiao", [str(self.svc / "scripts/logd.py"), "--raiz", str(self.raiz), "--spec",
                                                    str(self.svc / "governanca/papeis.json"), "--socket", str(self.logd_socket)])

    def derruba(self, nome):
        self._encerra(self.procs.pop(nome))
        for s in (self.logd_socket, self.gw_socket):
            if nome == "logd" and s == self.logd_socket or nome == "gateway" and s == self.gw_socket:
                s.unlink(missing_ok=True)

    def sobe_gateway(self):
        self.destino = self.destino or DestinoFalso()
        return self._subir("gateway", "ppp-rede", [str(self.svc / "scripts/gateway.py"), "--raiz", str(self.raiz), "--spec",
                                                   str(self.svc / "governanca/papeis.json"), "--socket", str(self.gw_socket),
                                                   "--logd-socket", str(self.logd_socket), "--permitir-http-de-teste", "--upstream",
                                                   f"http://127.0.0.1:{self.destino.porta}", "--chave-arquivo", str(self.chave_arquivo)])

    def requisicao_como(self, papel, metodo="POST", caminho="/v1/messages", cabecalhos=None, corpo=b"{\"x\":1}", chunked=False,
                        uid_avulso=None):
        """Faz uma requisição HTTP ao gateway COMO o papel (ou um uid avulso); devolve (status, corpo_resposta)."""
        codigo = (
            "import socket,sys,json\n"
            "a=json.loads(sys.stdin.read())\n"
            "s=socket.socket(socket.AF_UNIX); s.settimeout(20); s.connect(a['sock'])\n"
            "cab=''.join(f'{k}: {v}\\r\\n' for k,v in a['cab'].items())\n"
            "corpo=bytes.fromhex(a['corpo'])\n"
            "if a['chunked']:\n"
            "    cab+='Transfer-Encoding: chunked\\r\\n'\n"
            "    dados=b''.join(('%x\\r\\n'%len(corpo[i:i+5])).encode()+corpo[i:i+5]+b'\\r\\n' for i in range(0,len(corpo),5))+b'0\\r\\n\\r\\n'\n"
            "else:\n"
            "    cab+='Content-Length: %d\\r\\n'%len(corpo); dados=corpo\n"
            "s.sendall(f\"{a['metodo']} {a['caminho']} HTTP/1.0\\r\\nHost: x\\r\\n{cab}\\r\\n\".encode()+dados)\n"
            "r=b''\n"
            "while True:\n"
            "    b=s.recv(65536)\n"
            "    if not b: break\n"
            "    r+=b\n"
            "cabeca,_,resto=r.partition(b'\\r\\n\\r\\n')\n"
            "print(json.dumps({'status':int(cabeca.split()[1]),'corpo':resto.decode(errors='replace')}))\n")
        entrada = json.dumps({"sock": str(self.gw_socket), "metodo": metodo, "caminho": caminho, "cab": cabecalhos or {},
                              "corpo": corpo.hex(), "chunked": chunked})
        if uid_avulso is not None:
            r = subprocess.run([*prefixo_de(uid_avulso, uid_avulso, [uid_avulso, self.spec['grupos']['ppp-leitura']]), sys.executable, "-B", "-c", codigo], capture_output=True, text=True,
                               timeout=60, input=entrada)
        else:
            r = rodar_como(papel, self.spec, codigo, entrada=entrada)
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        return d["status"], d["corpo"]

    def le_log(self, nome):
        return (self.raiz / "logs" / nome).read_text(encoding="utf-8")
