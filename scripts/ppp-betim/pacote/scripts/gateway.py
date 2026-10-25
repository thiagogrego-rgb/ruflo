#!/usr/bin/env python3
"""Gateway de rede e de credencial (GOV-08): a sessão do agente não tem rede própria nem a chave da API.

A sessão roda num namespace de rede vazio (`jaula.py --rede gateway`). A única saída é este serviço, por socket Unix.
Ele NÃO é um proxy aberto: é um proxy reverso para UM destino configurado (`rede.upstream`) e só para caminhos
permitidos (`rede.caminhos_permitidos`). Por isso WebFetch, MCP remoto, `curl` e qualquer conexão a outro host simplesmente
não têm rota.
  - A credencial vem de arquivo 0600 do serviço ou de descritor herdado, NUNCA de argv nem de variável de ambiente, e é
    injetada aqui (cabeçalhos de autenticação do cliente são descartados). Não é registrada em log.
  - O chamador é identificado pelo kernel (SO_PEERCRED); uid desconhecido é negado.
  - Cada requisição gera um registro ANTES do envio (sem registro confirmado pelo serviço de log, nada é enviado) e outro
    ao final, no serviço de log (`logd.py`), com método, caminho sem query, status e tamanhos — nunca cabeçalhos nem corpo.
Limite: só cobre credenciais de API (chave). Login por assinatura (OAuth) não passa por aqui.

    python3 -I -B scripts/gateway.py --raiz DIR [--spec papeis.json] [--chave-arquivo F | --chave-fd N] (conta ppp-rede, nunca root)
"""
import argparse
import http.client
import http.server
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolamento_base as B  # noqa: E402
import logd  # noqa: E402

LIMITE_CORPO = 64 * 1024 * 1024
MAX_SIMULTANEAS = 8
TEMPO_UPSTREAM = 600
DESCARTAR_NA_ENTRADA = {"host", "authorization", "x-api-key", "proxy-authorization", "connection", "keep-alive", "te",
                        "trailer", "transfer-encoding", "upgrade", "content-length", "cookie", "x-forwarded-for"}
DESCARTAR_NA_SAIDA = {"connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-authenticate", "te", "trailer"}


def ler_chave(arquivo=None, fd=None):
    """Chave de API sem passar por argv nem ambiente. Arquivo: dono = quem executa, modo sem acesso a grupo/outros."""
    if fd is not None:
        with os.fdopen(fd, "r", closefd=True) as f:
            chave = f.read().strip()
    elif arquivo:
        st = os.stat(arquivo)
        if st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise SystemExit("arquivo da chave deve pertencer ao serviço e ter modo 0600")
        chave = Path(arquivo).read_text(encoding="utf-8").strip()
    else:
        raise SystemExit("informe --chave-arquivo ou --chave-fd (a chave nunca vem de argv nem de variável de ambiente)")
    if not chave:
        raise SystemExit("chave vazia")
    return chave


class Servidor(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, caminho, spec, chave, upstream=None, logd_socket=None):
        self.origens = {spec["contas"][p["conta"]]: nome for nome, p in spec["papeis"].items()}
        self.chave = chave
        alvo = urllib.parse.urlsplit(upstream or spec["rede"]["upstream"])
        if alvo.scheme not in ("https", "http") or not alvo.hostname:
            raise SystemExit("upstream inválido")
        self.alvo = alvo
        self.permitidos = tuple(spec["rede"]["caminhos_permitidos"])
        self.logd = logd_socket or spec["servicos"]["logd_socket"]
        self.limite = threading.BoundedSemaphore(MAX_SIMULTANEAS)
        Path(caminho).unlink(missing_ok=True)
        super().__init__(str(caminho), Manipulador)
        os.chown(caminho, -1, spec["grupos"][spec["servicos"]["grupo_socket"]])
        os.chmod(caminho, 0o660)


class Manipulador(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"          # uma requisição por conexão; o corpo termina no fechamento
    server_version = "ppp-gateway"

    def log_message(self, *_):             # nada de log do http.server (poderia vazar caminhos/cabeçalhos)
        pass

    def address_string(self):
        return "unix"

    def _auditar(self, papel, evento, **campos):
        return logd.enviar(self.server.logd, {"tipo": "rede", "papel": papel, "evento": evento, **campos})

    def _responder(self, codigo, texto):
        corpo = (texto + "\n").encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def _corpo(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            partes, total = [], 0
            while True:
                tamanho = int(self.rfile.readline(64).split(b";")[0].strip() or b"0", 16)
                if tamanho == 0:
                    self.rfile.readline(64)
                    break
                total += tamanho
                if total > LIMITE_CORPO:
                    raise ValueError("corpo grande demais")
                partes.append(self.rfile.read(tamanho))
                self.rfile.readline(4)
            return b"".join(partes)
        tamanho = int(self.headers.get("Content-Length") or 0)
        if tamanho < 0 or tamanho > LIMITE_CORPO:
            raise ValueError("corpo grande demais")
        return self.rfile.read(tamanho) if tamanho else b""

    def _tratar(self):
        inicio = time.monotonic()
        pid, uid, gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        papel = self.server.origens.get(uid)
        forma_invalida = not self.path.startswith("/") or self.path.startswith("//")      # só forma de origem: nada de URL absoluta
        partes = urllib.parse.urlsplit(self.path if not forma_invalida else "/")
        caminho = partes.path if not forma_invalida else self.path[:200]
        if papel is None:
            self._auditar("desconhecido", "negado", motivo="uid sem papel", metodo=self.command, caminho=caminho)
            return self._responder(403, "chamador não autorizado")
        if forma_invalida or self.command not in ("GET", "POST") or not caminho.startswith(self.server.permitidos) or ".." in caminho.split("/"):
            self._auditar(papel, "negado", motivo="destino ou método fora da lista", metodo=self.command, caminho=caminho[:200])
            return self._responder(403, "destino não permitido pelo gateway")
        try:
            corpo = self._corpo()
        except (ValueError, OSError):
            self._auditar(papel, "negado", motivo="corpo inválido ou grande demais", metodo=self.command, caminho=caminho)
            return self._responder(413, "corpo inválido")
        if not self._auditar(papel, "inicio", metodo=self.command, caminho=caminho, bytes_req=len(corpo)):
            return self._responder(503, "registro de auditoria indisponível; nada foi enviado")
        if not self.server.limite.acquire(blocking=False):
            self._auditar(papel, "negado", motivo="limite de conexões simultâneas", metodo=self.command, caminho=caminho)
            return self._responder(429, "limite de conexões simultâneas")
        status, enviados = 502, 0
        try:
            cab = {k: v for k, v in self.headers.items() if k.lower() not in DESCARTAR_NA_ENTRADA}
            cab["x-api-key"] = self.server.chave
            cab["Content-Length"] = str(len(corpo))
            alvo = self.server.alvo
            Con = http.client.HTTPSConnection if alvo.scheme == "https" else http.client.HTTPConnection
            con = Con(alvo.hostname, alvo.port, timeout=TEMPO_UPSTREAM)
            try:
                destino = caminho + (("?" + partes.query) if partes.query else "")
                con.request(self.command, destino, body=corpo or None, headers=cab)
                resp = con.getresponse()
                status = resp.status
                self.send_response(status)
                for k, v in resp.getheaders():
                    if k.lower() not in DESCARTAR_NA_SAIDA and k.lower() != "content-length":
                        self.send_header(k, v)
                self.end_headers()
                while True:
                    bloco = resp.read(8192)
                    if not bloco:
                        break
                    self.wfile.write(bloco)
                    self.wfile.flush()
                    enviados += len(bloco)
            finally:
                con.close()
        except Exception as erro:
            try:
                self._responder(502, "falha ao falar com o destino")
            except OSError:
                pass
            self._auditar(papel, "falha", metodo=self.command, caminho=caminho, erro=type(erro).__name__)
            return
        finally:
            self.server.limite.release()
        self._auditar(papel, "fim", metodo=self.command, caminho=caminho, status=status, bytes_resp=enviados,
                      ms=int((time.monotonic() - inicio) * 1000))

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _tratar


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--raiz", required=True)
    ap.add_argument("--spec", default=str(B.SPEC_PADRAO))
    ap.add_argument("--socket")
    ap.add_argument("--logd-socket")
    ap.add_argument("--upstream")
    ap.add_argument("--chave-arquivo")
    ap.add_argument("--chave-fd", type=int)
    a = ap.parse_args(argv)
    if os.geteuid() == 0:
        raise SystemExit("o gateway não executa como root")
    spec = B.carregar(a.spec)
    problemas = B.validar(spec)
    if problemas:
        raise SystemExit("papeis.json inválido: " + "; ".join(problemas))
    chave = ler_chave(a.chave_arquivo, a.chave_fd)
    srv = Servidor(a.socket or spec["servicos"]["gateway_socket"], spec, chave, a.upstream, a.logd_socket)
    print("gateway pronto", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
