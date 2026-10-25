#!/usr/bin/env python3
"""Gateway de rede e de credencial (GOV-08): a sessão do agente não tem rede própria nem a chave da API.

A sessão roda num namespace de rede vazio (`jaula.py --rede gateway`). A única saída é este serviço, por socket Unix.
Ele NÃO é um proxy aberto: é um proxy reverso para UM destino configurado (`rede.upstream`), só para caminhos exatos
permitidos (`rede.caminhos_permitidos`) e só por POST. WebFetch, MCP remoto, `curl` e qualquer outro host não têm rota.
  - A credencial vem de arquivo 0600 do serviço ou de descritor herdado, NUNCA de argv nem de variável de ambiente, e é
    injetada aqui (cabeçalhos de autenticação do cliente são descartados). Não é registrada em log; o processo não gera
    core dump nem é inspecionável por outras contas (PR_SET_DUMPABLE=0).
  - O chamador é identificado pelo kernel (SO_PEERCRED); uid desconhecido é negado.
  - Cada requisição gera um registro ANTES do envio (sem registro confirmado pelo serviço de log, nada é enviado) e outro
    ao final (melhor esforço: a resposta já saiu), com método, caminho sem query, status e tamanhos — nunca cabeçalhos
    nem corpo. O serviço de log é autenticado pelo uid do servidor (não basta alguém ocupar o socket).
  - Limites: corpo, prazo de leitura do cliente, conexões simultâneas globais e por papel; entrada estrita (só dígitos).
LIMITES: protege contra LER a chave, não contra USÁ-LA: qualquer processo da sessão pode gastar a cota pelo gateway.
Só cobre credenciais de API; login por assinatura (OAuth) não passa por aqui. O conteúdo das requisições vai ao provedor
do modelo (isso é inerente ao uso do modelo).

    python3 -I -B scripts/gateway.py --raiz DIR [--spec papeis.json] [--chave-arquivo F | --chave-fd N] (conta ppp-rede, nunca root)
"""
import argparse
import ctypes
import http.client
import http.server
import os
import re
import resource
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolamento_base as B  # noqa: E402
import logd  # noqa: E402

LIMITE_CORPO = 32 * 1024 * 1024
MAX_SIMULTANEAS = 8
MAX_POR_PAPEL = 4
PRAZO_LEITURA = 30          # segundos para cada operação no socket do cliente local (anti-gotejamento)
PRAZO_TOTAL_LEITURA = 90    # segundos para o cliente local enviar TODO o corpo
PRAZO_ESCRITA_CLIENTE = 120  # segundos para o cliente local consumir a resposta
TEMPO_UPSTREAM = 600
TAXA_POR_PAPEL = (20.0, 100)   # (por segundo, rajada): excesso é recusado SEM auditar cada tentativa (só um resumo)
HEX = re.compile(rb"^[0-9a-fA-F]{1,8}$")
DIGITOS = re.compile(r"^[0-9]{1,10}$")
CAMINHO_SEGURO = re.compile(r"^/[A-Za-z0-9._~/-]*$")      # sem '%', ';', espaços nem '..' (verificado à parte)
CABECALHOS_ENCAMINHADOS = ("content-type", "accept", "user-agent", "anthropic-", "x-stainless-", "x-app", "x-claude-")
DESCARTAR_NA_SAIDA = {"connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-authenticate", "te", "trailer", "content-length"}
PR_SET_DUMPABLE = 4


def endurecer_processo():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except (OSError, AttributeError):
        pass


def ler_chave(arquivo=None, fd=None):
    """Chave de API sem passar por argv nem ambiente. Arquivo: comum, do serviço, sem acesso a grupo/outros."""
    if fd is not None:
        with os.fdopen(fd, "r", closefd=True) as f:
            chave = f.read().strip()
    elif arquivo:
        d = os.open(arquivo, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(d)
            if st.st_uid != os.geteuid() or st.st_mode & 0o077 or (st.st_mode & 0o170000) != 0o100000:
                raise SystemExit("arquivo da chave deve ser comum, do serviço e com modo 0600")
            chave = os.read(d, 4096).decode("utf-8").strip()
        finally:
            os.close(d)
    else:
        raise SystemExit("informe --chave-arquivo ou --chave-fd (a chave nunca vem de argv nem de variável de ambiente)")
    if not chave:
        raise SystemExit("chave vazia")
    return chave


def ler_proxy(arquivo):
    """Proxy de saída (CONNECT) lido de arquivo 0600 do serviço: pode conter usuário:senha, por isso nunca vai a argv nem a log."""
    d = os.open(arquivo, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(d)
        if st.st_uid != os.geteuid() or st.st_mode & 0o077 or (st.st_mode & 0o170000) != 0o100000:
            raise SystemExit("arquivo do proxy deve ser comum, do serviço e com modo 0600")
        bruto = os.read(d, 4096).decode("utf-8").strip()
    finally:
        os.close(d)
    p = urllib.parse.urlsplit(bruto)
    if p.scheme != "http" or not p.hostname or not p.port:
        raise SystemExit("proxy deve ser http://[usuario:senha@]host:porta")
    cab = {}
    if p.username:
        import base64
        credencial = f"{urllib.parse.unquote(p.username)}:{urllib.parse.unquote(p.password or '')}"
        cab["Proxy-Authorization"] = "Basic " + base64.b64encode(credencial.encode("utf-8")).decode("ascii")
    return p.hostname, p.port, cab


def contexto_tls(ca_arquivo=None):
    """Verificação de certificado SEMPRE ligada; `ca_arquivo` acrescenta uma AC privada (ex.: inspeção TLS corporativa)."""
    ctx = ssl.create_default_context(cafile=ca_arquivo) if ca_arquivo else ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def validar_upstream(url, spec, permitir_http=False):
    alvo = urllib.parse.urlsplit(url)
    esperado = urllib.parse.urlsplit(spec["rede"]["upstream"])
    if alvo.scheme not in ("https", "http") or not alvo.hostname:
        raise SystemExit("upstream inválido")
    if not permitir_http and (alvo.scheme != "https" or alvo.hostname != esperado.hostname):
        raise SystemExit("upstream deve ser https e o host definido em papeis.json (a chave nunca vai em claro nem a outro host)")
    return alvo


class Taxa:
    def __init__(self, por_segundo, rajada):
        self.por_segundo, self.rajada = por_segundo, rajada
        self.fichas, self.ultimo, self.descartadas, self.ultimo_resumo = float(rajada), time.monotonic(), 0, 0.0
        self.trava = threading.Lock()

    def permite(self):
        with self.trava:
            agora = time.monotonic()
            self.fichas = min(float(self.rajada), self.fichas + (agora - self.ultimo) * self.por_segundo)
            self.ultimo = agora
            if self.fichas >= 1:
                self.fichas -= 1
                return True
            self.descartadas += 1
            return False

    def resumo_devido(self):
        """Quantas descartadas devem ser resumidas agora (no máximo uma vez a cada 10 s por papel); 0 se não é hora."""
        with self.trava:
            agora = time.monotonic()
            if self.descartadas and agora - self.ultimo_resumo >= 10:
                n, self.descartadas, self.ultimo_resumo = self.descartadas, 0, agora
                return n
            return 0


class Servidor(socketserver.ThreadingUnixStreamServer):
    request_queue_size = 128          # o padrão (5) faz clientes em rajada receberem EAGAIN no connect em vez de uma recusa controlada (429)
    daemon_threads = True

    def __init__(self, caminho, spec, chave, upstream=None, logd_socket=None, permitir_http=False, proxy=None, ca_arquivo=None):
        self.origens = {spec["contas"][p["conta"]]: nome for nome, p in spec["papeis"].items()}
        self.chave = chave
        self.alvo = validar_upstream(upstream or spec["rede"]["upstream"], spec, permitir_http)
        self.proxy = proxy
        self.tls = contexto_tls(ca_arquivo)
        self.permitidos = frozenset(spec["rede"]["caminhos_permitidos"])
        self.logd = logd_socket or spec["servicos"]["logd_socket"]
        self.uid_log = spec["contas"][spec["servicos"]["conta_log"]]
        self.limite = threading.BoundedSemaphore(MAX_SIMULTANEAS)
        self.por_papel = {nome: threading.BoundedSemaphore(MAX_POR_PAPEL) for nome in spec["papeis"]}
        self.taxa = {nome: Taxa(*TAXA_POR_PAPEL) for nome in spec["papeis"]}
        Path(caminho).unlink(missing_ok=True)
        antiga = os.umask(0o117)                     # nunca existe janela com o socket acessível a outros
        try:
            super().__init__(str(caminho), Manipulador)
        finally:
            os.umask(antiga)
        os.chown(caminho, -1, spec["grupos"][spec["servicos"]["grupo_socket"]])
        os.chmod(caminho, 0o660)


class Manipulador(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"          # uma requisição por conexão; o corpo termina no fechamento
    server_version = "ppp-gateway"
    timeout = PRAZO_LEITURA                # vale para cada operação no socket do cliente (anti-gotejamento)

    def log_message(self, *_):             # nada de log do http.server (poderia vazar caminhos/cabeçalhos)
        pass

    def address_string(self):
        return "unix"

    def _auditar(self, papel, evento, **campos):
        return logd.enviar(self.server.logd, {"tipo": "rede", "papel": papel, "evento": evento, **campos}, uid_esperado=self.server.uid_log)

    def _responder(self, codigo, texto):
        corpo = (texto + "\n").encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def _recusar(self, codigo, texto):
        """Recusa sem encaminhar. Drena (limitado) o corpo declarado para o cliente receber o STATUS e não um reset de conexão."""
        self._responder(codigo, texto)
        try:
            self.connection.settimeout(1.0)
            declarado = self.headers.get("Content-Length", "")
            falta = min(int(declarado), 65536) if declarado.isdigit() else 0
            fim = time.monotonic() + 1.0
            while falta > 0 and time.monotonic() < fim:
                bloco = self.rfile.read(min(falta, 4096))
                if not bloco:
                    break
                falta -= len(bloco)
        except (OSError, ValueError):
            pass

    def _ler_exato(self, n, limite):
        """Lê exatamente n bytes em blocos, com prazo TOTAL (o gotejamento não prende o slot)."""
        partes, falta = [], n
        while falta:
            if time.monotonic() > limite:
                raise ValueError("prazo total de leitura esgotado")
            bloco = self.rfile.read(min(falta, 65536))
            if not bloco:
                raise ValueError("corpo truncado")
            partes.append(bloco)
            falta -= len(bloco)
        return b"".join(partes)

    def _corpo(self):
        """Corpo estrito: Content-Length só dígitos, uma única vez; chunked só em hexadecimal puro; nunca os dois."""
        limite = time.monotonic() + PRAZO_TOTAL_LEITURA
        cls = self.headers.get_all("Content-Length") or []
        tes = self.headers.get_all("Transfer-Encoding") or []
        if len(cls) > 1 or len(tes) > 1 or (cls and tes):
            raise ValueError("cabeçalhos de tamanho ambíguos")
        if tes:
            if tes[0].strip().lower() != "chunked":
                raise ValueError("Transfer-Encoding não suportado")
            partes, total = [], 0
            while True:
                linha = self.rfile.readline(64).strip().split(b";")[0].strip()
                if not HEX.match(linha):
                    raise ValueError("tamanho de bloco inválido")
                tamanho = int(linha, 16)
                if tamanho == 0:
                    self.rfile.readline(64)
                    break
                total += tamanho
                if total > LIMITE_CORPO:
                    raise ValueError("corpo grande demais")
                partes.append(self._ler_exato(tamanho, limite))
                self.rfile.readline(4)
            return b"".join(partes)
        if not cls:
            return b""
        if not DIGITOS.match(cls[0].strip()):
            raise ValueError("Content-Length inválido")
        tamanho = int(cls[0].strip())
        if tamanho > LIMITE_CORPO:
            raise ValueError("corpo grande demais")
        return self._ler_exato(tamanho, limite)

    def _tratar(self):
        inicio = time.monotonic()
        pid, uid, gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        papel = self.server.origens.get(uid)
        bruto = self.path
        partes = urllib.parse.urlsplit(bruto) if bruto.startswith("/") and not bruto.startswith("//") else None
        caminho = partes.path if partes else bruto[:200]
        if papel is None:
            self._auditar("desconhecido", "negado", motivo="uid sem papel", metodo=self.command, caminho=caminho[:200])
            return self._recusar(403, "chamador não autorizado")
        valido = (partes is not None and self.command == "POST" and CAMINHO_SEGURO.match(caminho) and ".." not in caminho.split("/")
                  and caminho in self.server.permitidos)
        if not valido:
            self._auditar(papel, "negado", motivo="destino ou método fora da lista", metodo=self.command, caminho=caminho[:200])
            return self._recusar(403, "destino não permitido pelo gateway")
        if not self.server.taxa[papel].permite():
            n = self.server.taxa[papel].resumo_devido()
            if n:
                self._auditar(papel, "negado", motivo=f"taxa excedida ({n} requisições descartadas desde o último resumo)", metodo=self.command)
            return self._recusar(429, "taxa excedida")
        if not self.server.por_papel[papel].acquire(blocking=False):
            self._auditar(papel, "negado", motivo="limite de conexões do papel", metodo=self.command, caminho=caminho)
            return self._recusar(429, "limite de conexões do papel")
        try:
            if not self.server.limite.acquire(blocking=False):
                self._auditar(papel, "negado", motivo="limite global de conexões", metodo=self.command, caminho=caminho)
                return self._recusar(429, "limite global de conexões")
            try:
                self._encaminhar(papel, caminho, partes, inicio)
            finally:
                self.server.limite.release()
        finally:
            self.server.por_papel[papel].release()

    def _encaminhar(self, papel, caminho, partes, inicio):
        try:
            corpo = self._corpo()
        except (ValueError, OSError):
            self._auditar(papel, "negado", motivo="corpo inválido ou grande demais", metodo=self.command, caminho=caminho)
            return self._responder(400, "corpo inválido")
        if not self._auditar(papel, "inicio", metodo=self.command, caminho=caminho, bytes_req=len(corpo)):
            return self._responder(503, "registro de auditoria indisponível; nada foi enviado")
        self.connection.settimeout(PRAZO_ESCRITA_CLIENTE)
        status, enviados = 502, 0
        try:
            cab = {k: v for k, v in self.headers.items() if k.lower().startswith(CABECALHOS_ENCAMINHADOS)}
            cab["x-api-key"] = self.server.chave
            cab["Content-Length"] = str(len(corpo))
            alvo = self.server.alvo
            if alvo.scheme == "https" and self.server.proxy:
                p_host, p_porta, p_cab = self.server.proxy
                con = http.client.HTTPSConnection(p_host, p_porta, timeout=TEMPO_UPSTREAM, context=self.server.tls)
                con.set_tunnel(alvo.hostname, alvo.port or 443, headers=p_cab)      # CONNECT; o TLS é negociado com o destino, não com o proxy
            elif alvo.scheme == "https":
                con = http.client.HTTPSConnection(alvo.hostname, alvo.port, timeout=TEMPO_UPSTREAM, context=self.server.tls)
            else:
                con = http.client.HTTPConnection(alvo.hostname, alvo.port, timeout=TEMPO_UPSTREAM)
            try:
                destino = caminho + (("?" + partes.query) if partes.query else "")
                con.request(self.command, destino, body=corpo or None, headers=cab)
                resp = con.getresponse()
                status = resp.status
                self.send_response(status)
                for k, v in resp.getheaders():
                    if k.lower() not in DESCARTAR_NA_SAIDA:
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
    ap.add_argument("--permitir-http-de-teste", action="store_true", help="SOMENTE testes locais: aceita upstream http/outro host")
    ap.add_argument("--chave-arquivo")
    ap.add_argument("--chave-fd", type=int)
    ap.add_argument("--proxy-arquivo", help="arquivo 0600 do serviço com http://[usuario:senha@]host:porta (saída por CONNECT)")
    ap.add_argument("--ca-arquivo", help="AC adicional (PEM) para o certificado do destino; a verificação nunca é desligada")
    a = ap.parse_args(argv)
    if os.geteuid() == 0:
        raise SystemExit("o gateway não executa como root")
    endurecer_processo()
    spec = B.carregar(a.spec)
    problemas = B.validar(spec)
    if problemas:
        raise SystemExit("papeis.json inválido: " + "; ".join(problemas))
    chave = ler_chave(a.chave_arquivo, a.chave_fd)
    proxy = ler_proxy(a.proxy_arquivo) if a.proxy_arquivo else None
    srv = Servidor(a.socket or spec["servicos"]["gateway_socket"], spec, chave, a.upstream, a.logd_socket, a.permitir_http_de_teste,
                   proxy, a.ca_arquivo)
    print("gateway pronto", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
