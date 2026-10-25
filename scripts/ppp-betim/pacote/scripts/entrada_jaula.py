#!/usr/bin/env python3
"""Ponto de entrada DENTRO da jaula de rede (GOV-08): liga a sessão ao gateway sem dar rede ao agente.

Dentro do namespace de rede vazio só existe o loopback. Este script abre uma porta em 127.0.0.1, repassa cada conexão
ao socket Unix do gateway e entrega ao `claude` apenas `ANTHROPIC_BASE_URL` apontando para essa porta. A chave real nunca
entra no ambiente da sessão: o `ANTHROPIC_API_KEY` entregue é um marcador sem valor; o gateway o descarta e injeta a chave.

    python3 -I -B scripts/entrada_jaula.py --gateway /run/ppp-betim/gateway.sock -- claude [opções]
"""
import argparse
import ctypes
import os
import signal
import socket
import stat
import sys
import threading

PR_SET_PDEATHSIG = 1
MARCADOR = "gateway-local-sem-valor"
PERMITIDAS = ("PATH", "HOME", "TMPDIR", "LANG", "TERM", "PYTHONDONTWRITEBYTECODE", "PPP_PAPEL", "PPP_LOGD_SOCKET", "PPP_LOG_LEGADO")


def _copiar(origem, destino):
    try:
        while True:
            bloco = origem.recv(65536)
            if not bloco:
                break
            destino.sendall(bloco)
    except OSError:
        pass
    finally:
        for s in (origem, destino):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _atender(cliente, caminho):
    try:
        gw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        gw.connect(caminho)
    except OSError:
        cliente.close()
        return
    threading.Thread(target=_copiar, args=(gw, cliente), daemon=True).start()
    _copiar(cliente, gw)
    cliente.close()
    gw.close()


def servir(escuta, caminho):
    while True:
        try:
            cliente, _ = escuta.accept()
        except OSError:
            return
        threading.Thread(target=_atender, args=(cliente, caminho), daemon=True).start()


def rede_isolada():
    """True se o namespace de rede só tem o loopback (sem isso a ponte exporia o 127.0.0.1 do HOST com a identidade do papel)."""
    try:
        return {nome for _, nome in socket.if_nameindex()} <= {"lo"}      # interfaces do namespace ATUAL (/sys/class/net mostraria as do host)
    except OSError:
        return False


def preparar(caminho_gateway):
    """Abre o listener, bifurca o servidor e devolve (porta, env_extra). O pai segue e executa o comando."""
    escuta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    escuta.bind(("127.0.0.1", 0))
    escuta.listen(32)
    porta = escuta.getsockname()[1]
    pai = os.getpid()
    if os.fork() == 0:
        try:
            ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, signal.SIGKILL)     # morre junto com a sessão
        except (OSError, AttributeError):
            pass
        if os.getppid() != pai:
            os._exit(0)
        servir(escuta, caminho_gateway)
        os._exit(0)
    escuta.close()
    return porta


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--gateway", required=True)
    ap.add_argument("comando", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    comando = a.comando[1:] if a.comando[:1] == ["--"] else a.comando
    if not comando:
        raise SystemExit("informe o comando após --")
    try:
        if not stat.S_ISSOCK(os.stat(a.gateway).st_mode):
            raise OSError("não é socket")
    except OSError:
        raise SystemExit(f"gateway indisponível ({a.gateway}): sem rede, sem sessão")
    if not rede_isolada() and os.environ.get("PPP_PONTE_SEM_ISOLAMENTO_DE_TESTE") != "1":
        raise SystemExit("o namespace de rede não está isolado (há interface além de lo): a ponte exporia a rede do host; sessão recusada")
    porta = preparar(a.gateway)
    env = {k: v for k, v in os.environ.items() if k in PERMITIDAS}
    env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{porta}"
    env["ANTHROPIC_API_KEY"] = MARCADOR
    env["DISABLE_TELEMETRY"] = "1"
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    os.execvpe(comando[0], comando, env)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
