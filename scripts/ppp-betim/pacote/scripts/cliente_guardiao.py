"""Cliente do guardião (GOV-03). Único meio pelo qual agentes registram premissas.

O cliente não envia identidade: o guardião a obtém do kernel pelo socket.
"""
import json
import socket

SOCKET_PADRAO = "/run/ppp-betim/guardiao.sock"


class ErroGuardiao(Exception):
    def __init__(self, tipo, mensagem):
        super().__init__(f"{tipo}: {mensagem}")
        self.tipo = tipo


def chamar(pedido, caminho_socket=SOCKET_PADRAO, timeout=10):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conexao:
        conexao.settimeout(timeout)
        conexao.connect(str(caminho_socket))
        conexao.sendall(json.dumps(pedido, ensure_ascii=False).encode("utf-8") + b"\n")
        resposta = b""
        while not resposta.endswith(b"\n"):
            bloco = conexao.recv(65536)
            if not bloco:
                break
            resposta += bloco
    dados = json.loads(resposta)
    if not dados.get("ok"):
        raise ErroGuardiao(dados.get("erro"), dados.get("mensagem"))
    return dados["resultado"]


def propor(premissa, **kw):
    return chamar({"op": "propor", "premissa": premissa}, **kw)


def registrar_aprovacao(aprovacao, **kw):
    return chamar({"op": "registrar_aprovacao", "aprovacao": aprovacao}, **kw)


def exportar_versao(premissa_id, versao, **kw):
    return chamar({"op": "exportar_versao", "id": premissa_id, "versao": versao}, **kw)


def estado(premissa_id, versao, **kw):
    return chamar({"op": "estado", "id": premissa_id, "versao": versao}, **kw)
