"""Serviço guardião (GOV-03): única autoridade de escrita sobre premissas.

Executa com usuário de SO próprio, distinto do agente e de root. O agente não
tem escrita no armazenamento, no registro de aprovadores, na configuração nem
neste código; interage apenas pelo socket Unix. A identidade do proponente é
obtida do kernel (SO_PEERCRED), nunca da requisição.

    python3 -I -B guardiao.py /etc/ppp-betim/guardiao.json
"""
import json
import os
import socket
import socketserver
import stat
import struct
import sys
from pathlib import Path

CODIGO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODIGO / "scripts"))

import ancora  # noqa: E402
import aprovacao  # noqa: E402
from governanca import canonico, carregar_validador, erros_schema  # noqa: E402
from premissas_repositorio import RepositorioPremissas, gravar_exclusivo  # noqa: E402

LIMITE_REQUISICAO = 1 << 20
CAMPOS_PERMITIDOS = {"op", "premissa", "aprovacao", "id", "versao"}


class ConfiguracaoInsegura(RuntimeError):
    """O guardião recusa iniciar: a fronteira não estaria garantida."""


def exigir_protegido(caminho, uid_servico, recursivo=False):
    """Dono root ou o serviço e sem escrita por grupo/outros em todo o caminho.

    Diretórios com sticky bit e dono root (ex.: /tmp) são aceitos como ancestrais.
    """
    alvo = Path(caminho).resolve()
    for parte in [alvo, *alvo.parents]:
        st = parte.stat()
        gravavel = st.st_mode & 0o022
        sticky_root = stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX and st.st_uid == 0
        if st.st_uid not in (0, uid_servico) or (gravavel and not (parte != alvo and sticky_root)):
            raise ConfiguracaoInsegura(f"{parte} não está protegido contra escrita de terceiros")
    if recursivo and alvo.is_dir():
        for item in alvo.rglob("*"):
            st = item.lstat()
            if stat.S_ISLNK(st.st_mode) or st.st_uid not in (0, uid_servico) or st.st_mode & 0o022:
                raise ConfiguracaoInsegura(f"{item} não está protegido contra escrita de terceiros")


def carregar_configuracao(caminho):
    uid = os.getuid()
    if uid == 0 or os.geteuid() == 0:
        raise ConfiguracaoInsegura("O guardião não executa como root")
    exigir_protegido(caminho, uid)
    exigir_protegido(CODIGO, uid, recursivo=True)
    config = json.loads(Path(caminho).read_text(encoding="utf-8"))
    erros = erros_schema(carregar_validador("guardiao.schema.json"), config)
    if erros:
        raise ConfiguracaoInsegura("Configuração inválida: " + "; ".join(erros))
    exigir_protegido(config["aprovadores"], uid)
    exigir_protegido(f"{config['aprovadores']}.sig", uid)
    chave = Path(config["chave_privada_guardiao"])
    st = chave.stat()
    if st.st_uid != uid or st.st_mode & 0o077:
        raise ConfiguracaoInsegura("Chave do guardião deve pertencer ao serviço com modo 0600")
    for registros in (config["registros"], Path(config["socket"]).parent):
        exigir_protegido(registros, uid)
        if Path(registros).stat().st_uid != uid:
            raise ConfiguracaoInsegura(f"{registros} deve pertencer ao serviço")
    proponentes = {int(u): i for u, i in config["proponentes"].items()}
    ancoradores = set(config.get("ancoradores", []))
    if uid in proponentes or 0 in proponentes:
        raise ConfiguracaoInsegura("Proponente não pode ser root nem o próprio guardião")
    if ancoradores & (set(proponentes) | {uid}):
        raise ConfiguracaoInsegura("Ancorador não pode ser proponente nem o próprio guardião")
    aprovadores = aprovacao.carregar_aprovadores(config["aprovadores"],
                                                 config["chave_raiz_governanca"])
    if set(proponentes.values()) & set(aprovadores):
        raise ConfiguracaoInsegura("Identidades de proponentes e aprovadores devem ser disjuntas")
    return config, proponentes, ancoradores


class Guardiao:
    def __init__(self, caminho_config):
        from cryptography.hazmat.primitives import serialization
        self.config, self.proponentes, self.ancoradores = carregar_configuracao(caminho_config)
        self.repo = RepositorioPremissas(self.config["registros"], self.config["aprovadores"],
                                         self.config["chave_raiz_governanca"])
        self.chave = serialization.load_pem_private_key(
            Path(self.config["chave_privada_guardiao"]).read_bytes(), password=None)
        self.ultimo_checkpoint = Path(self.config["registros"]) / "ancora" / "ultimo.json"

    def executar(self, uid, pedido):
        """`uid` vem do kernel (SO_PEERCRED); nada no pedido altera a identidade ou o papel."""
        if uid in self.ancoradores:
            # Papel restrito: SOMENTE checkpoint, sem nenhum outro campo. Os conjuntos de
            # ancoradores e proponentes são disjuntos (verificado na configuração).
            if pedido != {"op": "checkpoint"}:
                raise PermissionError("Ancorador só pode solicitar checkpoint")
            return self.emitir_checkpoint()
        proponente = self.proponentes.get(uid)
        if proponente is None:
            raise PermissionError(f"uid {uid} não autorizado")
        if not isinstance(pedido, dict) or not set(pedido) <= CAMPOS_PERMITIDOS:
            raise PermissionError("Campos não permitidos; a identidade é atribuída pelo guardião")
        op = pedido.get("op")
        if op == "propor":
            return {"sha256": self.repo.propor(pedido.get("premissa"), proponente)}
        if op == "registrar_aprovacao":
            return {"aprovador": self.repo.registrar_aprovacao(pedido.get("aprovacao"))}
        if op == "estado":
            return self.repo.estado(pedido.get("id"), pedido.get("versao"))
        if op == "ler_aprovada":
            return self.repo.ler_aprovada(pedido.get("id"))
        if op == "exportar_versao":
            cadeia = self.repo.historico(pedido.get("id"))
            n = pedido.get("versao")
            if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= len(cadeia):
                raise ValueError("Versão inexistente")
            return {"envelope": cadeia[n - 1][2], "sha256": cadeia[n - 1][1]}
        # "checkpoint" é exclusivo do papel ancorador (ramo acima): proponentes não ancoram.
        raise PermissionError(f"Operação não permitida: {op!r}")

    def emitir_checkpoint(self):
        anterior = None
        if self.ultimo_checkpoint.exists():
            anterior = json.loads(self.ultimo_checkpoint.read_bytes())
            ancora.verificar_checkpoint(self.repo, anterior, ancora.chave_hex(self.chave))
        novo = ancora.emitir_checkpoint(self.repo, self.chave, anterior)
        self.ultimo_checkpoint.parent.mkdir(mode=0o700, exist_ok=True)
        destino = self.ultimo_checkpoint.with_name(f"seq-{novo['payload']['seq']}.json")
        gravar_exclusivo(destino, canonico(novo))
        temporario = self.ultimo_checkpoint.with_suffix(".tmp")
        temporario.write_bytes(canonico(novo))
        os.replace(temporario, self.ultimo_checkpoint)
        return novo


class Tratador(socketserver.StreamRequestHandler):
    timeout = 10

    def handle(self):
        credenciais = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                              struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", credenciais)
        try:
            linha = self.rfile.readline(LIMITE_REQUISICAO + 1)
            if len(linha) > LIMITE_REQUISICAO:
                raise ValueError("Requisição excede o limite")
            resposta = {"ok": True, "resultado": self.server.guardiao.executar(uid, json.loads(linha))}
        except Exception as erro:  # falha fechada: nada é gravado, o erro é devolvido
            resposta = {"ok": False, "erro": type(erro).__name__, "mensagem": str(erro)}
        self.wfile.write(canonico(resposta) + b"\n")


def servir(caminho_config):
    guardiao = Guardiao(caminho_config)
    caminho_socket = Path(guardiao.config["socket"])
    caminho_socket.unlink(missing_ok=True)
    os.umask(0o077)
    servidor = socketserver.UnixStreamServer(str(caminho_socket), Tratador)
    os.chmod(caminho_socket, 0o666)          # autorização por SO_PEERCRED, não por modo
    servidor.guardiao = guardiao
    print("PRONTO", flush=True)
    servidor.serve_forever()


if __name__ == "__main__":
    try:
        servir(sys.argv[1])
    except (ConfiguracaoInsegura, aprovacao.AutorizacaoIndisponivel, OSError, ValueError) as erro:
        print(f"RECUSADO: {erro}", file=sys.stderr, flush=True)
        sys.exit(3)
