"""Ancoragem do histórico contra rollback (GOV-03).

O guardião emite checkpoints encadeados e assinados com o estado de todas as
premissas (hashes de cada versão e de cada aprovação). Cópias guardadas fora
do alcance do guardião e do agente — armazenamento WORM com retenção,
repositório remoto com branch protegida, carimbo de tempo RFC 3161 — permitem
detectar exclusão ou reversão de qualquer item já ancorado, mesmo que o host
do guardião seja comprometido. É um controle DETECTIVO: não impede a remoção,
e o que ocorrer depois do último checkpoint ancorado não é coberto.
"""
from datetime import datetime, timezone

import aprovacao
from governanca import PADRAO_PREMISSA, canonico
from premissas_repositorio import sha256


class RollbackDetectado(Exception):
    """O estado atual não contém o que um checkpoint ancorado registrou."""


def chave_hex(chave_privada):
    from cryptography.hazmat.primitives import serialization
    return chave_privada.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def estado_atual(repo):
    estado = {}
    if not repo.premissas.is_dir():
        return estado
    for diretorio in sorted(repo.premissas.iterdir()):
        if not diretorio.is_dir() or not PADRAO_PREMISSA.fullmatch(diretorio.name):
            continue
        cadeia = repo.historico(diretorio.name)
        aprovacoes = {}
        for n, _, _ in cadeia:
            arquivo = diretorio / f"v{n}.aprovacao.json"
            if arquivo.exists():
                aprovacoes[str(n)] = sha256(arquivo.read_bytes())
        estado[diretorio.name] = {"versoes": [h for _, h, _ in cadeia], "aprovacoes": aprovacoes}
    return estado


def emitir_checkpoint(repo, chave_privada, anterior=None):
    payload = {
        "tipo": "checkpoint-premissas", "formato": 1,
        "seq": 1 if anterior is None else anterior["payload"]["seq"] + 1,
        "anterior": None if anterior is None else sha256(canonico(anterior)),
        "emitido_em": datetime.now(timezone.utc).isoformat(),
        "estado": estado_atual(repo),
    }
    return aprovacao.assinar(payload, chave_privada)


def verificar_checkpoint(repo, checkpoint, chave_publica_hex, anterior=None):
    """Confere assinatura, encadeamento e se o estado atual preserva o ancorado."""
    try:
        payload = checkpoint["payload"]
        valido = aprovacao.verificar_assinatura(chave_publica_hex, checkpoint["assinatura"],
                                                canonico(payload))
        estado_ancorado = payload["estado"]
        encadeado = anterior is None or payload["anterior"] == sha256(canonico(anterior))
    except (KeyError, TypeError) as erro:
        raise RollbackDetectado("Checkpoint malformado") from erro
    if not valido:
        raise RollbackDetectado("Checkpoint sem assinatura válida do guardião")
    if not encadeado:
        raise RollbackDetectado("Cadeia de checkpoints rompida")
    atual = estado_atual(repo)
    for premissa_id, ancorado in estado_ancorado.items():
        corrente = atual.get(premissa_id)
        if corrente is None:
            raise RollbackDetectado(f"{premissa_id}: premissa ancorada ausente")
        if corrente["versoes"][:len(ancorado["versoes"])] != ancorado["versoes"]:
            raise RollbackDetectado(f"{premissa_id}: versão ancorada removida ou alterada")
        for n, hash_aprovacao in ancorado["aprovacoes"].items():
            if corrente["aprovacoes"].get(n) != hash_aprovacao:
                raise RollbackDetectado(f"{premissa_id} v{n}: aprovação ancorada removida")
    return True
