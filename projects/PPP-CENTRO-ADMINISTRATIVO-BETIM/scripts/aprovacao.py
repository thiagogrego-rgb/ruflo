"""Verificação de aprovações humanas assinadas com Ed25519 (GOV-02).

Uma aprovação só é aceita se a assinatura confere com a chave pública de um
aprovador humano ativo do registro, com o papel e o produto adequados, e se o
payload estiver vinculado exatamente à versão aprovada (id, versão e SHA-256).
Qualquer falha do mecanismo resulta em bloqueio (fail-closed).
"""
import base64
import binascii
import hashlib
import json
from pathlib import Path

from governanca import (RAIZ, ValidacaoIndisponivel, canonico,
                        carregar_validador, erros_schema)

PAPEL_PREMISSAS = "aprovador-premissas"
REGISTRO_PADRAO = RAIZ / "governanca" / "aprovadores.json"


class AutorizacaoIndisponivel(PermissionError):
    """O mecanismo de autorização não pôde ser verificado; operação bloqueada."""


class AprovacaoInvalida(PermissionError):
    """A aprovação apresentada não é válida para a versão indicada."""


def payload_aprovacao(premissa_id, versao, sha256_versao, aprovador_id, emitida_em):
    return {
        "tipo": "aprovacao-premissa", "formato": 1,
        "premissa_id": premissa_id, "versao": versao,
        "sha256_versao": sha256_versao, "aprovador_id": aprovador_id,
        "emitida_em": emitida_em, "decisao": "APROVADA",
    }


def assinar(payload, chave_privada):
    """Assina o payload. Uso exclusivo do aprovador humano, fora do ambiente do agente."""
    assinatura = chave_privada.sign(canonico(payload))
    return {"payload": payload, "assinatura": base64.b64encode(assinatura).decode("ascii")}


def verificar_assinatura(chave_publica_hex, assinatura_b64, mensagem):
    """True somente se a assinatura Ed25519 conferir. Levanta AutorizacaoIndisponivel."""
    chave = _chave_publica(chave_publica_hex)
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError as erro:
        raise AutorizacaoIndisponivel("Dependência 'cryptography' ausente") from erro
    try:
        chave.verify(base64.b64decode(assinatura_b64, validate=True), mensagem)
    except (InvalidSignature, binascii.Error, ValueError):
        return False
    return True


def carregar_aprovadores(caminho=REGISTRO_PADRAO, chave_raiz=None, politica_serie=None):
    """Com `chave_raiz` (hex), exige `<caminho>.sig` assinado pela raiz de governança.

    Com `politica_serie` (GOV-04), exige também série crescente verificada contra a
    referência externa; isso só tem sentido com cadastro assinado, então `chave_raiz` é obrigatória.
    """
    if politica_serie is not None and chave_raiz is None:
        raise AutorizacaoIndisponivel("Política de série exige cadastro assinado pela raiz de governança")
    try:
        validador = carregar_validador("aprovadores.schema.json")
        bruto = Path(caminho).read_bytes()
        if chave_raiz is not None:
            assinatura = Path(f"{caminho}.sig").read_text(encoding="ascii").strip()
            if not verificar_assinatura(chave_raiz, assinatura, bruto):
                raise AutorizacaoIndisponivel(
                    "Registro de aprovadores sem assinatura válida da raiz de governança")
        dados = json.loads(bruto)
    except (ValidacaoIndisponivel, OSError, ValueError) as erro:
        raise AutorizacaoIndisponivel(f"Registro de aprovadores indisponível: {erro}") from erro
    erros = erros_schema(validador, dados)
    if erros:
        raise AutorizacaoIndisponivel("Registro de aprovadores inválido: " + "; ".join(erros))
    ids = [a["id"] for a in dados["aprovadores"]]
    if len(ids) != len(set(ids)):
        raise AutorizacaoIndisponivel("Registro de aprovadores com identificadores duplicados")
    if politica_serie is not None:
        politica_serie.validar(dados.get("serie"), hashlib.sha256(bruto).hexdigest())
    return {a["id"]: a for a in dados["aprovadores"] if a["ativo"]}


def _chave_publica(hex_chave):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_chave))
    except ImportError as erro:
        raise AutorizacaoIndisponivel("Dependência 'cryptography' ausente") from erro
    except ValueError as erro:
        raise AutorizacaoIndisponivel("Chave pública inválida no registro") from erro


def verificar(aprovacao, *, premissa_id, versao, sha256_versao, proponente, produto,
              registro=REGISTRO_PADRAO, chave_raiz=None, politica_serie=None):
    """Retorna o aprovador se a aprovação for válida; caso contrário, levanta PermissionError."""
    try:
        erros = erros_schema(carregar_validador("aprovacao.schema.json"), aprovacao)
    except ValidacaoIndisponivel as erro:
        raise AutorizacaoIndisponivel(str(erro)) from erro
    if erros:
        raise AprovacaoInvalida("Formato de aprovação inválido: " + "; ".join(erros))
    p = aprovacao["payload"]
    if (p["premissa_id"], p["versao"], p["sha256_versao"]) != (premissa_id, versao, sha256_versao):
        raise AprovacaoInvalida("Aprovação vinculada a outra premissa, versão ou conteúdo")
    aprovador = carregar_aprovadores(registro, chave_raiz, politica_serie).get(p["aprovador_id"])
    if aprovador is None:
        raise AprovacaoInvalida(f"Identidade não autorizada: {p['aprovador_id']}")
    if PAPEL_PREMISSAS not in aprovador["papeis"] or produto not in aprovador["produtos"]:
        raise AprovacaoInvalida(f"{p['aprovador_id']} não pode aprovar premissas de {produto}")
    if p["aprovador_id"] == proponente:
        raise AprovacaoInvalida("Segregação de funções: o proponente não pode aprovar")
    if not verificar_assinatura(aprovador["chave_publica_ed25519"],
                                aprovacao["assinatura"], canonico(p)):
        raise AprovacaoInvalida("Assinatura inválida para o aprovador declarado")
    return aprovador
