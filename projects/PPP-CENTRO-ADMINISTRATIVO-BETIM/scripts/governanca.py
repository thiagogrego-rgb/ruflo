"""Validações iniciais. Aprovação humana permanece bloqueada."""
import json
from pathlib import Path

def validar_premissa(p):
    obrigatorios = ("id","versao","produto","natureza",
                    "unidade","status")
    faltantes = [x for x in obrigatorios if x not in p]
    if faltantes:
        raise ValueError(f"Campos ausentes: {faltantes}")
    if not p["unidade"]:
        raise ValueError("Unidade ausente")
    if p["natureza"] not in ("OBSERVADO","CALCULADO","HIPOTESE"):
        raise ValueError("Natureza inválida")
    if p["status"] not in ("PROPOSTA","EM_VERIFICACAO",
                          "VERIFICADA","APROVADA",
                          "REJEITADA","SUBSTITUIDA"):
        raise ValueError("Status inválido")
    if p["natureza"] == "HIPOTESE":
        if not p.get("justificativa_hipotese"):
            raise ValueError("Hipótese sem justificativa")
    elif not p.get("fonte_id"):
        raise ValueError("Fonte obrigatória")
    if p["status"] == "APROVADA":
        raise PermissionError("Aprovação humana não configurada")
    return True

def aprovar_decisao(*args, **kwargs):
    raise PermissionError(
        "Mecanismo externo de autorização não configurado"
    )

def autorizar_publicacao(*args, **kwargs):
    raise PermissionError(
        "Publicação bloqueada até autorização humana verificável"
    )
