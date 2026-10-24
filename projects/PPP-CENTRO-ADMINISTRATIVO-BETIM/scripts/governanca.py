"""Validação de premissas pelo JSON Schema (GOV-01).

Aprovação de premissas só existe pelo fluxo assinado de `aprovacao.py`.
Decisões gerais e publicação permanecem bloqueadas.
"""
import json
import re
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
SCHEMAS = RAIZ / "governanca" / "schemas"
PADRAO_PREMISSA = re.compile(r"PREM-[0-9]{3,6}")
PADRAO_FONTE = re.compile(r"FONTE-[0-9]{3,6}")


class ValidacaoIndisponivel(RuntimeError):
    """O validador não pôde ser carregado; a operação deve ser bloqueada."""


class PremissaInvalida(ValueError):
    """A premissa viola o schema ou uma regra de integridade."""


def canonico(obj):
    """Serialização determinística usada em hashes e assinaturas."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def carregar_validador(nome_schema):
    try:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError
    except ImportError as erro:
        raise ValidacaoIndisponivel("Dependência 'jsonschema' ausente") from erro
    caminho = SCHEMAS / nome_schema
    try:
        schema = json.loads(caminho.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, ValueError, SchemaError) as erro:
        raise ValidacaoIndisponivel(f"Schema ilegível ou inválido: {caminho}") from erro
    return Draft202012Validator(schema)


def erros_schema(validador, dados):
    erros = sorted(validador.iter_errors(dados), key=lambda e: list(e.absolute_path))
    return ["/".join(map(str, e.absolute_path)) + ": " + e.message for e in erros]


def validar_premissa(p, fontes_dir=None):
    """Valida a premissa; com `fontes_dir`, exige que as fontes citadas existam."""
    if not isinstance(p, dict):
        raise PremissaInvalida("Premissa deve ser um objeto JSON")
    if p.get("status") == "APROVADA":
        raise PermissionError(
            "Status APROVADA não é declarável; decorre de aprovação humana assinada")
    erros = erros_schema(carregar_validador("premissa.schema.json"), p)
    if erros:
        raise PremissaInvalida("; ".join(erros))
    if p["id"] in p.get("dependencias", []):
        raise PremissaInvalida("Premissa não pode depender de si mesma")
    if fontes_dir is not None and p.get("fonte_id"):
        if not (Path(fontes_dir) / f"{p['fonte_id']}.json").is_file():
            raise PremissaInvalida(f"Fonte inexistente: {p['fonte_id']}")
    return True


def aprovar_decisao(*args, **kwargs):
    raise PermissionError(
        "Mecanismo externo de autorização não configurado"
    )


def autorizar_publicacao(*args, **kwargs):
    raise PermissionError(
        "Publicação bloqueada até autorização humana verificável"
    )
