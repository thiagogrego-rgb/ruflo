"""Série crescente do cadastro de aprovadores e referência externa (GOV-04).

Problema (R9): o cadastro é assinado, mas nada impede reapresentar um cadastro ANTIGO,
igualmente assinado, que ainda inclua um aprovador depois revogado.

Controle: o cadastro carrega `serie` (inteiro crescente, dentro dos bytes assinados). Um
cadastro só é aceito se `serie` não for inferior ao PISO, que é o maior entre:

1. `serie_minima` da REFERÊNCIA EXTERNA, assinada pela raiz de governança e entregue por
   meio protegido, fora do alcance dos agentes e, idealmente, do host do guardião;
2. a MARCA D'ÁGUA persistida pelo guardião (maior série já aceita).

Além disso, a mesma série nunca pode aparecer com conteúdo diferente (hash divergente), e a
série nunca diminui: reverter um aprovador exige NOVO cadastro, assinado, com série maior
(procedimento humano em governanca/GOV-04-robustez-nucleo.md).

Limites honestos: a referência é um arquivo; quem consegue substituí-la por uma versão
antiga assinada (ex.: `root` do host, se ela estiver no mesmo host) anula a proteção. Sua
efetividade depende de residir em meio que o host do guardião e o agente não reescrevem.
"""
import json
import os
import secrets
from pathlib import Path

from aprovacao import AutorizacaoIndisponivel, verificar_assinatura
from governanca import ValidacaoIndisponivel, canonico, carregar_validador, erros_schema

SERIE_MAXIMA = 2 ** 53 - 1


class ReferenciaIndisponivel(AutorizacaoIndisponivel):
    """Referência externa ausente, ilegível, malformada ou sem assinatura válida da raiz."""


class EstadoDeSerieCorrompido(AutorizacaoIndisponivel):
    """Marca d'água ilegível; exige procedimento humano de recuperação."""


class SerieAusente(AutorizacaoIndisponivel):
    """Cadastro sem número de série válido."""


class RetrocessoDeSerie(AutorizacaoIndisponivel):
    """Cadastro com série inferior ao piso: possível rollback."""


class SerieConflitante(AutorizacaoIndisponivel):
    """Mesma série apresentada com conteúdo diferente do conhecido."""


def _fsync_diretorio(diretorio):
    if os.name == "posix":
        fd = os.open(diretorio, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def substituir_atomico(destino, conteudo):
    """Troca o conteúdo de `destino` de forma atômica; uma queda deixa o antigo ou o novo."""
    destino = Path(destino)
    destino.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporario = destino.with_name(f".{destino.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temporario, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as arquivo:
            arquivo.write(conteudo)
            arquivo.flush()
            os.fsync(arquivo.fileno())
        os.replace(temporario, destino)
    finally:
        temporario.unlink(missing_ok=True)
    _fsync_diretorio(destino.parent)


class PoliticaSerie:
    def __init__(self, referencia, estado, chave_raiz_hex):
        self.referencia = Path(referencia)
        self.estado = Path(estado)
        self.chave_raiz = chave_raiz_hex
        self.ultima = None            # (serie, sha256) do cadastro validado mais recentemente

    def carregar_referencia(self):
        """Payload da referência, depois de validar formato e assinatura da raiz."""
        try:
            dados = json.loads(self.referencia.read_bytes())
            erros = erros_schema(carregar_validador("referencia-serie.schema.json"), dados)
        except (OSError, ValueError, ValidacaoIndisponivel) as erro:
            raise ReferenciaIndisponivel(
                f"Referência externa de série ausente ou ilegível: {erro}") from erro
        if erros:
            raise ReferenciaIndisponivel("Referência externa malformada: " + "; ".join(erros))
        if not verificar_assinatura(self.chave_raiz, dados["assinatura"], canonico(dados["payload"])):
            raise ReferenciaIndisponivel("Referência externa sem assinatura válida da raiz")
        return dados["payload"]

    def ler_estado(self):
        if not self.estado.exists():
            return None
        try:
            dados = json.loads(self.estado.read_bytes())
            serie, sha = dados["serie"], dados["sha256"]
            valido = (isinstance(dados, dict) and set(dados) == {"serie", "sha256"}
                      and isinstance(serie, int) and not isinstance(serie, bool)
                      and 1 <= serie <= SERIE_MAXIMA
                      and isinstance(sha, str) and len(sha) == 64
                      and all(c in "0123456789abcdef" for c in sha))
        except (OSError, ValueError, KeyError, TypeError) as erro:
            raise EstadoDeSerieCorrompido(f"Marca d'água de série ilegível: {erro}") from erro
        if not valido:
            raise EstadoDeSerieCorrompido("Marca d'água de série malformada")
        return dados

    def validar(self, serie, sha256_registro):
        """Aceita (e registra) o cadastro ou levanta uma subclasse de AutorizacaoIndisponivel."""
        if isinstance(serie, bool) or not isinstance(serie, int) or not 1 <= serie <= SERIE_MAXIMA:
            raise SerieAusente("Cadastro sem número de série válido")
        referencia = self.carregar_referencia()
        estado = self.ler_estado()
        piso = max(referencia["serie_minima"], estado["serie"] if estado else 0)
        if serie < piso:
            raise RetrocessoDeSerie(f"Cadastro com série {serie} abaixo do piso {piso}: possível rollback")
        if serie == referencia["serie_minima"] and sha256_registro != referencia["sha256_cadastro"]:
            raise SerieConflitante(f"Série {serie} com conteúdo diferente do fixado pela referência externa")
        if estado and serie == estado["serie"] and sha256_registro != estado["sha256"]:
            raise SerieConflitante(f"Série {serie} já aceita com outro conteúdo")
        if estado is None or serie > estado["serie"]:
            substituir_atomico(self.estado, canonico({"serie": serie, "sha256": sha256_registro}))
        self.ultima = (serie, sha256_registro)
        return serie

    def recuperar(self):
        """Remove temporários de gravações interrompidas da marca d'água."""
        removidos = sorted(self.estado.parent.glob(f".{self.estado.name}.*.tmp"))
        for temporario in removidos:
            temporario.unlink()
        return removidos
