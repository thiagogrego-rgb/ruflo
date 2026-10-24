"""Armazenamento append-only e versionado de premissas (GOV-01).

Layout em `registros/premissas/<ID>/`:
  v<N>.json            versão imutável (envelope canônico com hash da anterior)
  v<N>.aprovacao.json  aprovação humana assinada da versão N

Garantias implementadas em código:
- nenhum arquivo é sobrescrito: a gravação usa link atômico, que falha se o destino existir;
- um arquivo nunca fica parcialmente gravado: escreve-se num temporário e só então se publica;
- o histórico forma uma cadeia de hashes, verificada a cada leitura;
- o status APROVADA só é reconhecido com assinatura válida (ver `aprovacao.py`).

A cadeia de hashes detecta alterações, mas não prova autoria: quem tem escrita
no diretório pode reescrever versões não aprovadas e recalcular a cadeia.
"""
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

import aprovacao
from governanca import PADRAO_PREMISSA, PremissaInvalida, canonico, validar_premissa

PADRAO_PROPONENTE = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}")
PADRAO_VERSAO = re.compile(r"v([1-9][0-9]*)\.json")


class ConflitoVersao(Exception):
    """A versão proposta já existe ou não é a sucessora da última registrada."""


class IntegridadeViolada(Exception):
    """O armazenamento foi alterado fora do fluxo autorizado ou está corrompido."""


def sha256(dados):
    return hashlib.sha256(dados).hexdigest()


def _fsync_diretorio(diretorio):
    if os.name == "posix":
        fd = os.open(diretorio, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def gravar_exclusivo(destino, conteudo):
    """Publica `conteudo` em `destino` de forma atômica, sem jamais sobrescrever."""
    destino = Path(destino)
    temporario = destino.with_name(f".{destino.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temporario, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as arquivo:
            arquivo.write(conteudo)
            arquivo.flush()
            os.fsync(arquivo.fileno())
        os.link(temporario, destino)
    finally:
        temporario.unlink(missing_ok=True)
    os.chmod(destino, 0o444)
    _fsync_diretorio(destino.parent)


class RepositorioPremissas:
    def __init__(self, registros, registro_aprovadores=aprovacao.REGISTRO_PADRAO,
                 chave_raiz=None):
        self.premissas = Path(registros) / "premissas"
        self.fontes = Path(registros) / "fontes"
        self.registro_aprovadores = registro_aprovadores
        self.chave_raiz = chave_raiz

    def _diretorio(self, premissa_id):
        if not isinstance(premissa_id, str) or not PADRAO_PREMISSA.fullmatch(premissa_id):
            raise PremissaInvalida(f"Identificador de premissa inválido: {premissa_id!r}")
        return self.premissas / premissa_id

    def _versoes(self, premissa_id):
        diretorio = self._diretorio(premissa_id)
        if not diretorio.is_dir():
            return []
        return sorted(int(m.group(1)) for f in diretorio.iterdir()
                      if (m := PADRAO_VERSAO.fullmatch(f.name)))

    def historico(self, premissa_id):
        """Lista verificada de (versão, sha256, envelope). Levanta IntegridadeViolada."""
        numeros = self._versoes(premissa_id)
        if numeros != list(range(1, len(numeros) + 1)):
            raise IntegridadeViolada(f"{premissa_id}: sequência de versões com lacuna {numeros}")
        cadeia, anterior = [], None
        for n in numeros:
            bruto = (self._diretorio(premissa_id) / f"v{n}.json").read_bytes()
            try:
                envelope = json.loads(bruto)
                if canonico(envelope) != bruto:
                    raise ValueError("serialização não canônica")
                conteudo = envelope["premissa"]
                validar_premissa(conteudo)
                coerente = (conteudo["id"] == premissa_id and conteudo["versao"] == n
                            and envelope["hash_anterior"] == anterior
                            and set(envelope) == {"formato", "premissa", "proponente",
                                                  "registrada_em", "hash_anterior"})
            except (ValueError, KeyError, TypeError, PermissionError) as erro:
                raise IntegridadeViolada(f"{premissa_id} v{n}: conteúdo inválido ({erro})") from erro
            if not coerente:
                raise IntegridadeViolada(f"{premissa_id} v{n}: cadeia de versões rompida")
            anterior = sha256(bruto)
            cadeia.append((n, anterior, envelope))
        return cadeia

    def propor(self, premissa, proponente):
        """Registra nova versão. Retorna o SHA-256 da versão gravada."""
        validar_premissa(premissa, fontes_dir=self.fontes)
        if not isinstance(proponente, str) or not PADRAO_PROPONENTE.fullmatch(proponente):
            raise PremissaInvalida(f"Proponente inválido: {proponente!r}")
        for dependencia in premissa.get("dependencias", []):
            if not self._versoes(dependencia):
                raise PremissaInvalida(f"Dependência inexistente: {dependencia}")
        cadeia = self.historico(premissa["id"])
        esperada = len(cadeia) + 1
        if premissa["versao"] != esperada:
            raise ConflitoVersao(
                f"{premissa['id']}: versão {premissa['versao']} recusada; a próxima é {esperada}")
        envelope = {
            "formato": 1, "premissa": premissa, "proponente": proponente,
            "registrada_em": datetime.now(timezone.utc).isoformat(),
            "hash_anterior": cadeia[-1][1] if cadeia else None,
        }
        conteudo = canonico(envelope)
        diretorio = self._diretorio(premissa["id"])
        diretorio.mkdir(parents=True, exist_ok=True)
        try:
            gravar_exclusivo(diretorio / f"v{esperada}.json", conteudo)
        except FileExistsError as erro:
            raise ConflitoVersao(
                f"{premissa['id']} v{esperada} já registrada; registros não são sobrescritos") from erro
        return sha256(conteudo)

    def _verificar_aprovacao(self, premissa_id, n, hash_versao, envelope, dados):
        return aprovacao.verificar(
            dados, premissa_id=premissa_id, versao=n, sha256_versao=hash_versao,
            proponente=envelope["proponente"], produto=envelope["premissa"]["produto"],
            registro=self.registro_aprovadores, chave_raiz=self.chave_raiz)

    def registrar_aprovacao(self, dados):
        """Verifica e arquiva uma aprovação assinada. Nunca substitui outra."""
        try:
            premissa_id, n = dados["payload"]["premissa_id"], dados["payload"]["versao"]
        except (KeyError, TypeError) as erro:
            raise aprovacao.AprovacaoInvalida("Aprovação sem identificação da versão") from erro
        cadeia = self.historico(premissa_id)
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= len(cadeia):
            raise aprovacao.AprovacaoInvalida(f"{premissa_id}: versão {n!r} inexistente")
        _, hash_versao, envelope = cadeia[n - 1]
        aprovador = self._verificar_aprovacao(premissa_id, n, hash_versao, envelope, dados)
        try:
            gravar_exclusivo(self._diretorio(premissa_id) / f"v{n}.aprovacao.json", canonico(dados))
        except FileExistsError as erro:
            raise ConflitoVersao(f"{premissa_id} v{n} já possui aprovação registrada") from erro
        return aprovador["id"]

    def estado(self, premissa_id, n):
        """'APROVADA' ou 'PROPOSTA'. Falha fechada se houver adulteração ou falha de verificação."""
        cadeia = self.historico(premissa_id)
        if not 1 <= n <= len(cadeia):
            raise PremissaInvalida(f"{premissa_id}: versão {n} inexistente")
        _, hash_versao, envelope = cadeia[n - 1]
        arquivo = self._diretorio(premissa_id) / f"v{n}.aprovacao.json"
        if not arquivo.exists():
            return "PROPOSTA"
        try:
            dados = json.loads(arquivo.read_bytes())
        except ValueError as erro:
            raise IntegridadeViolada(f"{premissa_id} v{n}: aprovação corrompida") from erro
        self._verificar_aprovacao(premissa_id, n, hash_versao, envelope, dados)
        return "APROVADA"

    def ler_aprovada(self, premissa_id):
        """Conteúdo da versão aprovada mais recente, verificada. Bloqueia se não houver."""
        for n, _, envelope in reversed(self.historico(premissa_id)):
            if self.estado(premissa_id, n) == "APROVADA":
                return envelope["premissa"]
        raise PermissionError(f"{premissa_id}: nenhuma versão com aprovação verificável")

    def recuperar(self):
        """Remove temporários de gravações interrompidas. Executar sem gravações em curso."""
        if not self.premissas.is_dir():
            return []
        removidos = sorted(self.premissas.glob("*/.*.tmp"))
        for temporario in removidos:
            temporario.unlink()
        return removidos
