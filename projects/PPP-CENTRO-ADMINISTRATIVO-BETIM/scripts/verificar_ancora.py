#!/usr/bin/env python3
"""Verificador INDEPENDENTE de checkpoints ancorados (GOV-04).

Arquivo único, sem importar nada do projeto: depende só da biblioteca padrão e de
`cryptography` (verificação Ed25519). Foi escrito para rodar fora do host do guardião, por
um auditor, sobre cópias dos checkpoints guardadas em meio externo (WORM, repositório
protegido, carimbo de tempo). Somente LÊ arquivos; nunca escreve nem contata o guardião.

    verificar_ancora.py --chave-guardiao <64 hex> --checkpoints DIR_OU_ARQ [DIR_OU_ARQ ...]
                        [--inicio N] [--registros DIR] [--serie-minima N] [--json]

A chave pública do guardião deve vir de canal independente (não do mesmo meio dos
checkpoints). Verifica, por checkpoint: formato estrito e assinatura; na cadeia: seq contíguo,
encadeamento por hash e monotonicidade (nenhuma versão ou aprovação já ancorada desaparece ou
muda; a série do cadastro não diminui nem repete com outro conteúdo). Com `--registros`,
confere o armazenamento atual contra o último checkpoint; com `--serie-minima`, exige que o
último checkpoint ateste cadastro com série suficiente.

Saída: 0 = sem violações; 1 = violações; 2 = erro de uso ou de leitura.
Limites: só prova o que foi ancorado antes; o que ocorreu depois do último checkpoint
externo não é coberto, e uma chave do guardião comprometida permite forjar checkpoints.
"""
import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

HEX64 = re.compile(r"[0-9a-f]{64}")
ID_PREMISSA = re.compile(r"PREM-[0-9]{3,6}")
ARQUIVO_VERSAO = re.compile(r"v([1-9][0-9]*)\.json")
ARQUIVO_APROVACAO = re.compile(r"v([1-9][0-9]*)\.aprovacao\.json")
CHAVES_CHECKPOINT = {"tipo", "formato", "seq", "anterior", "emitido_em", "estado", "cadastro"}
OBRIGATORIAS = CHAVES_CHECKPOINT - {"cadastro"}


class ErroDeUso(Exception):
    pass


def canonico(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(dados):
    return hashlib.sha256(dados).hexdigest()


def _inteiro(valor, minimo=1):
    return isinstance(valor, int) and not isinstance(valor, bool) and valor >= minimo


def verificar_assinatura(chave_hex, assinatura_b64, mensagem):
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as erro:
        raise ErroDeUso("Dependência 'cryptography' ausente") from erro
    try:
        chave = Ed25519PublicKey.from_public_bytes(bytes.fromhex(chave_hex))
        chave.verify(base64.b64decode(assinatura_b64, validate=True), mensagem)
    except (InvalidSignature, binascii.Error, ValueError, TypeError):
        return False
    return True


def validar_formato(checkpoint):
    """Lista de problemas de formato (vazia se estruturalmente válido)."""
    if not isinstance(checkpoint, dict) or set(checkpoint) != {"payload", "assinatura"}:
        return ["checkpoint deve ter exatamente 'payload' e 'assinatura'"]
    payload, problemas = checkpoint["payload"], []
    if not isinstance(checkpoint["assinatura"], str) or not isinstance(payload, dict):
        return ["assinatura ou payload com tipo inválido"]
    chaves = set(payload)
    if not OBRIGATORIAS <= chaves or not chaves <= CHAVES_CHECKPOINT:
        return [f"chaves do payload inesperadas: {sorted(chaves ^ OBRIGATORIAS)}"]
    if payload["tipo"] != "checkpoint-premissas" or payload["formato"] != 1:
        problemas.append("tipo/formato desconhecidos")
    if not _inteiro(payload["seq"]):
        problemas.append("seq inválido")
    if payload["anterior"] is not None and not (isinstance(payload["anterior"], str)
                                                 and HEX64.fullmatch(payload["anterior"])):
        problemas.append("anterior inválido")
    if not isinstance(payload["emitido_em"], str):
        problemas.append("emitido_em inválido")
    estado = payload["estado"]
    if not isinstance(estado, dict):
        return problemas + ["estado deve ser objeto"]
    for premissa, dados in estado.items():
        ok = (isinstance(premissa, str) and ID_PREMISSA.fullmatch(premissa) and isinstance(dados, dict)
              and set(dados) == {"versoes", "aprovacoes"} and isinstance(dados["versoes"], list)
              and all(isinstance(h, str) and HEX64.fullmatch(h) for h in dados["versoes"])
              and isinstance(dados["aprovacoes"], dict)
              and all(isinstance(n, str) and n.isdigit() and 1 <= int(n) <= len(dados["versoes"])
                      and isinstance(h, str) and HEX64.fullmatch(h)
                      for n, h in dados["aprovacoes"].items()))
        if not ok:
            problemas.append(f"estado malformado em {premissa!r}")
    if "cadastro" in payload:
        c = payload["cadastro"]
        if not (isinstance(c, dict) and set(c) == {"serie", "sha256"} and _inteiro(c["serie"])
                and isinstance(c["sha256"], str) and HEX64.fullmatch(c["sha256"])):
            problemas.append("cadastro malformado")
    return problemas


def carregar(caminhos):
    """[(nome, bytes_json)] de arquivos e diretórios (`*.json`, exceto `ultimo.json`)."""
    itens = []
    for caminho in map(Path, caminhos):
        try:
            if caminho.is_dir():
                itens += [(str(a), a.read_bytes()) for a in sorted(caminho.glob("*.json"))
                          if a.name != "ultimo.json"]
            elif caminho.is_file():
                itens.append((str(caminho), caminho.read_bytes()))
            else:
                raise ErroDeUso(f"Caminho inexistente: {caminho}")
        except OSError as erro:
            raise ErroDeUso(f"Falha ao ler {caminho}: {erro}") from erro
    if not itens:
        raise ErroDeUso("Nenhum checkpoint encontrado")
    return itens


def estado_do_armazenamento(registros):
    """Estado atual calculado direto dos arquivos (hash dos bytes), sem importar o projeto."""
    base, estado, problemas = Path(registros) / "premissas", {}, []
    if not base.is_dir():
        return estado, [f"diretório de premissas inexistente: {base}"]
    for pasta in sorted(p for p in base.iterdir() if p.is_dir() and ID_PREMISSA.fullmatch(p.name)):
        versoes, aprovacoes = {}, {}
        for arquivo in pasta.iterdir():
            if (m := ARQUIVO_VERSAO.fullmatch(arquivo.name)):
                versoes[int(m.group(1))] = sha256(arquivo.read_bytes())
            elif (m := ARQUIVO_APROVACAO.fullmatch(arquivo.name)):
                aprovacoes[m.group(1)] = sha256(arquivo.read_bytes())
        numeros = sorted(versoes)
        if numeros != list(range(1, len(numeros) + 1)):
            problemas.append(f"{pasta.name}: sequência de versões com lacuna {numeros}")
        estado[pasta.name] = {"versoes": [versoes[n] for n in numeros], "aprovacoes": aprovacoes}
    return estado, problemas


def comparar_estados(antigo, novo, rotulo):
    """Violações se `novo` não preserva tudo o que `antigo` registrou."""
    violacoes = []
    for premissa, a in antigo.items():
        n = novo.get(premissa)
        if n is None:
            violacoes.append(f"{rotulo}: premissa {premissa} ancorada desapareceu")
            continue
        if n["versoes"][:len(a["versoes"])] != a["versoes"]:
            violacoes.append(f"{rotulo}: {premissa}: versão ancorada removida ou alterada")
        for numero, h in a["aprovacoes"].items():
            if n["aprovacoes"].get(numero) != h:
                violacoes.append(f"{rotulo}: {premissa} v{numero}: aprovação ancorada removida ou alterada")
    return violacoes


def verificar(itens, chave_hex, *, inicio=None, registros=None, serie_minima=None):
    """Retorna {"ok", "violacoes", "avisos", "checkpoints", "ultimo_seq"}."""
    violacoes, avisos, validos = [], [], {}
    if not HEX64.fullmatch(chave_hex or ""):
        raise ErroDeUso("--chave-guardiao deve ter 64 caracteres hexadecimais minúsculos")
    for nome, bruto in itens:
        try:
            checkpoint = json.loads(bruto)
        except ValueError:
            violacoes.append(f"{nome}: JSON inválido")
            continue
        problemas = validar_formato(checkpoint)
        if problemas:
            violacoes += [f"{nome}: {p}" for p in problemas]
            continue
        if not verificar_assinatura(chave_hex, checkpoint["assinatura"], canonico(checkpoint["payload"])):
            violacoes.append(f"{nome}: assinatura inválida para a chave do guardião informada")
            continue
        seq = checkpoint["payload"]["seq"]
        if seq in validos:
            if canonico(validos[seq]) != canonico(checkpoint):
                violacoes.append(f"{nome}: seq {seq} duplicado com conteúdo diferente")
            continue
        validos[seq] = checkpoint
    sequencia = [validos[s] for s in sorted(validos)]
    if sequencia:
        primeiro = sequencia[0]["payload"]
        esperado_inicio = inicio if inicio is not None else 1
        if primeiro["seq"] != esperado_inicio:
            if inicio is None:
                avisos.append(f"primeiro checkpoint é seq {primeiro['seq']}: cadeia anterior não conferida")
            else:
                violacoes.append(f"primeiro checkpoint é seq {primeiro['seq']}, esperado {inicio}")
        elif primeiro["seq"] == 1 and primeiro["anterior"] is not None:
            violacoes.append("seq 1 não pode ter checkpoint anterior")
    for antes, depois in zip(sequencia, sequencia[1:]):
        a, d = antes["payload"], depois["payload"]
        rotulo = f"seq {a['seq']}->{d['seq']}"
        if d["seq"] != a["seq"] + 1:
            violacoes.append(f"{rotulo}: lacuna na sequência (checkpoints removidos?)")
            continue
        if d["anterior"] != sha256(canonico(antes)):
            violacoes.append(f"{rotulo}: encadeamento por hash rompido")
        violacoes += comparar_estados(a["estado"], d["estado"], rotulo)
        ca, cd = a.get("cadastro"), d.get("cadastro")
        if ca is not None and cd is None:
            violacoes.append(f"{rotulo}: checkpoint deixou de atestar o cadastro de aprovadores")
        elif ca is not None and cd is not None:
            if cd["serie"] < ca["serie"]:
                violacoes.append(f"{rotulo}: série do cadastro diminuiu ({ca['serie']} -> {cd['serie']})")
            elif cd["serie"] == ca["serie"] and cd["sha256"] != ca["sha256"]:
                violacoes.append(f"{rotulo}: série {cd['serie']} do cadastro com conteúdo diferente")
    ultimo = sequencia[-1]["payload"] if sequencia else None
    if ultimo is not None and registros is not None:
        try:
            atual, problemas_vivos = estado_do_armazenamento(registros)
        except OSError as erro:
            raise ErroDeUso(f"Falha ao ler {registros}: {erro}") from erro
        violacoes += [f"armazenamento: {p}" for p in problemas_vivos]
        violacoes += comparar_estados(ultimo["estado"], atual, f"armazenamento x seq {ultimo['seq']}")
        novas = sum(max(0, len(d["versoes"]) - len(ultimo["estado"].get(p, {"versoes": []})["versoes"]))
                    for p, d in atual.items())
        if novas:
            avisos.append(f"{novas} versão(ões) posterior(es) ao último checkpoint, ainda não ancorada(s)")
    if serie_minima is not None and ultimo is not None:
        cadastro = ultimo.get("cadastro")
        if cadastro is None:
            violacoes.append("último checkpoint não atesta o cadastro; série mínima não verificável")
        elif cadastro["serie"] < serie_minima:
            violacoes.append(f"série do cadastro {cadastro['serie']} abaixo da mínima exigida {serie_minima}")
    return {"ok": not violacoes, "violacoes": violacoes, "avisos": avisos,
            "checkpoints": len(sequencia), "ultimo_seq": ultimo["seq"] if ultimo else None}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--chave-guardiao", required=True)
    parser.add_argument("--checkpoints", nargs="+", required=True)
    parser.add_argument("--inicio", type=int)
    parser.add_argument("--registros")
    parser.add_argument("--serie-minima", type=int)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        relatorio = verificar(carregar(args.checkpoints), args.chave_guardiao, inicio=args.inicio,
                              registros=args.registros, serie_minima=args.serie_minima)
    except ErroDeUso as erro:
        print("ERRO:", erro, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(relatorio, ensure_ascii=False, sort_keys=True))
    else:
        for aviso in relatorio["avisos"]:
            print("AVISO:", aviso)
        for violacao in relatorio["violacoes"]:
            print("VIOLAÇÃO:", violacao)
        print(("OK" if relatorio["ok"] else "FALHA") +
              f": {relatorio['checkpoints']} checkpoint(s) conferido(s); último seq {relatorio['ultimo_seq']}")
    return 0 if relatorio["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
