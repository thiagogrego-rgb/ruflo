"""Ferramenta do APROVADOR HUMANO (GOV-02). Não deve ser executada por agentes.

    gerar-chave --saida ~/.ppp-betim/aprovador.pem
    assinar --chave ~/.ppp-betim/aprovador.pem --aprovador ID \
            --premissa PREM-001 --versao 1 --envelope v1.json --saida aprov.json
    assinar-registro --chave ~/.ppp-betim/raiz.pem --registro aprovadores.json

`--envelope` é a versão exportada pelo guardião; `--registros` lê um
armazenamento local (uso sem guardião). Se o envelope tiver sido alterado no
caminho, a aprovação não confere com a versão guardada e é recusada.

Exige terminal interativo, frase-senha e confirmação digitada do hash. Essas
exigências dificultam o uso automatizado, mas não são controle de segurança:
a proteção real depende de a chave privada estar fora do alcance do agente.
"""
import argparse
import getpass
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aprovacao import assinar, payload_aprovacao  # noqa: E402
from governanca import RAIZ, canonico  # noqa: E402
from premissas_repositorio import RepositorioPremissas, sha256  # noqa: E402


def _recusar(mensagem):
    print("RECUSADO:", mensagem, file=sys.stderr)
    sys.exit(2)


def _exigir_terminal():
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        _recusar("execução exige terminal interativo de um aprovador humano")


def _fora_do_projeto(caminho):
    caminho = Path(caminho).expanduser().resolve()
    if caminho.is_relative_to(RAIZ):
        _recusar(f"a chave privada não pode ficar dentro do projeto ({RAIZ})")
    return caminho


def gerar_chave(args):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    destino = _fora_do_projeto(args.saida)
    senha = getpass.getpass("Frase-senha da chave: ").encode()
    if len(senha) < 12 or senha != getpass.getpass("Repita: ").encode():
        _recusar("frase-senha ausente, curta (<12) ou divergente")
    chave = Ed25519PrivateKey.generate()
    pem = chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.BestAvailableEncryption(senha))
    destino.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(destino, "xb") as arquivo:
        arquivo.write(pem)
    destino.chmod(0o600)
    publica = chave.public_key().public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw)
    print("Chave pública para governanca/aprovadores.json:", publica.hex())


def assinar_versao(args):
    from cryptography.hazmat.primitives import serialization
    caminho_chave = _fora_do_projeto(args.chave)
    if args.envelope:
        bruto = Path(args.envelope).read_bytes()
        envelope = json.loads(bruto)
        if canonico(envelope) != bruto:
            bruto = canonico(envelope)
        conteudo = envelope.get("premissa", {})
        if (conteudo.get("id"), conteudo.get("versao")) != (args.premissa, args.versao):
            _recusar("envelope não corresponde à premissa e versão indicadas")
        hash_versao = sha256(bruto)
    else:
        cadeia = RepositorioPremissas(args.registros).historico(args.premissa)
        if not 1 <= args.versao <= len(cadeia):
            _recusar(f"{args.premissa} v{args.versao} inexistente")
        _, hash_versao, envelope = cadeia[args.versao - 1]
    print(json.dumps(envelope, indent=2, ensure_ascii=False))
    print("SHA-256 da versão:", hash_versao)
    if input("Digite os 8 primeiros caracteres do SHA-256 para aprovar: ") != hash_versao[:8]:
        _recusar("confirmação divergente")
    senha = getpass.getpass("Frase-senha da chave: ").encode()
    chave = serialization.load_pem_private_key(caminho_chave.read_bytes(), password=senha)
    payload = payload_aprovacao(args.premissa, args.versao, hash_versao, args.aprovador,
                                datetime.now(timezone.utc).isoformat())
    with open(args.saida, "xb") as arquivo:
        arquivo.write(canonico(assinar(payload, chave)))
    print("Aprovação assinada gravada em", args.saida)


def assinar_registro(args):
    from cryptography.hazmat.primitives import serialization
    import base64
    caminho_chave = _fora_do_projeto(args.chave)
    bruto = Path(args.registro).read_bytes()
    print(bruto.decode("utf-8"))
    hash_registro = sha256(bruto)
    print("SHA-256 do registro:", hash_registro)
    if input("Digite os 8 primeiros caracteres do SHA-256 para assinar: ") != hash_registro[:8]:
        _recusar("confirmação divergente")
    senha = getpass.getpass("Frase-senha da chave: ").encode()
    chave = serialization.load_pem_private_key(caminho_chave.read_bytes(), password=senha)
    with open(f"{args.registro}.sig", "x", encoding="ascii") as arquivo:
        arquivo.write(base64.b64encode(chave.sign(bruto)).decode("ascii") + "\n")
    print("Assinatura gravada em", f"{args.registro}.sig")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="comando", required=True)
    g = sub.add_parser("gerar-chave")
    g.add_argument("--saida", required=True)
    a = sub.add_parser("assinar")
    for nome in ("--chave", "--aprovador", "--premissa", "--saida"):
        a.add_argument(nome, required=True)
    a.add_argument("--versao", type=int, required=True)
    origem = a.add_mutually_exclusive_group(required=True)
    origem.add_argument("--envelope")
    origem.add_argument("--registros")
    r = sub.add_parser("assinar-registro")
    r.add_argument("--chave", required=True)
    r.add_argument("--registro", required=True)
    args = parser.parse_args()
    _exigir_terminal()
    {"gerar-chave": gerar_chave, "assinar": assinar_versao,
     "assinar-registro": assinar_registro}[args.comando](args)


if __name__ == "__main__":
    main()
