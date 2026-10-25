#!/usr/bin/env python3
"""Serviço de log de auditoria (GOV-08): única conta que escreve em `logs/`, com registros encadeados por hash.

Os papéis de sessão NÃO têm permissão de escrita em `logs/` (nem no próprio log). O hook do guarda e o gateway de rede
enviam o registro por socket Unix; este serviço
  1. descobre quem chamou pelo kernel (SO_PEERCRED) — o conteúdo enviado nunca define a origem;
  2. acrescenta uma linha JSON {seq, ts, origem, dados, prev, hash} ao arquivo da origem (só-anexar, chattr +a);
  3. responde "ok" só depois de gravar e sincronizar (fsync); sem "ok" o chamador deve tratar como falha.
Cadeia: hash = sha256(prev + "\\n" + JSON canônico de {seq, ts, origem, dados}). Qualquer remoção, troca ou reordenação
de linhas quebra a verificação (`--verificar ARQUIVO`). Sem âncora externa, quem controla a conta deste serviço (ou root)
ainda pode reescrever a cadeia inteira: isto protege contra os AGENTES, não contra o administrador.

    python3 -I -B scripts/logd.py --raiz DIR [--spec papeis.json] [--socket CAMINHO]      (conta do serviço, nunca root)
    python3 -I -B scripts/logd.py --verificar logs/guarda-revisor.jsonl
"""
import argparse
import hashlib
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolamento_base as B  # noqa: E402

GENESE = "0" * 64
LIMITE_MENSAGEM = 16384
LIMITE_TEXTO = 2000


def _canonico(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def calcular_hash(prev, seq, ts, origem, dados):
    return hashlib.sha256((prev + "\n" + _canonico({"seq": seq, "ts": ts, "origem": origem, "dados": dados})).encode("utf-8")).hexdigest()


def verificar(caminho):
    """Lista de problemas da cadeia de um arquivo de log (vazia = íntegra)."""
    problemas, prev, esperado = [], GENESE, 1
    try:
        linhas = Path(caminho).read_text(encoding="utf-8").splitlines()
    except OSError as erro:
        return [f"ilegível: {erro}"]
    for n, linha in enumerate(linhas, 1):
        try:
            r = json.loads(linha)
            seq, ts, origem, dados, p, h = r["seq"], r["ts"], r["origem"], r["dados"], r["prev"], r["hash"]
        except (ValueError, KeyError, TypeError):
            problemas.append(f"linha {n}: formato inválido")
            return problemas
        if seq != esperado:
            problemas.append(f"linha {n}: seq {seq}, esperado {esperado} (linha removida, repetida ou reordenada)")
        if p != prev:
            problemas.append(f"linha {n}: prev não confere com a linha anterior")
        if h != calcular_hash(p, seq, ts, origem, dados):
            problemas.append(f"linha {n}: hash não confere (conteúdo alterado)")
        prev, esperado = h, seq + 1
    return problemas


def _limpar(valor, nivel=0):
    """Reduz o payload recebido a JSON pequeno e simples (strings truncadas)."""
    if nivel > 4:
        return "<profundo>"
    if isinstance(valor, str):
        return valor[:LIMITE_TEXTO]
    if isinstance(valor, (int, float, bool)) or valor is None:
        return valor
    if isinstance(valor, list):
        return [_limpar(x, nivel + 1) for x in valor[:50]]
    if isinstance(valor, dict):
        return {str(k)[:64]: _limpar(v, nivel + 1) for k, v in list(valor.items())[:50]}
    return str(valor)[:LIMITE_TEXTO]


class Cadeia:
    """Estado (seq, prev) de um arquivo; reabre em modo append e continua a cadeia."""

    def __init__(self, caminho):
        self.caminho = Path(caminho)
        self.trava = threading.Lock()
        problemas = verificar(self.caminho) if self.caminho.exists() else []
        if problemas:
            raise SystemExit(f"cadeia de {self.caminho.name} corrompida; serviço não inicia: {problemas[0]}")
        linhas = self.caminho.read_text(encoding="utf-8").splitlines() if self.caminho.exists() else []
        ultimo = json.loads(linhas[-1]) if linhas else None
        self.seq = ultimo["seq"] if ultimo else 0
        self.prev = ultimo["hash"] if ultimo else GENESE

    def anexar(self, origem, dados):
        with self.trava:
            seq, ts = self.seq + 1, time.strftime("%Y-%m-%dT%H:%M:%S%z")
            h = calcular_hash(self.prev, seq, ts, origem, dados)
            linha = _canonico({"seq": seq, "ts": ts, "origem": origem, "dados": dados, "prev": self.prev, "hash": h}) + "\n"
            fd = os.open(self.caminho, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.write(fd, linha.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            self.seq, self.prev = seq, h


class ServidorLog(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, spec, raiz, caminho_socket):
        self.origens = {spec["contas"][p["conta"]]: nome for nome, p in spec["papeis"].items()}
        conta_rede = spec.get("servicos", {}).get("conta_rede")
        if conta_rede in spec["contas"]:
            self.origens[spec["contas"][conta_rede]] = "rede"
        logs = Path(raiz) / "logs"
        self.cadeias = {nome: Cadeia(logs / f"guarda-{nome}.jsonl") for nome in spec["papeis"]}
        self.cadeias["rede"] = Cadeia(logs / "rede.jsonl")
        Path(caminho_socket).unlink(missing_ok=True)
        super().__init__(str(caminho_socket), ManipuladorLog)
        os.chown(caminho_socket, -1, spec["grupos"][spec["servicos"]["grupo_socket"]])     # papéis conectam pelo grupo de leitura
        os.chmod(caminho_socket, 0o660)


class ManipuladorLog(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        resposta = b"erro\n"
        try:
            pid, uid, gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            origem = self.server.origens.get(uid)
            if origem is None:
                resposta = b"negado\n"
            else:
                bruto = self.rfile.readline(LIMITE_MENSAGEM + 1)
                if bruto and len(bruto) <= LIMITE_MENSAGEM:
                    dados = _limpar(json.loads(bruto).get("dados", {}))
                    self.server.cadeias[origem].anexar(origem, dados)
                    resposta = b"ok\n"
        except Exception:      # qualquer falha = sem "ok": o chamador trata como log indisponível
            resposta = b"erro\n"
        try:
            self.wfile.write(resposta)
        except OSError:
            pass


def enviar(caminho_socket, dados, tempo=2.0):
    """Cliente: True só se o serviço confirmou a gravação."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(tempo)
            s.connect(str(caminho_socket))
            s.sendall((json.dumps({"dados": dados}, ensure_ascii=False) + "\n").encode("utf-8"))
            return s.makefile("rb").readline().strip() == b"ok"
    except (OSError, ValueError):
        return False


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--raiz")
    ap.add_argument("--spec", default=str(B.SPEC_PADRAO))
    ap.add_argument("--socket")
    ap.add_argument("--verificar")
    a = ap.parse_args(argv)
    if a.verificar:
        problemas = verificar(a.verificar)
        for p in problemas:
            print("PROBLEMA:", p, file=sys.stderr)
        print("cadeia íntegra" if not problemas else f"{len(problemas)} problema(s)")
        return 1 if problemas else 0
    if os.geteuid() == 0:
        raise SystemExit("o serviço de log não executa como root")
    if not a.raiz:
        raise SystemExit("--raiz é obrigatório")
    spec = B.carregar(a.spec)
    problemas = B.validar(spec)
    if problemas:
        raise SystemExit("papeis.json inválido: " + "; ".join(problemas))
    caminho = a.socket or spec["servicos"]["logd_socket"]
    servidor = ServidorLog(spec, os.path.realpath(a.raiz), caminho)
    print("serviço de log pronto", flush=True)
    servidor.serve_forever()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
