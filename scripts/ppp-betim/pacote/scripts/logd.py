#!/usr/bin/env python3
"""Serviço de log de auditoria (GOV-08): única conta que escreve em `logs/`, com registros encadeados por hash.

Os papéis de sessão NÃO têm permissão de escrita em `logs/` (nem no próprio log). O hook do guarda e o gateway de rede
enviam o registro por socket Unix; este serviço
  1. descobre quem chamou pelo kernel (SO_PEERCRED) — o conteúdo enviado nunca define a origem;
  2. acrescenta uma linha JSON {seq, ts, origem, dados, prev, hash} ao arquivo da origem (só-anexar, chattr +a);
  3. responde "ok" só depois de gravar e sincronizar (fsync); sem "ok" o chamador deve tratar como falha;
  4. limita taxa e tamanho por origem (um papel não enche o disco nem enterra os registros dos outros).
Cadeia: hash = sha256(prev + "\\n" + JSON canônico ASCII de {seq, ts, origem, dados}). Remoção, troca ou reordenação de
linhas quebra a verificação (`--verificar ARQUIVO`).

LIMITES (honestos):
  - Os `dados` enviados pelo hook são AUTODECLARADOS: o hook roda com o mesmo uid do agente. O que o serviço garante é
    a ORIGEM (papel), a ordem e a integridade da cadeia. A evidência autoritativa de tráfego é `rede.jsonl`, escrita pelo
    gateway (outra conta).
  - Sem âncora externa, quem controla a conta deste serviço (ou root) reescreve a cadeia inteira, e o TRUNCAMENTO do fim da
    cadeia não é detectável por `--verificar` (um prefixo coerente é íntegro). Mitigação: publique periodicamente
    `--cabeca ARQUIVO` (seq e hash do último registro) em local fora do alcance deste serviço e compare.
  - Cobre só chamadas de ferramenta que passam pelo hook e requisições que passam pelo gateway.
  - Disco cheio/EIO no meio de uma escrita pode deixar uma LINHA PARCIAL no fim de um arquivo só-anexar: o serviço então recusa
    novos registros daquela origem (fail-closed) e só o administrador repara (procedimento: `chattr -a`, remover a linha parcial,
    conferir com `--verificar`, `chattr +a`, reiniciar). Não há rotação automática: o teto de 512 MiB por arquivo é permanente.

    python3 -I -B scripts/logd.py --raiz DIR [--spec papeis.json] [--socket CAMINHO]      (conta do serviço, nunca root)
    python3 -I -B scripts/logd.py --verificar logs/guarda-revisor.jsonl | --cabeca logs/guarda-revisor.jsonl
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
import isolamento_so as SO  # noqa: E402

GENESE = "0" * 64
LIMITE_MENSAGEM = 16384
LIMITE_TEXTO = 2000
LIMITE_ARQUIVO = 512 * 1024 * 1024          # acima disso o serviço recusa novos registros daquela origem
TAXA_POR_SEGUNDO = 50.0
RAJADA = 200
TAXA_REDE = (1000.0, 2000)          # (por segundo, rajada): o gateway já limita por papel antes de auditar
MAX_CONEXOES = 64


def _canonico(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))      # ASCII: nenhuma quebra de linha Unicode


def calcular_hash(prev, seq, ts, origem, dados):
    return hashlib.sha256((prev + "\n" + _canonico({"seq": seq, "ts": ts, "origem": origem, "dados": dados})).encode("ascii")).hexdigest()


def _linhas(caminho):
    texto = Path(caminho).read_bytes().decode("utf-8")
    return [x for x in texto.split("\n") if x != ""]          # só "\n" separa registros (splitlines() quebraria em U+2028 etc.)


def verificar(caminho):
    """Lista de problemas da cadeia de um arquivo de log (vazia = íntegra)."""
    problemas, prev, esperado = [], GENESE, 1
    try:
        linhas = _linhas(caminho)
    except (OSError, UnicodeDecodeError) as erro:
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


def _ultimo_registro(caminho):
    """Último registro do arquivo, lendo só o final (sem varrer o arquivo todo); None se vazio."""
    with open(caminho, "rb") as f:
        f.seek(0, os.SEEK_END)
        tam = f.tell()
        bloco = 65536
        while True:
            ini = max(0, tam - bloco)
            f.seek(ini)
            dados = f.read(tam - ini)
            linhas = [x for x in dados.split(b"\n") if x]
            if len(linhas) >= 2 or ini == 0:
                break
            bloco *= 4
    if not linhas:
        return None
    return json.loads(linhas[-1].decode("utf-8"))


def cabeca(caminho):
    """(seq, hash) do último registro — para publicar fora do alcance do serviço (âncora contra truncamento)."""
    r = _ultimo_registro(caminho)
    return (0, GENESE) if r is None else (r["seq"], r["hash"])


def _texto(valor):
    if len(valor) <= LIMITE_TEXTO:
        return valor
    return valor[:LIMITE_TEXTO] + f"…[truncado: {len(valor)} caracteres, sha256={hashlib.sha256(valor.encode('utf-8')).hexdigest()}]"


def _limpar(valor, nivel=0):
    """Reduz o payload recebido a JSON pequeno e simples (strings truncadas, com marca e hash do original)."""
    if nivel > 4:
        return "<profundo>"
    if isinstance(valor, str):
        return _texto(valor)
    if isinstance(valor, (int, float, bool)) or valor is None:
        return valor
    if isinstance(valor, list):
        return [_limpar(x, nivel + 1) for x in valor[:50]]
    if isinstance(valor, dict):
        return {str(k)[:64]: _limpar(v, nivel + 1) for k, v in list(valor.items())[:50]}
    return _texto(str(valor))


class Balde:
    def __init__(self, taxa=TAXA_POR_SEGUNDO, rajada=RAJADA):
        self.taxa, self.rajada = taxa, rajada
        self.fichas, self.ultimo = float(rajada), time.monotonic()

    def consome(self):
        agora = time.monotonic()
        self.fichas = min(float(self.rajada), self.fichas + (agora - self.ultimo) * self.taxa)
        self.ultimo = agora
        if self.fichas < 1:
            return False
        self.fichas -= 1
        return True


class Cadeia:
    """Estado (seq, prev) de um arquivo; reabre em modo append e continua a cadeia."""

    def __init__(self, caminho, exigir_so_anexar=True):
        self.caminho = Path(caminho)
        self.trava = threading.Lock()
        self.balde = Balde(*TAXA_REDE) if self.caminho.name == "rede.jsonl" else Balde()
        if not self.caminho.exists():
            raise SystemExit(f"{self.caminho.name} não existe: rode `isolamento.py aplicar` (o serviço não cria nem ajusta arquivos)")
        if exigir_so_anexar and not SO._tem_so_anexar(self.caminho):
            raise SystemExit(f"{self.caminho.name} não é só-anexar (chattr +a): serviço não inicia")
        problemas = verificar(self.caminho)
        if problemas:
            raise SystemExit(f"cadeia de {self.caminho.name} corrompida; serviço não inicia: {problemas[0]}")
        self._ressincroniza()

    def _ressincroniza(self):
        self.seq, self.prev = cabeca(self.caminho)

    def anexar(self, origem, dados):
        with self.trava:
            if not self.balde.consome():
                raise OSError("taxa excedida")
            if self.caminho.stat().st_size > LIMITE_ARQUIVO:
                raise OSError("arquivo de log no limite")
            self._ressincroniza()           # o disco é a verdade: qualquer escrita parcial anterior é reabsorvida
            ultimo = _ultimo_registro(self.caminho)
            if ultimo is not None and ultimo["hash"] != calcular_hash(ultimo["prev"], ultimo["seq"], ultimo["ts"], ultimo["origem"], ultimo["dados"]):
                raise OSError("último registro inconsistente no disco")
            seq, ts = self.seq + 1, time.strftime("%Y-%m-%dT%H:%M:%S%z")
            h = calcular_hash(self.prev, seq, ts, origem, dados)
            linha = (_canonico({"seq": seq, "ts": ts, "origem": origem, "dados": dados, "prev": self.prev, "hash": h}) + "\n").encode("ascii")
            fd = os.open(self.caminho, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                escrito = 0
                while escrito < len(linha):
                    escrito += os.write(fd, linha[escrito:])
                os.fsync(fd)
            finally:
                os.close(fd)
            self.seq, self.prev = seq, h


class ServidorLog(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, spec, raiz, caminho_socket, exigir_so_anexar=True):
        self.origens = {spec["contas"][p["conta"]]: nome for nome, p in spec["papeis"].items()}
        conta_rede = spec.get("servicos", {}).get("conta_rede")
        if conta_rede in spec["contas"]:
            self.origens[spec["contas"][conta_rede]] = "rede"
        logs = Path(raiz) / "logs"
        self.cadeias = {nome: Cadeia(logs / f"guarda-{nome}.jsonl", exigir_so_anexar) for nome in spec["papeis"]}
        self.cadeias["rede"] = Cadeia(logs / "rede.jsonl", exigir_so_anexar)
        self.limite = threading.BoundedSemaphore(MAX_CONEXOES)
        Path(caminho_socket).unlink(missing_ok=True)
        antiga = os.umask(0o117)                     # nunca existe janela com o socket acessível a outros
        try:
            super().__init__(str(caminho_socket), ManipuladorLog)
        finally:
            os.umask(antiga)
        os.chown(caminho_socket, -1, spec["grupos"][spec["servicos"]["grupo_socket"]])     # papéis conectam pelo grupo de leitura
        os.chmod(caminho_socket, 0o660)


class ManipuladorLog(socketserver.StreamRequestHandler):
    timeout = 3          # prazo para cada leitura; o gotejamento não prende a thread

    def handle(self):
        if not self.server.limite.acquire(blocking=False):
            return
        resposta = b"erro\n"
        try:
            pid, uid, gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            origem = self.server.origens.get(uid)
            if origem is None:
                resposta = b"negado\n"
            else:
                inicio = time.monotonic()
                bruto = self.rfile.readline(LIMITE_MENSAGEM + 1)
                if bruto and len(bruto) <= LIMITE_MENSAGEM and bruto.endswith(b"\n") and time.monotonic() - inicio < 5:
                    dados = _limpar(json.loads(bruto).get("dados", {}))
                    self.server.cadeias[origem].anexar(origem, dados)
                    resposta = b"ok\n"
        except Exception:      # qualquer falha = sem "ok": o chamador trata como log indisponível
            resposta = b"erro\n"
        finally:
            self.server.limite.release()
        try:
            self.wfile.write(resposta)
        except OSError:
            pass


def enviar(caminho_socket, dados, tempo=2.0, uid_esperado=None):
    """Cliente: True só se o serviço confirmou a gravação (e, se informado, só se o servidor é a conta esperada)."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(tempo)
            s.connect(str(caminho_socket))
            if uid_esperado is not None:
                _, uid, _ = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if uid != uid_esperado:
                    return False        # outro processo ocupa o socket: sua confirmação não vale
            s.sendall((json.dumps({"dados": dados}, ensure_ascii=True) + "\n").encode("ascii"))
            return s.makefile("rb").readline().strip() == b"ok"
    except (OSError, ValueError):
        return False


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--raiz")
    ap.add_argument("--spec", default=str(B.SPEC_PADRAO))
    ap.add_argument("--socket")
    ap.add_argument("--verificar")
    ap.add_argument("--cabeca")
    ap.add_argument("--permitir-sem-so-anexar", action="store_true", help="SOMENTE desenvolvimento: aceita log sem chattr +a")
    a = ap.parse_args(argv)
    if a.verificar:
        problemas = verificar(a.verificar)
        for p in problemas:
            print("PROBLEMA:", p, file=sys.stderr)
        print("cadeia íntegra" if not problemas else f"{len(problemas)} problema(s)")
        return 1 if problemas else 0
    if a.cabeca:
        seq, h = cabeca(a.cabeca)
        print(json.dumps({"arquivo": Path(a.cabeca).name, "seq": seq, "hash": h}))
        return 0
    if os.geteuid() == 0:
        raise SystemExit("o serviço de log não executa como root")
    if not a.raiz:
        raise SystemExit("--raiz é obrigatório")
    spec = B.carregar(a.spec)
    problemas = B.validar(spec)
    if problemas:
        raise SystemExit("papeis.json inválido: " + "; ".join(problemas))
    caminho = a.socket or spec["servicos"]["logd_socket"]
    servidor = ServidorLog(spec, os.path.realpath(a.raiz), caminho, not a.permitir_sem_so_anexar)
    print("serviço de log pronto", flush=True)
    servidor.serve_forever()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
