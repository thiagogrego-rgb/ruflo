"""Ambiente do piloto controlado (GOV-09): pré-requisitos, contas, instalação, credencial, varredura e supervisor.

Tudo aqui é para DADOS SINTÉTICOS e para um ambiente de homologação/laboratório. Nada instala serviço de produção: o
supervisor é um processo comum (no ambiente institucional use as unidades do sistema descritas em GOV-08/GOV-09).
A credencial NUNCA passa por argv, ambiente, log ou artefato: entra por stdin/terminal oculto e vai para um arquivo 0600 da
conta do gateway; os registros guardam só tamanho e uma impressão curta (não reversível).
"""
import getpass
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolamento as ISO  # noqa: E402

CODIGO = Path("/opt/ppp-betim/codigo")
PROJETO = Path("/srv/ppp-betim/projeto")
ETC = Path("/etc/ppp-betim")
VAR = Path("/var/lib/ppp-betim")
ANCORAS = VAR / "ancoras"
EVIDENCIAS = VAR / "evidencias"
CHAVE = ETC / "chave-api"
CONFIG_SERVICOS = ETC / "servicos.json"
REGISTRO_CREDENCIAL = EVIDENCIAS / "registro-credencial.jsonl"
STATUS_SUPERVISOR = EVIDENCIAS / "supervisor-status.json"
MARCADOR_SINTETICO = "SINTETICO"


# ------------------------------------------------------------------------------------------------ pré-requisitos
def preflight(spec):
    """Lista de verificações {nome, ok, detalhe}. Não altera nada."""
    def tem(cmd):
        return shutil.which(cmd) is not None
    r = [
        {"nome": "executa como root (para criar contas e rebaixar privilégio)", "ok": os.geteuid() == 0, "detalhe": f"uid={os.geteuid()}"},
        {"nome": "Linux", "ok": sys.platform.startswith("linux"), "detalhe": os.uname().release},
        {"nome": "ferramentas: setpriv bwrap chattr groupadd useradd", "ok": all(tem(c) for c in ("setpriv", "bwrap", "chattr", "groupadd", "useradd")),
         "detalhe": ",".join(c for c in ("setpriv", "bwrap", "chattr", "groupadd", "useradd") if not tem(c)) or "todas presentes"},
        {"nome": "executável claude", "ok": tem("claude"), "detalhe": "presente" if tem("claude") else "ausente"},
        {"nome": "user namespaces (bubblewrap funciona)", "ok": subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-user", "true"],
                                                                        capture_output=True).returncode == 0 if tem("bwrap") else False, "detalhe": ""},
        {"nome": "fs.protected_hardlinks=1", "ok": Path("/proc/sys/fs/protected_hardlinks").read_text().strip() == "1"
         if Path("/proc/sys/fs/protected_hardlinks").exists() else False, "detalhe": ""},
        {"nome": "papeis.json válido", "ok": not ISO.validar(spec), "detalhe": "; ".join(ISO.validar(spec))[:200]},
    ]
    return r


def verificar_dados_sinteticos(pasta):
    """Recusa pastas de dados cujos arquivos não se declarem sintéticos (`SINTETICO` no início): proteção contra carga acidental de documento real."""
    problemas = []
    for arq in sorted(Path(pasta).rglob("*")):
        if arq.is_file() and arq.name not in (".sentinela", ".gitkeep"):
            try:
                inicio = arq.read_bytes()[:2048].decode("utf-8", errors="replace")
            except OSError:
                inicio = ""
            if MARCADOR_SINTETICO not in inicio:
                problemas.append(f"{arq}: não se declara sintético (falta a palavra {MARCADOR_SINTETICO} nos primeiros 2 KiB)")
    return problemas


# ------------------------------------------------------------------------------------------------ contas
def comandos_de_contas(spec):
    return [c for c in ISO.comandos_contas(spec).splitlines() if c and not c.startswith("#")]


def criar_contas(spec):
    """Cria as contas/grupos sintéticos que ainda não existem. Devolve (criadas, existentes)."""
    criadas, existentes = [], []
    for comando in comandos_de_contas(spec):
        alvo = comando.split()[-1]
        if comando.startswith("groupadd -g") and "&&" not in comando:
            existe = subprocess.run(["getent", "group", alvo], capture_output=True).returncode == 0
        else:
            existe = subprocess.run(["getent", "passwd", alvo], capture_output=True).returncode == 0
        if existe:
            existentes.append(alvo)
            continue
        subprocess.run(comando, shell=True, check=True, capture_output=True)
        criadas.append(alvo)
    return criadas, existentes


def inventario_de_contas(spec):
    """Contas/grupos como o SISTEMA os vê (getent/id), não só como a especificação os declara."""
    linhas = []
    for conta, uid in spec["contas"].items():
        r = subprocess.run(["id", conta], capture_output=True, text=True)
        passwd = subprocess.run(["getent", "passwd", conta], capture_output=True, text=True).stdout.strip().split(":")
        linhas.append({"conta": conta, "uid_esperado": uid, "id": r.stdout.strip(), "shell": passwd[-1] if len(passwd) > 6 else None,
                       "papel": next((n for n, p in spec["papeis"].items() if p["conta"] == conta), "serviço/administração")})
    return linhas


# ------------------------------------------------------------------------------------------------ instalação
def instalar(spec, origem_projeto, dados_sinteticos=None):
    """Instala código imutável (root), árvore do projeto, diretórios de serviço e homes. Idempotente."""
    problemas = []
    if dados_sinteticos:
        problemas = verificar_dados_sinteticos(dados_sinteticos)
        if problemas:
            raise SystemExit("instalação recusada (dados não declarados como sintéticos):\n  - " + "\n  - ".join(problemas[:5]))
    origem = Path(origem_projeto)
    if CODIGO.exists():
        shutil.rmtree(CODIGO)
    (CODIGO / "scripts").mkdir(parents=True)
    (CODIGO / "governanca").mkdir()
    for f in (origem / "scripts").glob("*.py"):
        shutil.copy2(f, CODIGO / "scripts" / f.name)
    shutil.copy2(origem / "governanca/papeis.json", CODIGO / "governanca/papeis.json")
    for p in [CODIGO.parent, CODIGO, CODIGO / "scripts", CODIGO / "governanca"]:
        os.chmod(p, 0o755)
    for f in (CODIGO / "scripts").glob("*.py"):
        os.chmod(f, 0o644)
    for p in [CODIGO.parent, *CODIGO.rglob("*")]:
        os.chown(p, 0, 0)
    if PROJETO.exists():
        for arq in (PROJETO / "logs").glob("*.jsonl") if (PROJETO / "logs").is_dir() else []:
            subprocess.run(["chattr", "-a", str(arq)], capture_output=True)
        shutil.rmtree(PROJETO)
    PROJETO.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(PROJETO.parent, 0o755)
    shutil.copytree(origem, PROJETO, ignore=shutil.ignore_patterns("__pycache__", "*.zip", "logs"), symlinks=True)
    for d in (ETC, VAR, ANCORAS):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)
    EVIDENCIAS.mkdir(parents=True, exist_ok=True)
    os.chmod(EVIDENCIAS, 0o700)
    run = Path(spec["servicos"]["dir"])
    run.mkdir(parents=True, exist_ok=True)
    os.chmod(run, 0o755)
    for sub, conta in (("log", spec["servicos"]["conta_log"]), ("gw", spec["servicos"]["conta_rede"])):
        d = run / sub
        d.mkdir(exist_ok=True)
        os.chown(d, spec["contas"][conta], spec["contas"][conta])
        os.chmod(d, 0o755)
    home_base = Path(spec["home_base"])
    home_base.mkdir(parents=True, exist_ok=True)
    os.chown(home_base, 0, 0)
    os.chmod(home_base, 0o755)
    avisos = ISO.aplicar(PROJETO, spec, home_base)
    return avisos


# ------------------------------------------------------------------------------------------------ credencial
def _impressao(chave_bytes):
    return hashlib.sha256(chave_bytes).hexdigest()[:8]


def registrar_credencial(acao, **campos):
    EVIDENCIAS.mkdir(parents=True, exist_ok=True)
    linha = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "acao": acao,
             "operador": os.environ.get("SUDO_USER") or getpass.getuser(), **campos}
    fd = os.open(REGISTRO_CREDENCIAL, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(linha, ensure_ascii=False) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return linha


def instalar_credencial(spec, chave_bytes, rotulo, destino=CHAVE):
    """Grava a chave em arquivo 0600 da conta do gateway, de forma atômica. Devolve o registro (sem o segredo)."""
    chave = chave_bytes.strip()
    if not (16 <= len(chave) <= 400) or any(b <= 32 or b >= 127 for b in chave):
        raise SystemExit("credencial recusada: tamanho fora de 16..400 ou caracteres não imprimíveis/espaços")
    uid = spec["contas"][spec["servicos"]["conta_rede"]]
    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)
    tmp = destino.with_name(destino.name + f".novo-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, chave + b"\n")
        os.fchown(fd, uid, uid)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, destino)
    return registrar_credencial("instalada", rotulo=rotulo, tamanho=len(chave), impressao=_impressao(chave), arquivo=str(destino))


def ler_credencial_do_terminal_ou_stdin():
    """Terminal: leitura SEM eco. Sem terminal: stdin (ex.: `gerenciador-de-segredos ler ... | piloto.py credencial instalar`)."""
    if sys.stdin.isatty():
        return getpass.getpass("credencial (não será exibida): ").encode("utf-8")
    return sys.stdin.buffer.read()


def verificar_credencial(spec, destino=CHAVE):
    """Confere dono/modo/tamanho do arquivo SEM exibir o conteúdo. {ok, problemas, tamanho, impressao}."""
    destino = Path(destino)
    if not destino.exists():
        return {"ok": False, "problemas": ["credencial não provisionada"], "tamanho": None, "impressao": None}
    st = os.lstat(destino)
    uid = spec["contas"][spec["servicos"]["conta_rede"]]
    problemas = []
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        problemas.append("não é arquivo comum")
    if st.st_uid != uid:
        problemas.append(f"dono {st.st_uid} (esperado {uid})")
    if st.st_mode & 0o077:
        problemas.append(f"modo {oct(stat.S_IMODE(st.st_mode))} (esperado 0600)")
    dados = destino.read_bytes().strip()
    return {"ok": not problemas, "problemas": problemas, "tamanho": len(dados), "impressao": _impressao(dados)}


def revogar_credencial(destino=CHAVE, motivo=""):
    destino = Path(destino)
    if destino.exists():
        tamanho = destino.stat().st_size
        with open(destino, "r+b") as f:           # sobrescreve antes de remover (melhor esforço; SSD/overlay não garantem)
            f.write(b"\0" * tamanho)
            f.flush()
            os.fsync(f.fileno())
        destino.unlink()
    return registrar_credencial("revogada", motivo=motivo)


# ------------------------------------------------------------------------------------------------ varredura
def varredura_de_credencial(chave_bytes, pastas, ignorar=()):
    """Procura a chave (bytes) em argv/ambiente de TODOS os processos e em arquivos das pastas. Nunca devolve o conteúdo.
    `ignorar`: caminhos de arquivo que PODEM conter a chave por desenho (o arquivo da credencial)."""
    chave = chave_bytes.strip()
    achados = []
    ignorar = {str(Path(p)) for p in ignorar}
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        for alvo in ("cmdline", "environ"):
            try:
                if chave in (proc / alvo).read_bytes():
                    achados.append({"onde": f"/proc/{proc.name}/{alvo}", "processo": (proc / "comm").read_text().strip()})
            except OSError:
                continue
    for pasta in pastas:
        pasta = Path(pasta)
        if not pasta.exists():
            continue
        for arq in pasta.rglob("*"):
            try:
                if arq.is_symlink() or not arq.is_file() or str(arq) in ignorar or arq.stat().st_size > 64 * 1024 * 1024:
                    continue
                if chave in arq.read_bytes():
                    achados.append({"onde": str(arq), "processo": None})
            except OSError:
                continue
    return achados


# ------------------------------------------------------------------------------------------------ supervisor
def comando_de_servico(spec, nome, config):
    """Linha de comando de um serviço (rebaixado para a conta dele, sem privilégios novos)."""
    conta = spec["servicos"]["conta_log"] if nome == "logd" else spec["servicos"]["conta_rede"]
    uid = spec["contas"][conta]
    grupos = [spec["grupos"][g] for g in spec["servicos"]["grupos_contas_servico"]]
    base = ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--groups=" + ",".join(str(g) for g in grupos), "--no-new-privs",
            "--inh-caps=-all", "--bounding-set=-all", sys.executable, "-I", "-B"]
    spec_path = str(CODIGO / "governanca/papeis.json")
    if nome == "logd":
        return base + [str(CODIGO / "scripts/logd.py"), "--raiz", str(PROJETO), "--spec", spec_path]
    g = config.get("gateway", {})
    cmd = base + [str(CODIGO / "scripts/gateway.py"), "--raiz", str(PROJETO), "--spec", spec_path, "--chave-arquivo", g.get("chave_arquivo", str(CHAVE))]
    if g.get("upstream"):
        cmd += ["--upstream", g["upstream"]]
    if g.get("proxy_arquivo"):
        cmd += ["--proxy-arquivo", g["proxy_arquivo"]]
    if g.get("ca_arquivo"):
        cmd += ["--ca-arquivo", g["ca_arquivo"]]
    if g.get("permitir_teste"):
        cmd += ["--permitir-http-de-teste"]
    return cmd


def supervisionar(spec, parar_apos=None):
    """Laço do supervisor: mantém logd e gateway no ar, reiniciando com espera; grava o status. Termina com SIGTERM."""
    parar = {"sim": False}
    signal.signal(signal.SIGTERM, lambda *_: parar.update(sim=True))
    filhos, reinicios, ultimo = {}, {"logd": 0, "gateway": 0}, {"logd": 0.0, "gateway": 0.0}
    inicio = time.time()
    while not parar["sim"]:
        config = json.loads(CONFIG_SERVICOS.read_text()) if CONFIG_SERVICOS.exists() else {}
        for nome in ("logd", "gateway"):
            p = filhos.get(nome)
            if p is not None and p.poll() is None:
                continue
            if p is not None:
                reinicios[nome] += 1
            if nome == "gateway" and not Path(config.get("gateway", {}).get("chave_arquivo", str(CHAVE))).exists():
                filhos.pop(nome, None)
                continue                              # sem credencial provisionada o gateway NÃO sobe (fail-closed)
            if time.monotonic() - ultimo[nome] < 1.0:
                continue
            ultimo[nome] = time.monotonic()
            filhos[nome] = subprocess.Popen(comando_de_servico(spec, nome, config), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                            start_new_session=True)
        STATUS_SUPERVISOR.write_text(json.dumps({"pid": os.getpid(), "desde": inicio, "reinicios": reinicios,
                                                 "pids": {n: (p.pid if p.poll() is None else None) for n, p in filhos.items()},
                                                 "gateway_sem_credencial": "gateway" not in filhos}, indent=1))
        time.sleep(0.4)
        if parar_apos and time.time() - inicio > parar_apos:
            break
    for p in filhos.values():
        if p.poll() is None:
            p.terminate()
    for p in filhos.values():
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    return reinicios
