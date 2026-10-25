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
import re
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
NOME_SEGURO = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


def argvs_de_contas(spec):
    """Lista de argv (sem shell) que cria grupos e contas da especificação. Os nomes são validados ANTES de qualquer execução."""
    problemas = ISO.validar(spec)
    nomes = list(spec["grupos"]) + list(spec["contas"])
    problemas += [f"nome inseguro: {n!r}" for n in nomes if not NOME_SEGURO.match(str(n))]
    if problemas:
        raise SystemExit("especificação recusada:\n  - " + "\n  - ".join(problemas[:10]))
    argvs = [("grupo", g, ["groupadd", "-g", str(gid), g]) for g, gid in spec["grupos"].items()]
    for c, uid in spec["contas"].items():
        papel = next((p for p in spec["papeis"].values() if p["conta"] == c), None)
        servicos = spec.get("servicos", {})
        if papel:
            sup = list(papel["grupos"])
        elif c in (servicos.get("conta_log"), servicos.get("conta_rede")):
            sup = list(servicos.get("grupos_contas_servico", []))
        else:
            sup = []
        argvs.append(("grupo", c, ["groupadd", "-g", str(uid), c]))
        argvs.append(("conta", c, ["useradd", "-r", "-M", "-u", str(uid), "-g", c, *(["-G", ",".join(sup)] if sup else []), "-s", "/usr/sbin/nologin", c]))
    return argvs


def comandos_de_contas(spec):
    return [" ".join(a[2]) for a in argvs_de_contas(spec)]


def criar_contas(spec):
    """Cria as contas/grupos que ainda não existem (sem shell). Devolve (criadas, existentes)."""
    criadas, existentes = [], []
    for tipo, nome, argv in argvs_de_contas(spec):
        existe = subprocess.run(["getent", "group" if tipo == "grupo" else "passwd", nome], capture_output=True).returncode == 0
        if existe:
            existentes.append(nome) if nome not in existentes else None
            continue
        subprocess.run(argv, check=True, capture_output=True)
        criadas.append(nome) if nome not in criadas else None
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
def _supervisor_vivo():
    try:
        pid = json.loads(STATUS_SUPERVISOR.read_text())["pid"]
        return Path(f"/proc/{pid}").exists() and "python" in Path(f"/proc/{pid}/comm").read_text()
    except (OSError, ValueError, KeyError):
        return False


def instalar(spec, origem_projeto, dados_sinteticos=None):
    """Instala código imutável (root), árvore do projeto, diretórios de serviço e homes. Idempotente."""
    origem = Path(origem_projeto)
    if _supervisor_vivo():
        raise SystemExit("instalação recusada: o supervisor está em execução (pare os serviços antes de trocar código e árvore)")
    problemas = verificar_dados_sinteticos(origem / "dados")                        # SEMPRE a pasta que será copiada
    if dados_sinteticos:
        problemas += verificar_dados_sinteticos(dados_sinteticos)
    if problemas:
        raise SystemExit("instalação recusada (dados não declarados como sintéticos):\n  - " + "\n  - ".join(problemas[:5]))
    for suspeito in [*(origem / "scripts").glob("*.py"), origem / "governanca/papeis.json"]:
        if suspeito.is_symlink():
            raise SystemExit(f"instalação recusada: link simbólico na origem do código: {suspeito}")
    if CODIGO.exists():
        shutil.rmtree(CODIGO)
    (CODIGO / "scripts").mkdir(parents=True)
    (CODIGO / "governanca").mkdir()
    for f in (origem / "scripts").glob("*.py"):
        shutil.copy2(f, CODIGO / "scripts" / f.name, follow_symlinks=False)
    shutil.copy2(origem / "governanca/papeis.json", CODIGO / "governanca/papeis.json", follow_symlinks=False)
    for p in [CODIGO.parent, CODIGO, CODIGO / "scripts", CODIGO / "governanca"]:
        os.chmod(p, 0o755)
    for f in (CODIGO / "scripts").glob("*.py"):
        os.chmod(f, 0o644)
    for p in [CODIGO.parent, *CODIGO.rglob("*")]:
        os.chown(p, 0, 0)
    if PROJETO.exists():
        logs_antigos = PROJETO / "logs"
        for arq in logs_antigos.glob("*.jsonl") if logs_antigos.is_dir() else []:
            subprocess.run(["chattr", "-a", str(arq)], capture_output=True)
        if logs_antigos.is_dir() and any(logs_antigos.glob("*.jsonl")):          # evidência não se apaga: os logs da instalação anterior ficam arquivados
            destino_logs = VAR / "logs-arquivados" / time.strftime("%Y%m%dT%H%M%S")
            destino_logs.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(logs_antigos, destino_logs)
        shutil.rmtree(PROJETO)
    PROJETO.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(PROJETO.parent, 0o755)
    shutil.copytree(origem, PROJETO, ignore=shutil.ignore_patterns("__pycache__", "*.zip", "logs"), symlinks=True)
    for d in (ETC, VAR):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)
    if ANCORAS.is_dir() and any(ANCORAS.glob("ancora-*.json")):         # logs novos = série nova; as âncoras antigas são evidência e ficam guardadas
        arquivo = VAR / "ancoras-arquivadas" / time.strftime("%Y%m%dT%H%M%S")
        arquivo.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(ANCORAS), str(arquivo))
    ANCORAS.mkdir(parents=True, exist_ok=True)
    os.chmod(ANCORAS, 0o755)
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
def chave_sintetica(arquivo):
    try:
        return MARCADOR_SINTETICO.encode() in Path(arquivo).read_bytes()
    except OSError:
        return False


def validar_config_producao(config, spec):
    """Para o modo api-real: nada de exceção de teste e destino só https do host definido em papeis.json. Devolve a lista de problemas."""
    g = config.get("gateway", {})
    problemas = []
    if g.get("permitir_teste"):
        problemas.append("servicos.json tem permitir_teste=true (sobra de laboratório?)")
    alvo = g.get("upstream")
    esperado = spec["rede"]["upstream"]
    if alvo and alvo.rstrip("/") != esperado.rstrip("/"):
        problemas.append(f"upstream {alvo!r} difere do definido em papeis.json ({esperado!r})")
    return problemas


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
    if g.get("permitir_teste") and chave_sintetica(g.get("chave_arquivo", str(CHAVE))):
        cmd += ["--permitir-http-de-teste"]                 # a exceção de teste só vale com credencial marcada SINTETICO; a chave real nunca vai em claro
    return cmd


def _assinatura(arquivo):
    try:
        st = os.stat(arquivo)
        return (st.st_ino, st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def supervisionar(spec, parar_apos=None, ancora_a_cada=300.0):
    """Laço do supervisor: mantém logd e gateway no ar e reinicia com espera. O gateway cai quando a credencial some ou muda (revogação/rotação
    valem de verdade) e só volta com a nova. Publica âncoras de log periodicamente. Termina com SIGTERM/SIGINT/SIGHUP."""
    parar = {"sim": False}
    for sinal in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sinal, lambda *_: parar.update(sim=True))
    filhos, reinicios, ultimo, assin = {}, {"logd": 0, "gateway": 0}, {"logd": 0.0, "gateway": 0.0}, {}
    config, ultima_ancora, inicio = {}, 0.0, time.time()
    env = {"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LANG": "C.UTF-8"}      # filhos NÃO herdam o ambiente do root
    while not parar["sim"]:
        try:
            config = json.loads(CONFIG_SERVICOS.read_text()) if CONFIG_SERVICOS.exists() else {}
        except ValueError:
            pass                                                         # config inválida: mantém a última boa em vez de derrubar o supervisor
        arq_chave = config.get("gateway", {}).get("chave_arquivo", str(CHAVE))
        g = filhos.get("gateway")
        if g is not None and g.poll() is None and _assinatura(arq_chave) != assin.get("gateway"):
            g.terminate()                                                # credencial removida ou trocada: o gateway em execução NÃO continua com a antiga
            try:
                g.wait(timeout=5)
            except subprocess.TimeoutExpired:
                g.kill()
                g.wait()
        for nome in ("logd", "gateway"):
            p = filhos.get(nome)
            if p is not None and p.poll() is None:
                continue
            if p is not None:
                reinicios[nome] += 1
            if nome == "gateway" and not Path(arq_chave).exists():
                filhos.pop(nome, None)
                continue                                                 # sem credencial provisionada o gateway NÃO sobe (fail-closed)
            if time.monotonic() - ultimo[nome] < 1.0:
                continue
            ultimo[nome] = time.monotonic()
            if nome == "gateway":
                assin["gateway"] = _assinatura(arq_chave)
            filhos[nome] = subprocess.Popen(comando_de_servico(spec, nome, config), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                            start_new_session=True, env=env)
        if ancora_a_cada and time.monotonic() - ultima_ancora > ancora_a_cada and filhos.get("logd") and filhos["logd"].poll() is None:
            ultima_ancora = time.monotonic()
            try:
                import ancora_logs
                ancora_logs.publicar(PROJETO, spec, ANCORAS)
            except (SystemExit, OSError, ValueError):
                pass                                                     # cadeia inválida ou destino inseguro: a falta de âncora aparece na verificação
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
