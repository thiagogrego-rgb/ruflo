"""Operações de SO do isolamento (GOV-07/08): aplicar, auditar e sondar.

Regra de ouro das operações privilegiadas: NUNCA seguir link simbólico escolhido por um papel. `aplicar` roda como root
sobre diretórios que os papéis controlam (produtos/*, homes); por isso toda operação é feita por descritor aberto com
O_NOFOLLOW e confirmado por fstat (dev/ino), nunca por caminho. Entradas inesperadas (link, hardlink, montagem, arquivo
especial) não são tocadas: são reportadas e a auditoria as recusa.
"""
import errno
import fcntl
import json
import os
import stat
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from isolamento_base import (SENTINELA, _bit, _dados, area_de, ids_papel, nomes_de_log, prever)  # noqa: E402

FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_APPEND_FL = 0x80086601, 0x40086602, 0x20
O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
XATTRS_PERIGOSOS = ("system.posix_acl_access", "system.posix_acl_default", "security.capability")


def _flags(fd):
    return struct.unpack("l", fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack("l", 0)))[0]


def _so_anexar(fd, ligar):
    """Liga/desliga o atributo só-anexar (chattr +a) no descritor; False se o filesystem não suporta."""
    try:
        atual = _flags(fd)
        novo = (atual | FS_APPEND_FL) if ligar else (atual & ~FS_APPEND_FL)
        if novo != atual:
            fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack("l", novo))
        return bool(_flags(fd) & FS_APPEND_FL) == ligar
    except OSError:
        return False


def _chattr(op, caminho):
    """Compatibilidade com os testes: '+a'/'-a' sobre um caminho que NÃO é link."""
    try:
        fd = os.open(caminho, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        return _so_anexar(fd, op == "+a")
    finally:
        os.close(fd)


def _tem_so_anexar(caminho):
    try:
        fd = os.open(caminho, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        return bool(_flags(fd) & FS_APPEND_FL)
    except OSError:
        return False
    finally:
        os.close(fd)


def _percorrer(raiz):
    yield raiz

    def _falha(erro):
        raise erro      # diretório ilegível não pode virar "conforme" em silêncio

    for base, dirs, arqs in os.walk(raiz, followlinks=False, onerror=_falha):
        for n in dirs + arqs:
            yield Path(base) / n


def _rel(raiz, p):
    r = Path(p).relative_to(raiz).as_posix()
    return "." if r == "." else r


# ----------------------------------------------------------------------------------------------- aplicar

def _garantir_dir(dirfd, nome, modo=0o700):
    try:
        os.mkdir(nome, modo, dir_fd=dirfd)
    except FileExistsError:
        pass
    return os.open(nome, O_DIR, dir_fd=dirfd)


def _fixar(fd, uid, gid, modo):
    os.fchown(fd, uid, gid)        # antes do chmod: chown limpa setuid/setgid
    os.fchmod(fd, modo)


SUMIU_OU_TROCADO = (errno.ENOENT, errno.ELOOP, errno.ENOTDIR, errno.ESTALE)


PROFUNDIDADE_MAXIMA = 64


def _aplicar_dir(dirfd, rel, spec, raiz_dev, avisos):
    if rel.count("/") >= PROFUNDIDADE_MAXIMA:
        avisos.append(f"{rel}: profundidade acima de {PROFUNDIDADE_MAXIMA} — não percorrido")
        return
    nomes_log = set(nomes_de_log(spec)) if rel == "logs" else set()
    for nome in os.listdir(dirfd):
        if nome in nomes_log:
            continue
        relf = nome if rel == "." else f"{rel}/{nome}"
        try:
            _aplicar_entrada(dirfd, nome, rel, relf, spec, raiz_dev, avisos)
        except OSError as erro:
            if erro.errno not in SUMIU_OU_TROCADO:
                raise
            avisos.append(f"{relf}: removido ou trocado durante a aplicação — não tocado")      # nunca segue o que apareceu


def _aplicar_entrada(dirfd, nome, rel, relf, spec, raiz_dev, avisos):
    st = os.stat(nome, dir_fd=dirfd, follow_symlinks=False)
    if stat.S_ISLNK(st.st_mode):
        uid, gid, _ = _dados(spec, relf, "arq")
        os.chown(nome, uid, gid, dir_fd=dirfd, follow_symlinks=False)     # o próprio link; o alvo nunca é tocado
        return
    if st.st_dev != raiz_dev:
        avisos.append(f"{relf}: outro filesystem (montagem) — não tocado")
        return
    if stat.S_ISDIR(st.st_mode):
        fd = os.open(nome, O_DIR, dir_fd=dirfd)
        try:
            if os.fstat(fd).st_ino != st.st_ino:
                avisos.append(f"{relf}: trocado durante a aplicação — não tocado")
                return
            uid, gid, modo = _dados(spec, relf, "dir")
            _fixar(fd, uid, gid, modo)
            _aplicar_dir(fd, relf, spec, raiz_dev, avisos)
        finally:
            os.close(fd)
    elif stat.S_ISREG(st.st_mode):
        fd = os.open(nome, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
        try:
            fst = os.fstat(fd)
            if fst.st_ino != st.st_ino or not stat.S_ISREG(fst.st_mode):
                avisos.append(f"{relf}: trocado durante a aplicação — não tocado")
            elif fst.st_nlink > 1:
                avisos.append(f"{relf}: mais de um link físico — não tocado (poderia ser alvo fora da área)")
            else:
                uid, gid, modo = _dados(spec, relf, "arq")
                _fixar(fd, uid, gid, modo)
        finally:
            os.close(fd)
    else:
        avisos.append(f"{relf}: arquivo especial — não tocado")


def _criar_areas(raizfd, spec):
    for a in spec["areas"]:
        fd = os.dup(raizfd)
        try:
            if a["caminho"] != ".":
                for parte in a["caminho"].split("/"):
                    novo = _garantir_dir(fd, parte)
                    os.close(fd)
                    fd = novo
            s = os.open(SENTINELA, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o640, dir_fd=fd)
            try:
                if not stat.S_ISREG(os.fstat(s).st_mode):
                    raise OSError(errno.EINVAL, f"{a['caminho']}/{SENTINELA} não é arquivo comum")
            finally:
                os.close(s)
        finally:
            os.close(fd)


def _aplicar_logs(raizfd, spec, avisos):
    try:
        logfd = os.open("logs", O_DIR, dir_fd=raizfd)
    except FileNotFoundError:
        return
    try:
        area = area_de(spec, "logs")
        uid, gid = spec["contas"][area["dono"]], spec["grupos"][area["grupo"]]
        for nome in nomes_de_log(spec):
            fd = os.open(nome, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o640, dir_fd=logfd)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
                    avisos.append(f"logs/{nome}: não é arquivo comum de link único — não tocado")
                    continue
                _so_anexar(fd, False)
                _fixar(fd, uid, gid, 0o640)
                if not _so_anexar(fd, True):
                    avisos.append(f"chattr +a indisponível em logs/{nome}: log não é só-anexar neste filesystem")
            finally:
                os.close(fd)
    finally:
        os.close(logfd)


def _aplicar_homes(home_base, spec):
    """Cria/ajusta home e tmp de cada papel por descritor. O home_base precisa existir, ser do root e não ser gravável por papel."""
    st = os.lstat(home_base)
    if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise SystemExit(f"home_base {home_base} deve ser diretório real do root, sem escrita para grupo/outros (crie-o antes)")
    hb = os.open(home_base, O_DIR)
    erros = []
    try:
        for nome, p in spec["papeis"].items():
            uid = spec["contas"][p["conta"]]
            try:
                h = _garantir_dir(hb, nome)
                try:
                    _fixar(h, uid, uid, 0o700)
                    t = _garantir_dir(h, "tmp")
                    try:
                        _fixar(t, uid, uid, 0o700)
                    finally:
                        os.close(t)
                finally:
                    os.close(h)
            except OSError as erro:
                erros.append(f"{nome}: {erro}")           # um papel adulterado não impede os demais de serem corrigidos
    finally:
        os.close(hb)
    if erros:
        raise OSError("home(s) não ajustado(s) (link ou entrada plantada?): " + "; ".join(erros))


def ancestrais_inseguros(raiz, spec):
    """Diretórios acima da raiz que algum papel atravessaria SEM poder ou que poderia alterar (renomear/trocar a raiz)."""
    div, real = [], os.path.realpath(raiz)
    uids_de_papel = {spec["contas"][p["conta"]] for p in spec["papeis"].values()}
    atual = real
    while atual != "/":
        st = os.stat(atual)
        modo = stat.S_IMODE(st.st_mode)
        if atual != real and st.st_uid in uids_de_papel:
            div.append(f"ancestral pertence a uma conta de papel (o dono sempre pode mudar o modo): {atual}")
        for nome in spec["papeis"]:
            uid, _, gids = ids_papel(spec, nome)
            if atual != real and not _bit(uid, gids, st.st_uid, st.st_gid, modo, 1):
                div.append(f"ancestral não atravessável pelo papel {nome}: {atual}")
            if atual != real and not modo & 0o1000 and _bit(uid, gids, st.st_uid, st.st_gid, modo, 2) and uid != 0:
                div.append(f"ancestral gravável pelo papel {nome} (permite trocar a raiz): {atual}")
        atual = os.path.dirname(atual)
    return div


def aplicar(raiz, spec, home_base=None):
    if os.geteuid() != 0:
        raise SystemExit("aplicar exige root (chown); nada foi alterado")
    perigosos = [d for d in ancestrais_inseguros(raiz, spec) + (ancestrais_inseguros(home_base, spec) if home_base else [])
                 if "gravável" in d or "pertence" in d]
    if perigosos:
        raise SystemExit("aplicar recusado: a raiz poderia ser trocada por um papel:\n  - " + "\n  - ".join(perigosos[:5]))
    avisos = []
    raizfd = os.open(raiz, O_DIR)
    try:
        _criar_areas(raizfd, spec)
        st = os.fstat(raizfd)
        uid, gid, modo = _dados(spec, ".", "dir")
        _fixar(raizfd, uid, gid, modo)
        _aplicar_dir(raizfd, ".", spec, st.st_dev, avisos)
        _aplicar_logs(raizfd, spec, avisos)
    finally:
        os.close(raizfd)
    if home_base:
        _aplicar_homes(home_base, spec)
    return avisos


# ----------------------------------------------------------------------------------------------- auditar

def _xattrs_perigosos(caminho):
    try:
        return [x for x in os.listxattr(caminho, follow_symlinks=False) if x in XATTRS_PERIGOSOS]
    except OSError as erro:
        if erro.errno in (errno.ENOTSUP, errno.ENODATA):
            return []       # filesystem sem xattr: nada a conferir
        return ["xattr ilegível"]       # qualquer outro erro (ex.: EACCES) NÃO vira "sem ACL"


def _mais_permissivo(encontrado, esperado):
    return bool(encontrado & ~esperado & 0o7777)


def auditar(raiz, spec, home_base=None):
    raiz = Path(raiz)
    div = []
    dev_raiz = os.lstat(raiz).st_dev
    log_ok = set(nomes_de_log(spec))
    for a in spec["areas"]:
        if not (raiz / a["caminho"]).is_dir():
            div.append(f"área ausente: {a['caminho']} (a jaula precisa do ponto de montagem; rode aplicar)")
    for p in _percorrer(raiz):
        rel = _rel(raiz, p)
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            continue                                    # sumiu durante a varredura (sessão ativa): nada a auditar
        except OSError as erro:
            div.append(f"{rel}: não auditável ({erro.strerror})")      # ex.: caminho longo demais — nunca vira "conforme"
            continue
        if stat.S_ISLNK(st.st_mode):
            alvo = Path(os.path.realpath(p))
            try:
                alvo_rel = alvo.relative_to(os.path.realpath(raiz)).as_posix()
            except ValueError:
                div.append(f"symlink aponta para fora do projeto: {rel}")
                continue
            if area_de(spec, alvo_rel) is not area_de(spec, rel):
                div.append(f"symlink cruza áreas: {rel} -> {alvo_rel}")
            continue
        modo = stat.S_IMODE(st.st_mode)
        if st.st_dev != dev_raiz:
            div.append(f"outro filesystem (montagem) dentro do projeto: {rel}")
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            div.append(f"arquivo especial (fifo/socket/dispositivo): {rel}")
            continue
        if modo & 0o002:
            div.append(f"gravável por 'outros': {rel}")
        if stat.S_ISREG(st.st_mode) and modo & 0o6000:
            div.append(f"setuid/setgid em arquivo: {rel}")
        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            div.append(f"mais de um link físico: {rel}")
        if _xattrs_perigosos(p):
            div.append(f"ACL ou capability de arquivo em {rel}")
        if rel.startswith("logs/") and rel.count("/") == 1 and p.name != SENTINELA:
            if p.name not in log_ok:
                div.append(f"arquivo inesperado em logs/: {p.name}")
            continue
        tipo = "dir" if stat.S_ISDIR(st.st_mode) else "arq"
        uid, gid, esperado = _dados(spec, rel, tipo)
        area = area_de(spec, rel)
        if area["escrita"] and rel != area["caminho"]:
            # área em que o papel dono grava (umask 0027 etc.): dono e grupo exatos, modo nunca MAIS permissivo
            ruim = (st.st_uid, st.st_gid) != (uid, gid) or _mais_permissivo(modo, esperado | (0o2000 if tipo == "dir" else 0))
        else:
            ruim = (st.st_uid, st.st_gid) != (uid, gid) or modo != esperado
        if ruim:
            div.append(f"{rel}: encontrado {st.st_uid}:{st.st_gid} {oct(modo)}, esperado {uid}:{gid} {oct(esperado)}")
    area_logs = area_de(spec, "logs")
    for nome in log_ok:
        arq = raiz / "logs" / nome
        if not arq.exists():
            continue
        st = os.lstat(arq)
        if (st.st_uid, st.st_gid) != (spec["contas"][area_logs["dono"]], spec["grupos"][area_logs["grupo"]]) \
                or stat.S_IMODE(st.st_mode) != 0o640:
            div.append(f"log {nome}: dono, grupo ou modo incorretos")
        if not _tem_so_anexar(arq):
            div.append(f"log {nome} não é só-anexar (chattr +a)")
    try:
        if Path("/proc/sys/fs/protected_hardlinks").read_text().strip() != "1":
            div.append("fs.protected_hardlinks != 1: hardlink de arquivo legível por papel sem escrita seria possível")
    except OSError:
        div.append("não foi possível ler fs.protected_hardlinks")
    div.extend(ancestrais_inseguros(raiz, spec))
    if home_base:
        for nome, p in spec["papeis"].items():
            for sub in (Path(home_base) / nome, Path(home_base) / nome / "tmp"):
                try:
                    st = os.lstat(sub)
                except OSError:
                    div.append(f"home ausente: {sub}")
                    continue
                if stat.S_ISLNK(st.st_mode) or st.st_uid != spec["contas"][p["conta"]] or stat.S_IMODE(st.st_mode) != 0o700:
                    div.append(f"home do papel {nome} com dono, modo ou tipo incorretos: {sub}")
    return sorted(set(div))


# ----------------------------------------------------------------------------------------------- sondar

def _como(uid, gid, gids, funcao):
    """Executa `funcao()` num filho com os ids do papel; devolve o resultado serializável."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            os.setgroups(gids)
            os.setgid(gid)
            os.setuid(uid)
            try:
                os.setuid(0)
                recuperou = True
            except PermissionError:
                recuperou = False
            resultado = {"recuperou_root": recuperou, **funcao()}
        except Exception as erro:       # falha do próprio teste
            resultado = {"erro_do_teste": repr(erro)}
        os.write(w, json.dumps(resultado).encode())
        os._exit(0)
    os.close(w)
    dados = b""
    while True:
        bloco = os.read(r, 65536)
        if not bloco:
            break
        dados += bloco
    os.close(r)
    os.waitpid(pid, 0)
    return json.loads(dados or b"{}")


def _ler(caminho):
    with open(caminho, "rb") as f:
        return f.read()


def _abrir_rw(caminho):
    with open(caminho, "r+b"):
        pass


NEGACOES = (errno.EACCES, errno.EPERM)


def _acesso(caminho, modo):
    """os.access com a ressalva: filesystem somente leitura ou caminho ausente NÃO é negação do DAC (None = inconclusivo);
    permissão negada para chegar ao caminho (EACCES/EPERM) é, sim, negação (False)."""
    try:
        os.lstat(caminho)
        if modo & os.W_OK and os.statvfs(caminho).f_flag & os.ST_RDONLY:
            return None
    except PermissionError:
        return False
    except OSError:
        return None
    return os.access(caminho, modo)


def _tentar(fn):
    """True = a operação funcionou; False = o kernel NEGOU (EACCES/EPERM); None = falhou por outro motivo (inconclusivo)."""
    try:
        fn()
        return True
    except OSError as erro:
        return False if erro.errno in NEGACOES else None


def _acesso_arquivo_de_log(arq):
    """Escrita no log: sem atravessar a pasta é negação do DAC (EACCES); com a pasta atravessável o arquivo precisa existir."""
    if os.access(arq.parent, os.X_OK):
        return _acesso(arq, os.W_OK)
    return False


def _sondas(raiz, spec, papel):
    uid, gid, gids = ids_papel(spec, papel)
    raiz = Path(raiz)

    def corpo():
        res, pid = {}, os.getpid()
        escrevivel = None
        for a in spec["areas"]:
            d = raiz / a["caminho"]
            s = d / SENTINELA
            c = a["caminho"]
            res[f"{c}|listar"] = _tentar(lambda: os.listdir(d))
            res[f"{c}|ler"] = _tentar(lambda: _ler(s))
            nome = d / f".sonda-{pid}"

            def criar():
                os.close(os.open(nome, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            res[f"{c}|criar"] = _tentar(criar)
            if res[f"{c}|criar"]:
                _tentar(lambda: os.unlink(nome))
                escrevivel = escrevivel or d
            res[f"{c}|sobrescrever"] = _tentar(lambda: _abrir_rw(s))
            ra = _acesso(d, os.W_OK | os.X_OK)
            res[f"{c}|renomear"] = ra if ra is None else (ra and os.access(d.parent, os.X_OK))       # renomear exige escrita na pasta (sem renomear)
        ataques = {}
        if escrevivel is not None:
            for a in spec["areas"]:
                s = raiz / a["caminho"] / SENTINELA
                elo, duro = escrevivel / f".elo-{pid}", escrevivel / f".duro-{pid}"

                def via_elo():
                    os.symlink(s, elo)
                    try:
                        _ler(elo)
                    finally:
                        os.unlink(elo)
                ataques[f"{a['caminho']}|via_symlink"] = _tentar(via_elo)

                def via_duro():
                    os.link(s, duro)
                    os.unlink(duro)
                ataques[f"{a['caminho']}|hardlink"] = _tentar(via_duro)
        ataques["raiz|mover_area_registros"] = _acesso(raiz, os.W_OK | os.X_OK)         # renomear registros/ exige escrita na raiz
        logs = {}
        for nome in nomes_de_log(spec):
            arq = raiz / "logs" / nome
            # sem tocar nos logs reais: acesso de escrita no arquivo cobre anexar e truncar; escrita na pasta cobre apagar/criar
            logs[f"{nome}|anexar"] = _acesso_arquivo_de_log(arq)
            logs[f"{nome}|truncar"] = logs[f"{nome}|anexar"]
            logs[f"{nome}|apagar"] = _acesso(raiz / "logs", os.W_OK | os.X_OK)
            logs[f"{nome}|criar_outro"] = logs[f"{nome}|apagar"]
        return {"areas": res, "ataques": ataques, "logs": logs}
    return _como(uid, gid, gids, corpo)


def sondar(raiz, spec):
    if os.geteuid() != 0:
        raise SystemExit("sondar exige root (para assumir os ids dos papéis); nada foi alterado")
    divergencias, registro = [], {}
    for nome in nomes_de_log(spec):
        if not (Path(raiz) / "logs" / nome).exists():
            divergencias.append(f"log {nome} ausente: a sondagem não pode afirmar que a escrita é negada")
    for papel in spec["papeis"]:
        r = _sondas(raiz, spec, papel)
        registro[papel] = r
        if "erro_do_teste" in r:
            divergencias.append(f"{papel}: erro do próprio teste: {r['erro_do_teste']}")
            continue
        if r["recuperou_root"]:
            divergencias.append(f"{papel}: processo recuperou root após setuid")
        for chave, obtido in r["areas"].items():
            caminho, op = chave.split("|")
            previsto = prever(spec, papel, caminho, op)
            if obtido is None:
                divergencias.append(f"{papel} {caminho} {op}: INCONCLUSIVO (falhou por outro motivo que não a negação do kernel)")
            elif obtido != previsto:
                divergencias.append(f"{papel} {caminho} {op}: obtido {obtido}, previsto {previsto}")
        for chave, obtido in r["ataques"].items():
            caminho, ataque = chave.split("|")
            if ataque == "via_symlink":
                previsto = prever(spec, papel, caminho, "ler")
            elif ataque == "hardlink":      # com fs.protected_hardlinks=1: só quem lê E grava o original
                previsto = prever(spec, papel, caminho, "ler") and prever(spec, papel, caminho, "sobrescrever")
            else:
                previsto = False
            if obtido is None:
                divergencias.append(f"{papel} ataque {chave}: INCONCLUSIVO")
            elif obtido != previsto:
                divergencias.append(f"{papel} ataque {chave}: obtido {obtido}, previsto {previsto}")
        for chave, obtido in r["logs"].items():
            nome, op = chave.split("|")
            if obtido is None:
                divergencias.append(f"{papel} logs/{nome} {op}: INCONCLUSIVO")
            elif obtido:            # nenhum papel anexa, trunca, apaga ou cria em logs/: só o serviço de log escreve
                divergencias.append(f"{papel} conseguiu '{op}' em logs/{nome}")
    return divergencias, registro
