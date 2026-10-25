#!/usr/bin/env python3
"""Lançador de sessão do Claude Code (GOV-05/06/07/08): configuração blindada + papel de SO sem privilégio + rede só pelo gateway.

Sem `--papel` (SOMENTE dados sintéticos, sem isolamento de SO; como root exige `--sem-isolamento` explícito):
  1. recusa iniciar se `verificar_configuracao.py` achar qualquer problema;
  2. passa os controles por `--settings` e ignora a fonte `local` (`--setting-sources user,project`).

Com `--papel` (obrigatório para dados reais; exige executar como root ou já como a conta do papel):
  3. valida `governanca/papeis.json` e AUDITA a árvore (donos, modos, links, ACL, logs só-anexar); recusa se divergir;
  4. rebaixa o processo para a conta do papel: uid, gid, grupos suplementares, `no_new_privs`, sem capabilities, umask 0027;
  5. ambiente mínimo entregue por `execve` (NUNCA em argv): HOME próprio, PATH fixo, socket do serviço de log;
  6. `--rede gateway` (padrão): jaula com namespace de rede vazio; a única saída é o gateway, que injeta a credencial —
     a chave da API NÃO entra no ambiente da sessão. `--rede aberta` mantém a rede do host e repassa as variáveis de
     autenticação ao processo (somente dados sintéticos; a chave fica visível ao agente);
  7. `settings` gerado por papel (root, fora do HOME do papel): controles do projeto + `deny` de leitura das áreas que o
     papel não lê + bloqueio de WebFetch/WebSearch; fontes `user` e `local` ignoradas.

Uso:  python3 scripts/iniciar_sessao.py [--papel NOME] [--rede gateway|aberta] [--jaula] [--dry-run] [--sandbox] [--claude CAMINHO] [-- opções do claude]
      papéis: coordenador | controlador-dr | revisor | p1..p7 (cada agente de produto tem a sua conta)

Não substitui revisão humana nem autentica o usuário. Settings gerenciados da organização continuam com precedência.
"""
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolamento as ISO  # noqa: E402
import jaula as JAULA  # noqa: E402
import verificar_configuracao as V  # noqa: E402

PATH_FIXO = "/usr/local/bin:/usr/bin:/bin"
ENV_AUTENTICACAO = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_BASE_URL",
                    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
                    "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE")
ENV_PERMITIDAS = ENV_AUTENTICACAO + ("LANG", "TERM")
SEGREDOS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PROXY")
# Lista BRANCA do que o operador pode repassar ao claude (tudo que começa com '-' e não está aqui é recusado).
OPCOES_PERMITIDAS = {"-p", "--print", "--output-format", "--input-format", "--agent", "--model", "--verbose", "--max-turns",
                     "--continue", "-c", "--resume", "-r", "--session-id", "--include-partial-messages", "--fork-session"}
FLAGS_FIXAS = ["--setting-sources", "project", "--strict-mcp-config"]      # nada de MCP do HOME gravável, nem settings `user`/`local`
OPCOES_DO_LANCADOR = ("--dry-run", "--sandbox", "--jaula", "--sem-isolamento", "--permitir-servicos-de-teste")
BLOQUEIOS_DE_REDE = ["WebFetch", "WebSearch"]


def verificar_servico(caminho, uid_esperado, nome):
    """O socket precisa ser socket, da conta do serviço, numa pasta que só ela (ou root) pode alterar: ninguém ocupa o lugar do serviço."""
    try:
        st = os.lstat(caminho)
        pai = os.lstat(os.path.dirname(caminho))
    except OSError:
        raise SystemExit(f"Sessão NÃO iniciada: {nome} indisponível (sem {nome}, sem sessão)")
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != uid_esperado:
        raise SystemExit(f"Sessão NÃO iniciada: {nome} não é um socket da conta esperada (uid {uid_esperado}): {caminho}")
    if pai.st_uid not in (0, uid_esperado) or pai.st_mode & 0o022 or stat.S_ISLNK(pai.st_mode):
        raise SystemExit(f"Sessão NÃO iniciada: a pasta de {nome} pode ser alterada por outras contas: {os.path.dirname(caminho)}")
    atual = os.path.dirname(os.path.realpath(caminho))              # e toda a cadeia de ancestrais até a raiz
    while atual != "/":
        atual = os.path.dirname(atual)
        a = os.stat(atual)
        if a.st_mode & 0o022 and not a.st_mode & 0o1000:
            raise SystemExit(f"Sessão NÃO iniciada: ancestral de {nome} gravável por outras contas (sem sticky): {atual}")


def _terminal_inseguro(sysctl="/proc/sys/dev/tty/legacy_tiocsti", release=None, tem_terminal=None):
    """True se há terminal de controle e o kernel permite TIOCSTI (a jaula não usa --new-session: quebraria o uso interativo).

    Com o sysctl: valor 1 permite. Sem o sysctl: kernels anteriores a 6.2 sempre permitem; a partir do 6.2 a ausência do arquivo
    significa que o recurso foi compilado fora (CONFIG_LEGACY_TIOCSTI=n)."""
    tem_terminal = any(os.isatty(fd) for fd in (0, 1, 2)) if tem_terminal is None else tem_terminal
    if not tem_terminal:
        return False
    try:
        return Path(sysctl).read_text().strip() == "1"
    except OSError:
        pass
    try:
        maior, menor = (int(x) for x in (release or os.uname().release).split(".")[:2])
    except ValueError:
        return True             # versão ilegível: não presume que é seguro
    return (maior, menor) < (6, 2)


def _limpar_temporarios_antigos(dias=30):
    """Remove arquivos de settings gerados em lançamentos anteriores (só os do próprio root, em /var/tmp)."""
    import time
    pasta = Path("/var/tmp")
    if not pasta.is_dir():
        return
    limite = time.time() - dias * 86400
    for arq in pasta.glob("ppp-settings-*.json"):
        try:
            st = arq.lstat()
            if st.st_uid == os.geteuid() and st.st_mtime < limite and arq.is_file() and not arq.is_symlink():
                arq.unlink()
        except OSError:
            pass


def _temporario_do_root(conteudo):
    """Arquivo criado por quem lança (root), O_EXCL, 0644, em /var/tmp (a jaula esconde /tmp): o papel lê, não troca."""
    _limpar_temporarios_antigos()
    fd, caminho = tempfile.mkstemp(prefix="ppp-settings-", suffix=".json", dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(conteudo, f, ensure_ascii=False)
        os.fchmod(f.fileno(), 0o644)
    return caminho


def settings_com_sandbox():
    base = json.loads((V.RAIZ / ".claude/settings.json").read_text(encoding="utf-8"))
    base.update(json.loads((V.RAIZ / "governanca/sandbox-recomendado.json").read_text(encoding="utf-8")))
    return _temporario_do_root(base)


def regras_de_leitura(spec, papel, raiz):
    """`deny` de Read para cada área que o papel NÃO lê (camada extra; o isolamento de SO continua sendo o controle principal)."""
    return [f"Read(/{Path(raiz).as_posix()}/{a['caminho']}/**)" for a in spec["areas"]
            if papel not in a["leitura"] and a["caminho"] != "."]


def settings_do_papel(spec, papel, sandbox=False):
    base = json.loads((V.RAIZ / ".claude/settings.json").read_text(encoding="utf-8"))
    if sandbox:
        base.update(json.loads((V.RAIZ / "governanca/sandbox-recomendado.json").read_text(encoding="utf-8")))
    perm = base.setdefault("permissions", {})
    perm["deny"] = list(perm.get("deny", [])) + regras_de_leitura(spec, papel, V.RAIZ) + BLOQUEIOS_DE_REDE
    return _temporario_do_root(base)


def ambiente_do_papel(papel, home, env_origem=None, rede="gateway", logd_socket=None):
    env_origem = os.environ if env_origem is None else env_origem
    env = {"PATH": PATH_FIXO, "HOME": str(home), "TMPDIR": str(Path(home) / "tmp"), "PPP_PAPEL": papel,
           "PYTHONDONTWRITEBYTECODE": "1"}
    if logd_socket:
        env["PPP_LOGD_SOCKET"] = str(logd_socket)
    permitidas = ENV_PERMITIDAS if rede == "aberta" else ("LANG", "TERM")       # gateway: a sessão nunca recebe credencial
    env.update({k: env_origem[k] for k in permitidas if k in env_origem})
    return env


def plano_do_papel(spec, papel, argumentos, claude, home_base=None, dry_run=False, sandbox=False, jaula=False,
                   rede="gateway", logd_socket=None, gateway_socket=None, servicos_de_teste=False):
    """Monta (comando, env, cwd, uid, gid, gids) do papel; levanta SystemExit em qualquer recusa."""
    if papel not in spec["papeis"]:
        raise SystemExit(f"papel desconhecido: {papel} (válidos: {', '.join(spec['papeis'])})")
    for a in argumentos:
        if a.startswith("-") and a.split("=", 1)[0] not in OPCOES_PERMITIDAS:
            raise SystemExit(f"opção recusada (fora da lista branca; reabriria configuração, ferramentas ou permissões): {a}")
    if rede not in ("gateway", "aberta"):
        raise SystemExit(f"modo de rede desconhecido: {rede}")
    uid, gid, gids = ISO.ids_papel(spec, papel)
    euid = os.geteuid()
    if euid != 0:
        raise SystemExit("execute como root: só o root cria o settings do papel fora do alcance dele, audita a árvore e rebaixa o processo")
    home_raiz = home_base or spec["home_base"]
    home = Path(home_raiz) / papel
    div = ISO.auditar(V.RAIZ, spec, None if dry_run else home_raiz)
    if div:
        raise SystemExit("Sessão NÃO iniciada: isolamento do SO divergente:\n  - " + "\n  - ".join(div[:20]))
    if not dry_run and _terminal_inseguro():
        raise SystemExit("Sessão NÃO iniciada: há terminal de controle e dev.tty.legacy_tiocsti=1 (a sessão poderia injetar teclas no "
                         "terminal do operador). Defina `sysctl dev.tty.legacy_tiocsti=0` ou lance sem terminal (-p, serviço).")
    padrao = spec["papeis"][papel].get("agente_padrao")
    if not any(a == "--agent" or a.startswith("--agent=") for a in argumentos):
        if not padrao:
            raise SystemExit(f"o papel '{papel}' exige --agent <agente> explícito")
        argumentos = ["--agent", padrao, *argumentos]
    servicos = spec.get("servicos", {})
    logd_socket = logd_socket or servicos.get("logd_socket")
    gateway_socket = gateway_socket or servicos.get("gateway_socket")
    if not dry_run:
        if not logd_socket or not os.path.exists(logd_socket):
            raise SystemExit("Sessão NÃO iniciada: serviço de log indisponível (sem trilha, sem sessão)")
        if rede == "gateway" and (not gateway_socket or not os.path.exists(gateway_socket)):
            raise SystemExit("Sessão NÃO iniciada: gateway de rede indisponível (sem rede, sem sessão)")
        if not servicos_de_teste:
            verificar_servico(logd_socket, spec["contas"][servicos["conta_log"]], "serviço de log")
            if rede == "gateway":
                verificar_servico(gateway_socket, spec["contas"][servicos["conta_rede"]], "gateway de rede")
    env = ambiente_do_papel(papel, home, rede=rede, logd_socket=logd_socket)
    extra_ro = [os.path.dirname(s) for s in (logd_socket, gateway_socket) if s and os.path.dirname(s) != servicos.get("dir")]
    extra_ro.append(os.path.dirname(os.path.realpath(claude)))      # o executável precisa continuar visível se estiver numa pasta oculta
    if dry_run:
        settings = "<temporario-do-root>/ppp-settings.json"
    else:
        settings = settings_do_papel(spec, papel, sandbox)
        extra_ro.append(settings)
    flags = ["--settings", settings, *FLAGS_FIXAS]
    prefixo = []
    setpriv = shutil.which("setpriv")
    if not setpriv:
        raise SystemExit("setpriv (util-linux) não encontrado: sem como rebaixar privilégios com segurança")
    prefixo = [setpriv, f"--reuid={uid}", f"--regid={gid}", "--groups=" + ",".join(str(g) for g in gids if g != gid),
               "--no-new-privs", "--inh-caps=-all", "--bounding-set=-all"]
    envolucro = []
    if jaula or rede == "gateway":
        if not shutil.which("bwrap"):
            raise SystemExit("jaula/gateway exigem bubblewrap (bwrap): sem ele a sessão não inicia")
        envolucro = [*JAULA.argumentos_jaula(spec, papel, V.RAIZ, home, rede=rede, extra_ro=extra_ro), "--"]
    ponte = []
    if rede == "gateway":
        ponte = [os.path.realpath(sys.executable), "-I", "-B", str(V.RAIZ / "scripts/entrada_jaula.py"),
                 "--gateway", str(gateway_socket), "--"]
    comando = [*prefixo, *envolucro, *ponte, claude, *flags, *argumentos]
    return comando, env, V.RAIZ, uid, gid, gids


def mascarar(comando):
    return ["{}=<omitido>".format(c.split("=", 1)[0]) if "=" in c and any(s in c.split("=", 1)[0] for s in SEGREDOS) else c
            for c in comando]


def mascarar_ambiente(env):
    return {k: ("<omitido>" if any(s in k for s in SEGREDOS) else v) for k, v in env.items()}


def montar(argumentos, claude=None, sandbox=False):
    """Caminho sem papel (dados sintéticos)."""
    problemas = V.verificar()
    if problemas:
        raise SystemExit("Sessão NÃO iniciada:\n  - " + "\n  - ".join(problemas))
    claude = claude or shutil.which("claude")
    if not claude:
        raise SystemExit("executável 'claude' não encontrado no PATH")
    settings = settings_com_sandbox() if sandbox else str(V.RAIZ / ".claude/settings.json")
    return [claude, "--settings", settings, "--setting-sources", "user,project", *argumentos]


def _opcao(argv, nome):
    if nome in argv:
        i = argv.index(nome)
        valor = argv[i + 1] if i + 1 < len(argv) else None
        if valor is None:
            raise SystemExit(f"{nome} exige um valor")
        return valor, argv[:i] + argv[i + 2:]
    return None, argv


def main(argv):
    seco = "--dry-run" in argv
    sandbox = "--sandbox" in argv
    jaula = "--jaula" in argv
    sem_isolamento = "--sem-isolamento" in argv
    servicos_de_teste = "--permitir-servicos-de-teste" in argv
    resto = [a for a in argv if a not in OPCOES_DO_LANCADOR]
    papel, resto = _opcao(resto, "--papel")
    claude, resto = _opcao(resto, "--claude")
    home_base, resto = _opcao(resto, "--home-base")
    rede, resto = _opcao(resto, "--rede")
    logd_socket, resto = _opcao(resto, "--logd-socket")
    gateway_socket, resto = _opcao(resto, "--gateway-socket")
    if resto[:1] == ["--"]:
        resto = resto[1:]
    if papel is None and (jaula or rede):
        raise SystemExit("--jaula e --rede exigem --papel (o perfil de montagem e de rede vem do papel)")
    if papel is None and os.geteuid() == 0 and not sem_isolamento:
        raise SystemExit("recusado: como root, a sessão exige --papel (rebaixa privilégio) ou, só com dados sintéticos, "
                         "--sem-isolamento explícito")
    if papel is None:
        print("AVISO: sem --papel não há isolamento de SO; use SOMENTE com dados sintéticos.", file=sys.stderr)
        comando = montar(resto, claude, sandbox)
        if seco:
            print(" ".join(comando))
            return 0
        os.environ["PPP_LOG_LEGADO"] = "1"      # modo sintético: o guarda grava o log direto no arquivo (sem serviço de log)
        os.chdir(V.RAIZ)
        os.execv(comando[0], comando)
    problemas = V.verificar()
    if problemas:
        raise SystemExit("Sessão NÃO iniciada:\n  - " + "\n  - ".join(problemas))
    spec = ISO.carregar()
    invalidos = ISO.validar(spec)
    if invalidos:
        raise SystemExit("papeis.json inválido:\n  - " + "\n  - ".join(invalidos))
    claude = claude or shutil.which("claude")
    if not claude:
        raise SystemExit("executável 'claude' não encontrado no PATH")
    rede = rede or "gateway"
    if rede == "aberta":
        print("AVISO: --rede aberta: a sessão tem rede do host e recebe a credencial no ambiente; use SOMENTE com dados sintéticos.",
              file=sys.stderr)
    comando, env, cwd, uid, gid, gids = plano_do_papel(spec, papel, resto, claude, home_base, seco, sandbox, jaula, rede,
                                                       logd_socket, gateway_socket, servicos_de_teste)
    if seco:
        print(json.dumps({"comando": mascarar(comando), "env": mascarar_ambiente(env), "cwd": str(cwd), "uid": uid, "gid": gid,
                          "grupos": gids, "rede": rede}))
        return 0
    os.chdir(cwd)
    os.umask(0o027)
    os.closerange(3, 65536)              # nenhum descritor herdado do operador (ex.: --chave-fd) chega à sessão
    os.execve(comando[0], comando, dict(env))       # credenciais (modo aberto) só no ambiente herdado, nunca em argv


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
