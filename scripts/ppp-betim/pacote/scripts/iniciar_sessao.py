#!/usr/bin/env python3
"""Lançador de sessão do Claude Code (GOV-05/06/07): configuração blindada + papel de SO sem privilégio.

Sem `--papel` (SOMENTE dados sintéticos, sem isolamento de SO):
  1. recusa iniciar se `verificar_configuracao.py` achar qualquer problema;
  2. passa os controles por `--settings` e ignora a fonte `local` (`--setting-sources user,project`).

Com `--papel` (obrigatório para dados reais; exige executar como root ou já como a conta do papel):
  3. valida `governanca/papeis.json` e AUDITA a árvore (donos, modos, setuid, symlinks, logs só-anexar); recusa se divergir;
  4. rebaixa o processo para a conta do papel: uid, gid, grupos suplementares, `no_new_privs`, sem capabilities, umask 0027;
  5. entrega ao `claude` só um ambiente mínimo: HOME próprio do papel, PATH fixo e variáveis de autenticação/proxy permitidas
     (nenhuma credencial é gravada em disco por este script; use variável de ambiente do operador).

Uso:  python3 scripts/iniciar_sessao.py [--papel NOME] [--jaula] [--sem-isolamento] [--dry-run] [--sandbox] [--claude CAMINHO] [-- opções do claude]
      --jaula  (com --papel) envolve o processo inteiro numa jaula bwrap de montagens (scripts/jaula.py)
      papéis: coordenador | controlador-dr | revisor | agentes (este exige --agent pN-...)

Não substitui revisão humana nem autentica o usuário. Settings gerenciados da organização continuam com precedência.
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolamento as ISO  # noqa: E402
import jaula as JAULA  # noqa: E402
import verificar_configuracao as V  # noqa: E402

PATH_FIXO = "/usr/local/bin:/usr/bin:/bin"
ENV_PERMITIDAS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_BASE_URL",
                  "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
                  "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "LANG", "TERM")
SEGREDOS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PROXY")
OPCOES_PROIBIDAS = ("--settings", "--setting-sources", "--dangerously-skip-permissions", "--permission-mode",
                    "--allow-dangerously-skip-permissions", "--add-dir", "--mcp-config", "--plugin-dir")


def settings_com_sandbox(destino_dir=None, dono=None):
    base = json.loads((V.RAIZ / ".claude/settings.json").read_text(encoding="utf-8"))
    base.update(json.loads((V.RAIZ / "governanca/sandbox-recomendado.json").read_text(encoding="utf-8")))
    # Em /var/tmp (sticky; a jaula esconde /tmp, não /var/tmp), O_EXCL, dono de quem lança (root): o papel lê, não troca
    fd, caminho = tempfile.mkstemp(prefix="ppp-settings-", suffix=".json", dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(base, f, ensure_ascii=False)
    os.chmod(caminho, 0o644)
    return caminho


def ambiente_do_papel(papel, home, env_origem=None):
    env_origem = os.environ if env_origem is None else env_origem
    env = {"PATH": PATH_FIXO, "HOME": str(home), "TMPDIR": str(Path(home) / "tmp"), "PPP_PAPEL": papel,
           "PYTHONDONTWRITEBYTECODE": "1"}
    env.update({k: env_origem[k] for k in ENV_PERMITIDAS if k in env_origem})
    return env


def plano_do_papel(spec, papel, argumentos, claude, home_base=None, dry_run=False, sandbox=False, jaula=False):
    """Monta (comando, env, cwd, uid, gid, gids) do papel; levanta SystemExit em qualquer recusa."""
    if papel not in spec["papeis"]:
        raise SystemExit(f"papel desconhecido: {papel} (válidos: {', '.join(spec['papeis'])})")
    for a in argumentos:
        if a.split("=", 1)[0] in OPCOES_PROIBIDAS:
            raise SystemExit(f"opção recusada (reabriria configuração ou permissões): {a}")
    uid, gid, gids = ISO.ids_papel(spec, papel)
    euid = os.geteuid()
    if euid not in (0, uid):
        raise SystemExit(f"execute como root (para rebaixar) ou como a conta do papel (uid {uid}); uid atual {euid}")
    if euid == 0:
        div = ISO.auditar(V.RAIZ, spec)
        if div:
            raise SystemExit("Sessão NÃO iniciada: isolamento do SO divergente:\n  - " + "\n  - ".join(div[:20]))
    elif set(os.getgroups()) | {gid} != set(gids):
        raise SystemExit("grupos do processo diferem dos do papel; use o lançador como root ou `sudo -u` com os grupos corretos")
    padrao = spec["papeis"][papel].get("agente_padrao")
    if "--agent" not in argumentos:
        if not padrao:
            raise SystemExit(f"o papel '{papel}' exige --agent <agente> explícito")
        argumentos = ["--agent", padrao, *argumentos]
    home = Path(home_base or spec["home_base"]) / papel
    env = ambiente_do_papel(papel, home)
    settings = str(V.RAIZ / ".claude/settings.json")
    if sandbox:
        settings = "<temporario>/ppp-settings.json" if dry_run else settings_com_sandbox()
    flags = ["--settings", settings, "--setting-sources", "user,project"]
    prefixo = []
    if euid == 0:
        setpriv = shutil.which("setpriv")
        if not setpriv:
            raise SystemExit("setpriv (util-linux) não encontrado: sem como rebaixar privilégios com segurança")
        prefixo = [setpriv, f"--reuid={uid}", f"--regid={gid}", "--groups=" + ",".join(str(g) for g in gids if g != gid),
                   "--no-new-privs", "--inh-caps=-all", "--bounding-set=-all"]
    envolucro = []
    if jaula:
        if not shutil.which("bwrap"):
            raise SystemExit("--jaula exige bubblewrap (bwrap): sem ele a sessão não inicia")
        envolucro = [*JAULA.argumentos_jaula(spec, papel, V.RAIZ, home), "--"]
    comando = [*prefixo, *envolucro, "/usr/bin/env", "-i", *[f"{k}={v}" for k, v in env.items()], claude, *flags, *argumentos]
    return comando, env, V.RAIZ, uid, gid, gids


def mascarar(comando):
    return ["{}=<omitido>".format(c.split("=", 1)[0]) if "=" in c and any(s in c.split("=", 1)[0] for s in SEGREDOS) else c
            for c in comando]


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
        return valor, argv[:i] + argv[i + 2:]
    return None, argv


def main(argv):
    seco = "--dry-run" in argv
    sandbox = "--sandbox" in argv
    jaula = "--jaula" in argv
    sem_isolamento = "--sem-isolamento" in argv
    resto = [a for a in argv if a not in ("--dry-run", "--sandbox", "--jaula", "--sem-isolamento")]
    papel, resto = _opcao(resto, "--papel")
    claude, resto = _opcao(resto, "--claude")
    home_base, resto = _opcao(resto, "--home-base")
    if resto[:1] == ["--"]:
        resto = resto[1:]
    if "--papel" in argv and papel is None:
        raise SystemExit("--papel exige um valor")
    if papel is None and jaula:
        raise SystemExit("--jaula exige --papel (o perfil de montagem vem do papel)")
    if papel is None and os.geteuid() == 0 and not sem_isolamento:
        raise SystemExit("recusado: como root, a sessão exige --papel (rebaixa privilégio) ou, só com dados sintéticos, "
                         "--sem-isolamento explícito")
    if papel is None:
        print("AVISO: sem --papel não há isolamento de SO; use SOMENTE com dados sintéticos.", file=sys.stderr)
        comando = montar(resto, claude, sandbox)
        if seco:
            print(" ".join(comando))
            return 0
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
    comando, env, cwd, uid, gid, gids = plano_do_papel(spec, papel, resto, claude, home_base, seco, sandbox, jaula)
    if seco:
        print(json.dumps({"comando": mascarar(comando), "cwd": str(cwd), "uid": uid, "gid": gid, "grupos": gids}))
        return 0
    os.chdir(cwd)
    os.umask(0o027)
    os.execv(comando[0], comando)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
