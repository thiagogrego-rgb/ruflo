"""Cenários do piloto controlado (GOV-09), parte 1: contexto e cenários S01–S07.

Cada cenário devolve {"id","titulo","resultado": PASSOU|FALHOU|NAO_EXECUTADO,"evidencia": {...determinística...},"volatil": {...}}.
`evidencia` entra na comparação de reprodutibilidade; `volatil` (pids, tempos) não.
Honestidade de método: com `modo = "laboratorio-modelo-simulado"` o destino da API é um MODELO FALSO local — isso NÃO é uma chamada
real ao provedor. Só o cenário S04 com `modo = "api-real"` e credencial provisionada por humano conta como chamada real.
"""
import json
import os
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ancora_logs as ANC  # noqa: E402
import isolamento as ISO  # noqa: E402
import logd  # noqa: E402
import piloto_ambiente as AMB  # noqa: E402

PASSOU, FALHOU, NAO_EXECUTADO = "PASSOU", "FALHOU", "NAO_EXECUTADO"
MARCADORES = {"restritos": "SINTETICO-SEGREDO-RESTRITO-PILOTO", "entrada": "SINTETICO-ENTRADA-PILOTO", "logs": "SINTETICO-LOG-PILOTO",
              "dr": "SINTETICO-SAIDA-DR-PILOTO"}


def resultado(id_, titulo, ok, evidencia, volatil=None, motivo=None):
    if ok is None:
        return {"id": id_, "titulo": titulo, "resultado": NAO_EXECUTADO, "evidencia": {"motivo": motivo, **evidencia}, "volatil": volatil or {}}
    return {"id": id_, "titulo": titulo, "resultado": PASSOU if ok else FALHOU, "evidencia": evidencia, "volatil": volatil or {}}


class Contexto:
    """Reúne o que os cenários precisam: especificação, modelo falso (destino do gateway no laboratório) e execução de sessões."""

    def __init__(self, spec, modelo, modo="laboratorio-modelo-simulado", claude=None):
        self.spec, self.modelo, self.modo = spec, modelo, modo
        self.claude = claude
        self.logd_socket = spec["servicos"]["logd_socket"]
        self.gw_socket = spec["servicos"]["gateway_socket"]
        self.launcher = str(AMB.PROJETO / "scripts/iniciar_sessao.py")

    def uid(self, papel):
        return self.spec["contas"][self.spec["papeis"][papel]["conta"]]

    def comando_sessao(self, papel, extra=(), agente=None):
        a = ["--agent", agente] if agente else []
        cmd = [sys.executable, "-B", self.launcher, "--papel", papel]
        if self.claude:
            cmd += ["--claude", self.claude]
        return cmd + ["--", *a, "-p", "teste", "--output-format", "json", *extra]

    def sessao(self, papel, roteiro, agente=None, tempo=240):
        self.modelo.reiniciar(roteiro)
        r = subprocess.run(self.comando_sessao(papel, agente=agente), capture_output=True, text=True, timeout=tempo, stdin=subprocess.DEVNULL,
                           env={"PATH": os.environ["PATH"], "LANG": "C.UTF-8"})
        return r, [dict(x) for x in self.modelo.resultados]

    def leitura(self, rel):
        return ("Read", {"file_path": str(AMB.PROJETO / rel)})

    def como(self, papel, codigo, args=(), entrada=None):
        uid = self.uid(papel)
        grupos = ",".join(str(g) for g in ISO.ids_papel(self.spec, papel)[2] if g != uid)
        cmd = ["setpriv", f"--reuid={uid}", f"--regid={uid}", f"--groups={grupos}" if grupos else "--clear-groups", sys.executable, "-B", "-c", codigo, *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60, input=entrada)


def cria_dados_sinteticos(spec):
    """Marcadores sintéticos nas áreas sigilosas (dono e modo conforme a especificação)."""
    destinos = {"dados/restritos/SINTETICO-r.txt": MARCADORES["restritos"], "dados/entrada/SINTETICO-e.txt": MARCADORES["entrada"],
                "produtos/DR/saida/SINTETICO-dr.txt": MARCADORES["dr"], "produtos/P3/SINTETICO-p3.md": "SINTETICO conteudo do P3",
                "produtos/P4/SINTETICO-p4.md": "SINTETICO conteudo do P4", "produtos/C/SINTETICO-c.md": "SINTETICO plano de C"}
    for rel, conteudo in destinos.items():
        caminho = AMB.PROJETO / rel
        caminho.parent.mkdir(parents=True, exist_ok=True)
        caminho.write_text(f"{conteudo}\n", encoding="utf-8")
        uid, gid, modo = ISO._dados(spec, rel, "arq")
        os.chown(caminho, uid, gid)
        os.chmod(caminho, modo)


# ------------------------------------------------------------------------------------------------ S01
def s01_usuario_sem_privilegio(ctx):
    """`claude` real roda como a conta do papel: uid/gid, sem capabilities, no_new_privs, namespace de rede próprio, ambiente sem credencial."""
    ctx.modelo.atraso = 8.0
    try:
        ctx.modelo.reiniciar([ctx.leitura("produtos/P3/SINTETICO-p3.md")])
        p = subprocess.Popen(ctx.comando_sessao("p3"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL,
                             env={"PATH": os.environ["PATH"], "LANG": "C.UTF-8", "ANTHROPIC_API_KEY": "chave-do-operador-que-nao-pode-chegar"})
        uid = ctx.uid("p3")
        alvo = None
        for _ in range(60):
            time.sleep(0.5)
            for d in Path("/proc").iterdir():
                if not d.name.isdigit():
                    continue
                try:
                    status = (d / "status").read_text()
                    cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
                except OSError:
                    continue
                if f"Uid:\t{uid}\t{uid}" in status and "claude" in cmd and "bwrap" not in cmd and "setpriv" not in cmd and "entrada_jaula" not in cmd:
                    alvo = d
                    break
            if alvo:
                break
        if not alvo:
            p.kill()
            return resultado("S01", "Claude Code como usuário sem privilégios", False, {"processo_encontrado": False})
        campos = {}
        for linha in (alvo / "status").read_text().splitlines():
            k, _, v = linha.partition(":")
            campos[k] = v.strip()
        ambiente = (alvo / "environ").read_bytes().decode(errors="replace")
        rede_sessao = os.readlink(alvo / "ns/net")
        rede_host = os.readlink("/proc/self/ns/net")
        p.wait(timeout=60)
    finally:
        ctx.modelo.atraso = 0.0
    ev = {"uid_real_efetivo_salvo": campos["Uid"].split() == [str(uid)] * 4, "gid_do_papel": campos["Gid"].split()[0] == str(uid),
          "capEff_zero": int(campos["CapEff"], 16) == 0, "capBnd_zero": int(campos["CapBnd"], 16) == 0, "no_new_privs": campos["NoNewPrivs"] == "1",
          "namespace_de_rede_proprio": rede_sessao != rede_host, "chave_do_operador_no_ambiente": "chave-do-operador" in ambiente,
          "base_url_local": "ANTHROPIC_BASE_URL=http://127.0.0.1:" in ambiente, "nao_e_root": uid != 0}
    ok = all(v for k, v in ev.items() if k != "chave_do_operador_no_ambiente") and not ev["chave_do_operador_no_ambiente"]
    binario = os.path.realpath(shutil.which("claude") or "")
    versao = subprocess.run([binario, "--version"], capture_output=True, text=True, timeout=30).stdout.strip() if binario else ""
    return resultado("S01", "Claude Code como usuário sem privilégios", ok, ev, {"pid": int(alvo.name), "grupos": campos.get("Groups"), "binario": binario,
                                                                              "versao": versao, "papel_testado": "p3"})


# ------------------------------------------------------------------------------------------------ S02
def s02_contas_e_permissoes(ctx):
    div = ISO.auditar(AMB.PROJETO, ctx.spec, ctx.spec["home_base"])
    divs, registro = ISO.sondar(AMB.PROJETO, ctx.spec)
    inv = AMB.inventario_de_contas(ctx.spec)
    sem_login = all((i["shell"] or "").endswith(("nologin", "false")) for i in inv)
    contas_ok = all(i["id"].startswith(f"uid={i['uid_esperado']}(") for i in inv)
    operacoes = sum(len(r["areas"]) + len(r["ataques"]) + len(r["logs"]) for r in registro.values())
    ev = {"auditoria_conforme": div == [], "sondagem_conforme": divs == [], "papeis_sondados_igual_ao_declarado": len(registro) == len(ctx.spec["papeis"]) == 10,
          "contas_inventariadas_igual_as_declaradas": len(inv) == len(ctx.spec["contas"]) > 0, "contas_conferem_com_o_sistema": bool(inv) and contas_ok,
          "contas_sem_shell_de_login": bool(inv) and sem_login, "operacoes_sondadas_acima_de_800": operacoes > 800}
    return resultado("S02", "Contas e permissões por papel (sistema real)", all(ev.values()), ev, {"operacoes": operacoes, "divergencias": (div + divs)[:5]})


# ------------------------------------------------------------------------------------------------ S03
def s03_inicializacao_segura(ctx):
    base = [sys.executable, "-B", ctx.launcher]
    casos = {}

    def roda(nome, cmd, esperado, usuario=None, env=None):
        if usuario is not None:                                                  # com o grupo de leitura, para o launcher ser LIDO e executar a própria checagem
            grupo = ctx.spec["grupos"]["ppp-leitura"]
            cmd = ["setpriv", f"--reuid={usuario}", f"--regid={usuario}", f"--groups={grupo}", *cmd]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL, env=env or {"PATH": os.environ["PATH"]})
        msg = (r.stderr.strip().splitlines() or [""])[-1][:160]
        casos[nome] = {"recusou": r.returncode != 0 and esperado.lower() in (r.stderr + r.stdout).lower(), "mensagem": msg}
    roda("sem_root", base + ["--papel", "p3", "--dry-run"], "execute como root", usuario=ctx.uid("p3"))
    roda("root_sem_papel", base + ["--dry-run"], "exige --papel")
    roda("opcao_fora_da_lista_branca", base + ["--papel", "p3", "--", "--dangerously-skip-permissions", "-p", "x"], "opção recusada")
    roda("opcao_agents", base + ["--papel", "p3", "--", "--agents", "{}", "-p", "x"], "opção recusada")
    roda("servico_de_log_inexistente", base + ["--papel", "p3", "--logd-socket", "/run/ppp-betim/log/nao-existe.sock", "--", "-p", "x"], "indisponível")
    roda("papel_inexistente", base + ["--papel", "fantasma", "--", "-p", "x"], "papel desconhecido")
    settings = AMB.PROJETO / ".claude/settings.json"
    original = settings.read_bytes()
    try:
        settings.write_text('{"permissions": {', encoding="utf-8")
        roda("configuracao_adulterada", base + ["--papel", "p3", "--", "-p", "x"], "Sessão NÃO iniciada")
    finally:
        settings.write_bytes(original)
    positivo = subprocess.run(base + ["--papel", "p3", "--dry-run"], capture_output=True, text=True, timeout=60)
    ev = {"recusas": {k: v["recusou"] for k, v in casos.items()}, "controle_positivo_dry_run_ok": positivo.returncode == 0}
    ok = all(v["recusou"] for v in casos.values()) and ev["controle_positivo_dry_run_ok"]
    return resultado("S03", "Inicialização segura por mecanismo controlado", ok, ev, {"mensagens": {k: v["mensagem"] for k, v in casos.items()}})


# ------------------------------------------------------------------------------------------------ S04
def _egresso_tls(host="api.anthropic.com", porta=443):
    """Conexão TLS ao provedor SEM enviar credencial nem requisição: só prova que a rota e o certificado funcionam."""
    try:
        with socket.create_connection((host, porta), timeout=8) as s, ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
            return True, t.version()
    except (OSError, ssl.SSLError) as erro:
        return False, type(erro).__name__


def s04_chamada_real_a_api(ctx):
    """ÚNICO cenário que conta como chamada real ao provedor. Exige credencial provisionada por humano e modo api-real."""
    cred = AMB.verificar_credencial(ctx.spec)
    base = {"credencial_provisionada": cred["ok"]}
    if ctx.modo != "api-real":
        return resultado("S04", "Comunicação real com a API pelo gateway", None, base,
                         motivo="execução em modo laboratório com modelo simulado: nenhuma chamada real foi feita")
    if not cred["ok"]:
        return resultado("S04", "Comunicação real com a API pelo gateway", None, base,
                         motivo="credencial NÃO provisionada pelo responsável humano (ver registro-credencial)")
    egresso_ok, detalhe = _egresso_tls()
    base["rota_tls_ao_provedor"] = egresso_ok
    if not egresso_ok:
        return resultado("S04", "Comunicação real com a API pelo gateway", None, base, motivo=f"sem rota TLS ao provedor ({detalhe})")
    inicio = time.monotonic()
    cmd = [sys.executable, "-B", ctx.launcher, "--papel", "coordenador", *(["--claude", ctx.claude] if ctx.claude else []), "--", "-p",
           "Responda apenas com a palavra: ok", "--output-format", "json", "--model", "haiku", "--max-turns", "1"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL, env={"PATH": os.environ["PATH"], "LANG": "C.UTF-8"})
    try:
        saida = json.loads(r.stdout)
    except ValueError:
        saida = {}
    rede = [json.loads(l)["dados"] for l in (AMB.PROJETO / "logs/rede.jsonl").read_text().splitlines()[-6:]]
    fim = [e for e in rede if e.get("evento") == "fim"]
    ev = {**base, "sessao_terminou_sem_erro": r.returncode == 0 and not saida.get("is_error", True),
          "resposta_contem_ok": "ok" in str(saida.get("result", "")).lower(), "gateway_registrou_status_200": bool(fim) and fim[-1].get("status") == 200,
          "modelo_informado": sorted(saida.get("modelUsage", {}).keys())}
    ok = ev["sessao_terminou_sem_erro"] and ev["resposta_contem_ok"] and ev["gateway_registrou_status_200"]
    return resultado("S04", "Comunicação real com a API pelo gateway", ok, ev,
                     {"latencia_s": round(time.monotonic() - inicio, 1), "tokens": saida.get("usage", {}), "api_error_status": saida.get("api_error_status")})


# ------------------------------------------------------------------------------------------------ S05
def s05_protecao_da_credencial(ctx, chave_bytes):
    """A credencial não aparece em argv/ambiente de nenhum processo nem em arquivos do ambiente; só o arquivo dela a contém, e só a conta do gateway lê."""
    cred = AMB.verificar_credencial(ctx.spec)
    if not cred["ok"]:
        return resultado("S05", "Proteção da credencial", None, {"credencial_provisionada": False}, motivo="nenhuma credencial provisionada para varrer")
    pastas = [AMB.PROJETO, AMB.VAR, Path("/tmp"), Path("/var/tmp"), Path(ctx.spec["servicos"]["dir"]), Path(ctx.spec["home_base"]), AMB.ETC]
    achados = AMB.varredura_de_credencial(chave_bytes, pastas, ignorar=[AMB.CHAVE])
    planta = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(20)", chave_bytes.decode()])      # canário plantado: a varredura TEM de achá-lo
    try:
        time.sleep(0.5)
        controle_positivo = any(a["onde"] == f"/proc/{planta.pid}/cmdline" for a in AMB.varredura_de_credencial(chave_bytes, []))
    finally:
        planta.kill()
        planta.wait()
    leitura_por_papel = {}
    for papel in ctx.spec["papeis"]:
        r = ctx.como(papel, f"try:\n open({str(AMB.CHAVE)!r}).read(); print('LEU')\nexcept OSError: print('NEGADO')")
        leitura_por_papel[papel] = r.stdout.strip()
    ev = {"modo_do_arquivo_ok": cred["ok"], "varredura_acha_canario_plantado_em_argv": controle_positivo, "ocorrencias_fora_do_arquivo_da_credencial": len(achados),
          "nenhum_papel_le_o_arquivo": all(v == "NEGADO" for v in leitura_por_papel.values()), "papeis_testados": len(leitura_por_papel)}
    ok = cred["ok"] and controle_positivo and not achados and ev["nenhum_papel_le_o_arquivo"]
    return resultado("S05", "Proteção da credencial", ok, ev, {"locais_com_ocorrencia": [a["onde"] for a in achados][:5], "impressao": cred["impressao"]})


# ------------------------------------------------------------------------------------------------ S06
SONDA_REDE = r"""
import json, os, socket, urllib.request
r = {}
r["interfaces"] = sorted(n for _, n in socket.if_nameindex())
def conecta(h, p):
    s = socket.socket(); s.settimeout(3)
    try: s.connect((h, p)); return True
    except OSError: return False
    finally: s.close()
r["internet_1.1.1.1:443"] = conecta("1.1.1.1", 443)
r["loopback_do_host_porta_do_modelo"] = conecta("127.0.0.1", int(os.environ["PORTA_DO_MODELO"]))
try:
    ip = socket.getaddrinfo("api.anthropic.com", 443, socket.AF_INET)[0][4][0]      # pode vir do /etc/hosts: arquivo estático, não consulta DNS
except OSError:
    ip = None
r["ip_do_provedor_alcancavel"] = conecta(ip, 443) if ip else False
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
try: u.connect(("8.8.8.8", 53)); u.send(b"x"); r["servidor_dns_alcancavel"] = True
except OSError: r["servidor_dns_alcancavel"] = False
base = os.environ["ANTHROPIC_BASE_URL"]
def pedido(metodo, caminho):
    try:
        rq = urllib.request.Request(base + caminho, data=b"{}" if metodo == "POST" else None, method=metodo, headers={"x-api-key": "marcador"})
        return urllib.request.urlopen(rq, timeout=15).status
    except urllib.error.HTTPError as e: return e.code
    except OSError: return None
r["via_gateway_post_messages"] = pedido("POST", "/v1/messages")
r["via_gateway_post_models"] = pedido("POST", "/v1/models")
r["via_gateway_get_messages"] = pedido("GET", "/v1/messages")
r["via_gateway_post_files"] = pedido("POST", "/v1/files")
print(json.dumps(r))
"""


def s06_restricoes_de_rede(ctx):
    papel = "p3"
    uid = ctx.uid(papel)
    home = Path(ctx.spec["home_base"]) / papel
    ctx.modelo.reiniciar([])
    cmd = ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--groups=" + ",".join(str(g) for g in ISO.ids_papel(ctx.spec, papel)[2] if g != uid),
           "--no-new-privs", sys.executable, "-B", str(AMB.PROJETO / "scripts/jaula.py"), "--papel", papel, "--raiz", str(AMB.PROJETO), "--home", str(home),
           "--rede", "gateway", "--", sys.executable, "-I", "-B", str(AMB.PROJETO / "scripts/entrada_jaula.py"), "--gateway", ctx.gw_socket, "--",
           "env", f"PORTA_DO_MODELO={ctx.modelo.porta}", sys.executable, "-c", SONDA_REDE]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                       env={"PATH": os.environ["PATH"], "PORTA_DO_MODELO": str(ctx.modelo.porta), "HOME": str(home)})
    try:
        s = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return resultado("S06", "Restrições de rede", False, {"sonda_executou": False}, {"stderr": r.stderr[-300:]})
    recebidos = [q["caminho"].split("?")[0] for q in ctx.modelo.requisicoes]
    ev = {"destino_so_recebeu_o_pedido_permitido": recebidos == ["/v1/messages"], "so_loopback": s["interfaces"] == ["lo"], "sem_internet": s["internet_1.1.1.1:443"] is False, "sem_rota_ao_ip_do_provedor": s["ip_do_provedor_alcancavel"] is False, "sem_acesso_a_servidor_dns": s["servidor_dns_alcancavel"] is False,
          "sem_acesso_ao_loopback_do_host": s["loopback_do_host_porta_do_modelo"] is False, "gateway_aceita_messages": s["via_gateway_post_messages"] == 200,
          "gateway_recusa_models_get_e_files": s["via_gateway_post_models"] == 403 and s["via_gateway_get_messages"] == 403 and s["via_gateway_post_files"] == 403}
    return resultado("S06", "Restrições de rede (namespace vazio + gateway)", all(ev.values()), ev, {"sonda": s})


# ------------------------------------------------------------------------------------------------ S07
def s07_logs_integros(ctx, destino_ancoras=AMB.ANCORAS):
    problemas = {n: logd.verificar(AMB.PROJETO / "logs" / n) for n in ISO.nomes_de_log(ctx.spec)}
    cadeias_ok = all(not p for p in problemas.values())
    protegido = True
    for n in ISO.nomes_de_log(ctx.spec):
        st = os.stat(AMB.PROJETO / "logs" / n)
        protegido &= st.st_uid == ctx.spec["contas"]["ppp-guardiao"] and (st.st_mode & 0o777) == 0o640 and ISO._tem_so_anexar(AMB.PROJETO / "logs" / n)
    divs, _ = ISO.sondar(AMB.PROJETO, ctx.spec)
    ts, cabecas = ANC.publicar(AMB.PROJETO, ctx.spec, destino_ancoras)
    ancoras_ok = ANC.verificar(AMB.PROJETO, ctx.spec, destino_ancoras) == []
    registros = sum(c["seq"] for c in cabecas.values())
    ev = {"cadeias_integras": cadeias_ok, "arquivos_so_anexar_do_servico_0640": bool(protegido), "nenhum_papel_escreve": divs == [],
          "ancora_publicada_e_confere": ancoras_ok, "ha_registros": registros > 0, "log_de_rede_com_registros": cabecas["rede.jsonl"]["seq"] > 0}
    return resultado("S07", "Integridade e armazenamento protegido dos logs", all(ev.values()), ev, {"registros_total": registros, "ancora": ts})
