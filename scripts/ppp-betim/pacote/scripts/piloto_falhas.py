"""Cenários do piloto controlado (GOV-09), parte 2: S08 agentes×skills e S09 falha e recuperação (F1–F6).
Mesmas regras de honestidade da parte 1: o destino da API no laboratório é um modelo simulado, não o provedor real.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ancora_logs as ANC  # noqa: E402
import isolamento as ISO  # noqa: E402
import logd  # noqa: E402
import piloto_ambiente as AMB  # noqa: E402
from piloto_cenarios import resultado  # noqa: E402

SKILLS_COMUNS = ("ingestao-data-request", "base-premissas", "verificacao-independente")


def _matriz():
    return json.loads((AMB.PROJETO / "governanca/matriz-agentes.json").read_text(encoding="utf-8"))["agentes"]


def _todas_as_skills():
    return sorted(p.name for p in (AMB.PROJETO / ".claude/skills").iterdir() if p.is_dir())


# ------------------------------------------------------------------------------------------------ S08
def s08_agentes_e_skills(ctx):
    """Para cada um dos dez papéis, o agente padrão roda de verdade (claude real, jaula, gateway) e usa as skills autorizadas,
    é recusado nas não autorizadas e nas de fora do projeto, escreve na própria área e é barrado em área alheia."""
    matriz, todas = _matriz(), _todas_as_skills()
    por_agente, falhas = {}, []
    for papel, dados in ctx.spec["papeis"].items():
        agente = dados["agente_padrao"]
        info = matriz[agente]
        autorizadas = sorted(set(info["skills"]) | set(SKILLS_COMUNS))
        proibida = next((s for s in todas if s not in autorizadas), None)
        escrita = (info["escrita"] or [None])[0]
        alheia = "produtos/P1" if papel != "p1" else "produtos/P2"
        roteiro = [("Skill", {"skill": s}) for s in autorizadas]
        roteiro += [("Skill", {"skill": proibida})] if proibida else []
        roteiro += [("Skill", {"skill": "update-config"})]
        if escrita:
            roteiro += [("Write", {"file_path": str(AMB.PROJETO / escrita / f"SINTETICO-piloto-{papel}.md"), "content": f"SINTETICO saida de {papel}\n"})]
        roteiro += [("Write", {"file_path": str(AMB.PROJETO / alheia / f"SINTETICO-invasao-{papel}.md"), "content": "SINTETICO nao deve existir\n"})]
        r, res = ctx.sessao(papel, roteiro, agente=None)
        n = len(autorizadas)
        ok_aut = len(res) >= n and all(not x["erro"] for x in res[:n])
        pos = n
        ok_proib = True
        if proibida:
            ok_proib = len(res) > pos and res[pos]["erro"]
            pos += 1
        ok_ext = len(res) > pos and res[pos]["erro"]
        pos += 1
        ok_esc, ok_alheia = True, False
        if escrita:
            alvo = AMB.PROJETO / escrita / f"SINTETICO-piloto-{papel}.md"
            ok_esc = len(res) > pos and not res[pos]["erro"] and alvo.exists() and alvo.stat().st_uid == ctx.uid(papel)
            pos += 1
        ok_alheia = len(res) > pos and res[pos]["erro"] and not (AMB.PROJETO / alheia / f"SINTETICO-invasao-{papel}.md").exists()
        item = {"agente": agente, "skills_autorizadas_ok": ok_aut, "n_autorizadas": n, "skill_nao_autorizada_recusada": ok_proib,
                "skill_externa_recusada": ok_ext, "escrita_na_propria_area": ok_esc, "escrita_em_area_alheia_barrada": ok_alheia,
                "sessao_terminou": r.returncode == 0}
        por_agente[papel] = item
        if not all(v for k, v in item.items() if k not in ("agente", "n_autorizadas")):
            falhas.append(papel)
    skills_exercitadas = sorted({s for dados in ctx.spec["papeis"].values() for s in set(matriz[dados["agente_padrao"]]["skills"]) | set(SKILLS_COMUNS)})
    ev = {"agentes_exercitados": len(por_agente), "agentes_esperados": 10, "skills_do_projeto": len(todas), "skills_exercitadas_por_algum_agente": len(skills_exercitadas),
          "skills_nunca_exercitadas": sorted(set(todas) - set(skills_exercitadas)), "por_agente": por_agente, "agentes_com_falha": falhas}
    ok = not falhas and len(por_agente) == 10 and len(todas) == 19
    return resultado("S08", "Dez agentes e dezenove skills em execução real (modelo simulado)", ok, ev)


# ------------------------------------------------------------------------------------------------ S09
def _pids():
    try:
        return json.loads(AMB.STATUS_SUPERVISOR.read_text()).get("pids", {})
    except (OSError, ValueError):
        return {}


def _espera(cond, tempo=20.0, passo=0.3):
    fim = time.monotonic() + tempo
    while time.monotonic() < fim:
        if cond():
            return True
        time.sleep(passo)
    return False


def _sessao_ok(ctx, papel="p3"):
    r, res = ctx.sessao(papel, [ctx.leitura("produtos/P3/SINTETICO-p3.md")], tempo=120)
    return r.returncode == 0 and bool(res) and not res[0]["erro"]


def _mata(nome):
    pid = _pids().get(nome)
    if pid:
        os.kill(pid, signal.SIGKILL)
    return pid


def _novo_pid(nome, antigo):
    return _espera(lambda: _pids().get(nome) not in (None, antigo), 25)


def f1_servico_de_log_cai(ctx):
    antigo = _mata("logd")
    time.sleep(0.5)
    recusou = subprocess.run(ctx.comando_sessao("p3"), capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                             env={"PATH": os.environ["PATH"]}).returncode != 0
    if _novo_pid("logd", antigo):
        _espera(lambda: logd_vivo(ctx), 15)
    return {"nova_sessao_recusada_enquanto_cai": recusou, "supervisor_reiniciou": _pids().get("logd") not in (None, antigo),
            "sessao_normal_apos_recuperacao": _sessao_ok(ctx),
            "cadeias_integras_apos": all(not logd.verificar(AMB.PROJETO / "logs" / n) for n in ISO.nomes_de_log(ctx.spec))}


def logd_vivo(ctx):
    import socket
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(2)
    try:
        s.connect(ctx.logd_socket)
        return True
    except OSError:
        return False
    finally:
        s.close()


def f2_gateway_cai(ctx):
    antigo = _mata("gateway")
    time.sleep(0.5)
    r, _ = ctx.sessao("p3", [ctx.leitura("produtos/P3/SINTETICO-p3.md")], tempo=120)
    falhou_sem_vazar = r.returncode != 0 or "is_error\": true" in r.stdout or "API Error" in r.stdout
    vazou = any(m in (r.stdout + r.stderr) for m in ("chave-do-operador", "SINTETICO-CANARIO"))
    _novo_pid("gateway", antigo)
    _espera(lambda: os.path.exists(ctx.gw_socket), 15)
    return {"sessao_falha_enquanto_gateway_cai": falhou_sem_vazar, "nada_vazou_na_falha": not vazou,
            "supervisor_reiniciou": _pids().get("gateway") not in (None, antigo), "sessao_normal_apos_recuperacao": _sessao_ok(ctx)}


def f3_destino_indisponivel(ctx):
    porta = ctx.modelo.porta
    ctx.modelo.indisponivel = True
    try:
        inicio = time.monotonic()
        r, _ = ctx.sessao("p3", [ctx.leitura("produtos/P3/SINTETICO-p3.md")], tempo=200)
        duracao = time.monotonic() - inicio
        erro = r.returncode != 0 or "API Error" in r.stdout or '"is_error":true' in r.stdout.replace(" ", "")
    finally:
        ctx.modelo.indisponivel = False
    return {"sessao_termina_com_erro_e_nao_trava": erro and duracao < 190, "porta_do_modelo_mantida": porta == ctx.modelo.porta,
            "sessao_normal_apos_retorno": _sessao_ok(ctx)}, {"duracao_s": round(duracao, 1)}


def f4_credencial_ausente_e_rotacao(ctx, chave_atual, chave_nova):
    """Revoga a credencial (gateway deve sair do ar e não voltar), reprovisiona outra e confirma que só a nova chega ao destino."""
    config = AMB.CONFIG_SERVICOS
    AMB.revogar_credencial(motivo="teste F4 (laboratório)")
    antigo = _mata("gateway")
    time.sleep(2.5)
    sem_gateway = _pids().get("gateway") is None and not os.path.exists(ctx.gw_socket)
    r, _ = ctx.sessao("p3", [ctx.leitura("produtos/P3/SINTETICO-p3.md")], tempo=120)
    sessao_falha = r.returncode != 0 or "API Error" in r.stdout
    AMB.instalar_credencial(ctx.spec, chave_nova, "rotacao-sintetica-F4")
    voltou = _espera(lambda: _pids().get("gateway") not in (None, antigo) and os.path.exists(ctx.gw_socket), 30)
    ctx.modelo.requisicoes.clear()
    sessao_nova = voltou and _sessao_ok(ctx)
    chaves = {q["cabecalhos"].get("x-api-key") for q in ctx.modelo.requisicoes}
    return {"gateway_nao_sobe_sem_credencial": sem_gateway, "sessao_falha_sem_credencial": sessao_falha, "gateway_volta_com_nova_credencial": bool(voltou),
            "sessao_normal_apos_rotacao": bool(sessao_nova), "destino_viu_so_a_chave_nova": chaves == {chave_nova.decode().strip()},
            "chave_antiga_nao_chegou_apos_rotacao": chave_atual.decode().strip() not in chaves, "config_existe": config.exists()}


def f5_adulteracao_de_logs(ctx):
    """Em CÓPIA dos logs (o original não é tocado): edição, remoção do meio e truncagem da cauda; e, no original, escrita direta barrada."""
    temp = Path(tempfile.mkdtemp(prefix="piloto-adulteracao-"))
    try:
        raiz = temp / "proj"
        (raiz / "logs").mkdir(parents=True)
        for n in ISO.nomes_de_log(ctx.spec):
            shutil.copy2(AMB.PROJETO / "logs" / n, raiz / "logs" / n)
        destino = temp / "ancoras"
        destino.mkdir(mode=0o755)
        os.chown(destino, 0, 0)
        ANC.publicar(raiz, ctx.spec, destino)
        alvo = raiz / "logs" / "rede.jsonl"
        linhas = alvo.read_text().splitlines()
        res = {"registros_no_alvo": len(linhas)}
        alvo.write_text("\n".join(linhas[:-2]) + "\n")                       # trunca a cauda (cadeia continua válida, só mais curta)
        res["truncagem_da_cauda_detectada_pela_ancora"] = any("TRUNCADA" in p for p in ANC.verificar(raiz, ctx.spec, destino))
        alvo.write_text("\n".join(linhas) + "\n")
        editado = json.loads(linhas[len(linhas) // 2])
        editado["dados"]["evento"] = "forjado"
        meio = linhas[:]
        meio[len(linhas) // 2] = json.dumps(editado)
        alvo.write_text("\n".join(meio) + "\n")
        res["edicao_detectada_pela_cadeia"] = bool(logd.verificar(alvo))
        alvo.write_text("\n".join(linhas[:5] + linhas[6:]) + "\n")
        res["remocao_no_meio_detectada"] = bool(logd.verificar(alvo))
        # no original: nenhum papel consegue anexar nem truncar
        tentativas = {}
        for papel in ("coordenador", "p3", "revisor"):
            r = ctx.como(papel, "import sys\ntry:\n open(sys.argv[1],'a').write('x'); print('ESCREVEU')\nexcept OSError: print('NEGADO')",
                         args=[str(AMB.PROJETO / "logs/rede.jsonl")])
            tentativas[papel] = r.stdout.strip()
        res["papeis_nao_escrevem_no_log_original"] = all(v == "NEGADO" for v in tentativas.values())
        # só-anexar permite ANEXAR (inclusive ao root) e bloqueia truncar/reescrever; por isso aqui se testa apenas a truncagem
        r = subprocess.run(["sh", "-c", f": > {AMB.PROJETO}/logs/rede.jsonl"], capture_output=True, text=True)
        res["mesmo_root_nao_trunca_com_so_anexar"] = r.returncode != 0
        res["original_continua_integro"] = not logd.verificar(AMB.PROJETO / "logs/rede.jsonl")
        return res
    finally:
        shutil.rmtree(temp, ignore_errors=True)


SONDA_RAJADA = r"""
import socket, sys, threading, json, time
caminho = sys.argv[1]
corpo = b'{"model":"x","max_tokens":1,"messages":[{"role":"user","content":"x"}]}'
codigos = []
def um():
    s = socket.socket(socket.AF_UNIX); s.settimeout(60)
    try:
        s.connect(caminho)
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(corpo) + corpo)
        d = b""
        while b"\r\n" not in d:
            c = s.recv(256)
            if not c: break
            d += c
        codigos.append(int(d.split()[1]) if d else 0)
    except OSError:
        codigos.append(0)
    finally:
        s.close()
ts = [threading.Thread(target=um) for _ in range(12)]
[t.start() for t in ts]; [t.join() for t in ts]
print(json.dumps(sorted(codigos)))
"""


def f6_rajada(ctx):
    ctx.modelo.reiniciar([])
    ctx.modelo.atraso = 3.0
    try:
        r = ctx.como("p3", SONDA_RAJADA, args=[ctx.gw_socket])
    finally:
        ctx.modelo.atraso = 0.0
    try:
        codigos = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"sonda_executou": False}, {"stderr": r.stderr[-200:]}
    return {"limite_por_papel_aplicado": codigos.count(429) >= 1 and codigos.count(200) <= 4 + 2, "algumas_atendidas": codigos.count(200) >= 1,
            "nenhum_erro_de_conexao": codigos.count(0) == 0, "gateway_continua_vivo": _sessao_ok(ctx)}, {"codigos": codigos}


def s09_falha_e_recuperacao(ctx, chave_atual, chave_nova):
    todos, volatil = {}, {}
    for id_, fn in (("F1_servico_de_log_cai", f1_servico_de_log_cai), ("F2_gateway_cai", f2_gateway_cai), ("F3_destino_indisponivel", f3_destino_indisponivel),
                    ("F5_adulteracao_de_logs", f5_adulteracao_de_logs), ("F6_rajada_de_requisicoes", f6_rajada)):
        out = fn(ctx)
        if isinstance(out, tuple):
            todos[id_], volatil[id_] = out
        else:
            todos[id_] = out
    todos["F4_credencial_ausente_e_rotacao"] = f4_credencial_ausente_e_rotacao(ctx, chave_atual, chave_nova)
    ok = all(all(v for v in d.values() if isinstance(v, bool)) for d in todos.values())
    return resultado("S09", "Falha e recuperação (F1–F6)", ok, todos, volatil)
