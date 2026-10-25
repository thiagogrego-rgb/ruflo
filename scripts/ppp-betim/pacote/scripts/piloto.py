#!/usr/bin/env python3
"""Piloto controlado de infraestrutura e API (GOV-09). Operação de ADMINISTRADOR (root); usa apenas dados sintéticos.

  piloto.py preflight
  piloto.py contas criar|inventario
  piloto.py instalar --origem ARVORE [--dados-sinteticos PASTA]
  piloto.py supervisor [--parar-apos S]                       (mantém logd e gateway; reinicia; fail-closed sem credencial)
  piloto.py credencial instalar --rotulo TEXTO                (lê do terminal sem eco ou do stdin; NUNCA por argumento)
  piloto.py credencial verificar|revogar|registro
  piloto.py varredura                                         (procura a credencial em argv/ambiente/arquivos; não imprime o segredo)
  piloto.py ancoras publicar|verificar
  piloto.py executar --modo laboratorio|api-real --saida PASTA [--rotulo X]
  piloto.py comparar A.json B.json                            (reprodutibilidade: S10)

Modo `laboratorio`: o destino da API é um MODELO SIMULADO local com uma credencial sintética (canário); NÃO é chamada real ao provedor.
Modo `api-real`: exige credencial provisionada por HUMANO em /etc/ppp-betim/chave-api e serviços já em execução; só os cenários que não
dependem de roteiro simulado são executados (S02, S03, S04, S05, S07); os demais ficam NÃO EXECUTADO.
"""
import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "testes"))
import ancora_logs as ANC  # noqa: E402
import isolamento as ISO  # noqa: E402
import piloto_ambiente as AMB  # noqa: E402
import piloto_cenarios as C  # noqa: E402
import piloto_falhas as F  # noqa: E402


def carregar_spec(caminho=None):
    """Especificação da instalação imutável; antes da instalação (ou em testes) cai para a que acompanha este script."""
    instalada = AMB.CODIGO / "governanca/papeis.json"
    local = Path(__file__).resolve().parent.parent / "governanca/papeis.json"
    return json.loads(Path(caminho or (instalada if instalada.exists() else local)).read_text(encoding="utf-8"))


def _imprime(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def _espera_sockets(spec, tempo=30):
    fim = time.monotonic() + tempo
    while time.monotonic() < fim:
        if Path(spec["servicos"]["logd_socket"]).exists() and Path(spec["servicos"]["gateway_socket"]).exists():
            return True
        time.sleep(0.3)
    return False


def _escreve_config(upstream, permitir_teste, proxy=None, ca=None):
    cfg = {"gateway": {"chave_arquivo": str(AMB.CHAVE), "upstream": upstream, "permitir_teste": permitir_teste}}
    if proxy:
        cfg["gateway"]["proxy_arquivo"] = proxy
    if ca:
        cfg["gateway"]["ca_arquivo"] = ca
    AMB.CONFIG_SERVICOS.write_text(json.dumps(cfg, indent=1))
    os.chmod(AMB.CONFIG_SERVICOS, 0o644)


def _executa_cenario(fn, *args):
    inicio = time.monotonic()
    try:
        r = fn(*args)
    except (Exception, SystemExit) as erro:  # noqa: BLE001 — o piloto registra a falha do cenário em vez de abortar
        return {"id": getattr(fn, "__name__", "?").split("_")[0].upper(), "titulo": getattr(fn, "__doc__", "") or "", "resultado": C.FALHOU,
                "evidencia": {"excecao": f"{type(erro).__name__}: {str(erro)[:300]}"}, "volatil": {}}
    r["volatil"]["duracao_s"] = round(time.monotonic() - inicio, 1)
    return r


def _relatorio_md(rodada):
    linhas = [f"# Piloto GOV-09 — rodada `{rodada['rotulo']}`", "",
              "> **Escopo: LABORATÓRIO.** Modelo de API SIMULADO e credencial sintética. **Infraestrutura de homologação: NÃO realizada.** "
              "Nenhum resultado abaixo autoriza dados reais nem declara homologação.", "",
              f"- Modo: **{rodada['modo']}**",
              f"- Início: {rodada['inicio']} — duração {rodada['duracao_s']} s",
              f"- Credencial: {rodada['credencial']}", "",
              "| Cenário | Resultado | O que prova |", "|---|---|---|"]
    for r in rodada["cenarios"]:
        linhas.append(f"| {r['id']} | **{r['resultado']}** | {r['titulo']} |")
    linhas += ["", "Chamada real ao provedor (S04): **" + next(r["resultado"] for r in rodada["cenarios"] if r["id"] == "S04") + "**", ""]
    for r in rodada["cenarios"]:
        if r["resultado"] != C.PASSOU:
            linhas += [f"## {r['id']} — {r['resultado']}", "```json", json.dumps(r["evidencia"], ensure_ascii=False, indent=1)[:3000], "```", ""]
    return "\n".join(linhas)


def executar(args):
    if os.geteuid() != 0:
        raise SystemExit("o piloto roda como administrador (root)")
    spec = carregar_spec()
    saida = Path(args.saida)
    saida.mkdir(parents=True, exist_ok=True)
    inicio = time.time()
    lab = args.modo == "laboratorio"
    modelo, sup, ctx = None, None, None
    chave_a = chave_b = None
    try:
        if lab:
            from modelo_falso import ModeloFalso
            modelo = ModeloFalso([])
            chave_a = f"sk-ant-SINTETICO-CANARIO-{secrets.token_hex(16)}".encode()
            chave_b = f"sk-ant-SINTETICO-CANARIO-{secrets.token_hex(16)}".encode()
            C.cria_dados_sinteticos(spec)
            _escreve_config(f"http://127.0.0.1:{modelo.porta}", True)
            AMB.instalar_credencial(spec, chave_a, f"canario-sintetico-{args.rotulo}")
            sup = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "supervisor"], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        if not _espera_sockets(spec, 40):
            raise SystemExit("serviços não subiram (logd/gateway): ver supervisor-status.json")
        ctx = C.Contexto(spec, modelo, "laboratorio-modelo-simulado" if lab else "api-real", claude=shutil.which("claude"))
        credencial = AMB.verificar_credencial(spec)
        cenarios = []
        add = cenarios.append
        add(_executa_cenario(C.s02_contas_e_permissoes, ctx))
        add(_executa_cenario(C.s03_inicializacao_segura, ctx))
        add(_executa_cenario(C.s04_chamada_real_a_api, ctx))
        if lab:
            add(_executa_cenario(C.s01_usuario_sem_privilegio, ctx))
            add(_executa_cenario(C.s05_protecao_da_credencial, ctx, chave_a))
            add(_executa_cenario(C.s06_restricoes_de_rede, ctx))
            add(_executa_cenario(F.s08_agentes_e_skills, ctx))
            add(_executa_cenario(C.s07_logs_integros, ctx))
            add(_executa_cenario(F.s09_falha_e_recuperacao, ctx, chave_a, chave_b))
            add(_executa_cenario(C.s07_logs_integros, ctx))                          # de novo: após as falhas as cadeias seguem íntegras
            cenarios[-1]["id"], cenarios[-1]["titulo"] = "S07b", "Integridade dos logs após os testes de falha"
            varredura = AMB.varredura_de_credencial(chave_b, [AMB.PROJETO, AMB.VAR, Path("/tmp"), Path("/var/tmp"), Path(spec["servicos"]["dir"]),
                                                              Path(spec["home_base"])], ignorar=[AMB.CHAVE])
            add(C.resultado("S05b", "Credencial rotacionada ausente de argv/ambiente/arquivos após o piloto", not varredura,
                            {"ocorrencias": len(varredura)}, {"locais": [a["onde"] for a in varredura][:5]}))
        else:
            chave_real = AMB.CHAVE.read_bytes() if AMB.CHAVE.exists() else b""
            add(_executa_cenario(C.s05_protecao_da_credencial, ctx, chave_real))
            add(_executa_cenario(C.s07_logs_integros, ctx))
            for id_, titulo in (("S01", "Claude Code como usuário sem privilégios"), ("S06", "Restrições de rede"), ("S08", "Dez agentes e dezenove skills"),
                                ("S09", "Falha e recuperação")):
                add(C.resultado(id_, titulo, None, {}, motivo="depende de roteiro simulado; não executado no modo api-real"))
        cenarios.sort(key=lambda r: r["id"])
        rodada = {"rotulo": args.rotulo, "modo": ctx.modo, "inicio": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(inicio)),
                  "duracao_s": round(time.time() - inicio, 1), "credencial": ("canário sintético (laboratório)" if lab else
                                                                              f"provisionada por humano, impressão {credencial['impressao']}"),
                  "chamada_real_a_api": next(r["resultado"] for r in cenarios if r["id"] == "S04"), "cenarios": cenarios,
                  "resumo": {k: sum(1 for r in cenarios if r["resultado"] == k) for k in (C.PASSOU, C.FALHOU, C.NAO_EXECUTADO)}}
        (saida / f"rodada-{args.rotulo}.json").write_text(json.dumps(rodada, ensure_ascii=False, indent=1), encoding="utf-8")
        (saida / f"rodada-{args.rotulo}.md").write_text(_relatorio_md(rodada), encoding="utf-8")
        _imprime({"arquivo": str(saida / f"rodada-{args.rotulo}.json"), **rodada["resumo"]})
        return 0 if not rodada["resumo"][C.FALHOU] else 1
    finally:
        if sup is not None:
            sup.terminate()
            try:
                sup.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sup.kill()
        if lab:
            AMB.revogar_credencial(motivo=f"fim do piloto de laboratório {args.rotulo}")
            if modelo:
                modelo.fechar()


def comparar(args):
    a, b = (json.loads(Path(p).read_text(encoding="utf-8")) for p in (args.a, args.b))
    dif = []
    if a["rotulo"] == b["rotulo"] or a["inicio"] == b["inicio"]:
        dif.append({"cenario": "*", "diferenca": "as rodadas não são independentes (mesmo rótulo ou mesmo início)"})
    if a["modo"] != b["modo"]:
        dif.append({"cenario": "*", "diferenca": f"modos diferentes: {a['modo']} x {b['modo']}"})
    da, db = ({r["id"]: r for r in x["cenarios"]} for x in (a, b))
    for id_ in sorted(set(da) | set(db)):
        if id_ not in da or id_ not in db:
            dif.append({"cenario": id_, "diferenca": "presente em uma rodada só"})
        elif da[id_]["resultado"] != db[id_]["resultado"] or da[id_]["evidencia"] != db[id_]["evidencia"]:
            dif.append({"cenario": id_, "a": da[id_]["resultado"], "b": db[id_]["resultado"], "evidencia_igual": da[id_]["evidencia"] == db[id_]["evidencia"]})
    comuns = [i for i in da if i in db]
    reproduzidos = [i for i in comuns if da[i]["resultado"] == db[i]["resultado"] == C.PASSOU]
    nao_executados = [i for i in comuns if da[i]["resultado"] == db[i]["resultado"] == C.NAO_EXECUTADO]
    r = {"id": "S10", "titulo": "Reprodutibilidade entre duas rodadas independentes", "rodadas": [a["rotulo"], b["rotulo"]], "cenarios_comparados": len(comuns),
         "reproduzidos_com_PASSOU": len(reproduzidos), "nao_executados_nas_duas": nao_executados,
         "ignorado_na_comparacao": "campo 'volatil' (pids, durações, contagens de registros, códigos da rajada) — a evidência comparada é a determinística",
         "resultado": C.PASSOU if not dif and reproduzidos else C.FALHOU, "diferencas": dif}
    _imprime(r)
    return 0 if r["resultado"] == C.PASSOU else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("preflight")
    c = sub.add_parser("contas")
    c.add_argument("acao", choices=["criar", "inventario"])
    i = sub.add_parser("instalar")
    i.add_argument("--origem", required=True)
    i.add_argument("--dados-sinteticos")
    s = sub.add_parser("supervisor")
    s.add_argument("--parar-apos", type=float)
    cr = sub.add_parser("credencial")
    cr.add_argument("acao", choices=["instalar", "verificar", "revogar", "registro"])
    cr.add_argument("--rotulo", default="")
    sub.add_parser("varredura")
    an = sub.add_parser("ancoras")
    an.add_argument("acao", choices=["publicar", "verificar"])
    ex = sub.add_parser("executar")
    ex.add_argument("--modo", choices=["laboratorio", "api-real"], required=True)
    ex.add_argument("--saida", required=True)
    ex.add_argument("--rotulo", default="r1")
    cp = sub.add_parser("comparar")
    cp.add_argument("a")
    cp.add_argument("b")
    args = ap.parse_args(argv)

    if args.cmd == "comparar":
        return comparar(args)
    spec = carregar_spec(Path(__file__).resolve().parent.parent / "governanca/papeis.json" if args.cmd in ("preflight", "instalar", "contas") else None)
    if args.cmd == "preflight":
        r = AMB.preflight(spec)
        _imprime(r)
        return 0 if all(x["ok"] for x in r) else 1
    if args.cmd == "contas":
        if args.acao == "criar":
            criadas, existentes = AMB.criar_contas(spec)
            _imprime({"criadas": criadas, "ja_existiam": existentes})
        else:
            _imprime(AMB.inventario_de_contas(spec))
        return 0
    if args.cmd == "instalar":
        _imprime({"avisos": AMB.instalar(spec, args.origem, args.dados_sinteticos)})
        return 0
    if args.cmd == "supervisor":
        _imprime({"reinicios": AMB.supervisionar(spec, args.parar_apos)})
        return 0
    if args.cmd == "credencial":
        if args.acao == "instalar":
            if not args.rotulo:
                raise SystemExit("informe --rotulo (ex.: ticket do canal seguro); o valor da credencial NUNCA é argumento")
            _imprime(AMB.instalar_credencial(spec, AMB.ler_credencial_do_terminal_ou_stdin(), args.rotulo))
        elif args.acao == "verificar":
            r = AMB.verificar_credencial(spec)
            _imprime(r)
            return 0 if r["ok"] else 1
        elif args.acao == "revogar":
            _imprime(AMB.revogar_credencial(motivo=args.rotulo or "revogação manual"))
        else:
            print(AMB.REGISTRO_CREDENCIAL.read_text(encoding="utf-8") if AMB.REGISTRO_CREDENCIAL.exists() else "")
        return 0
    if args.cmd == "varredura":
        chave = AMB.ler_credencial_do_terminal_ou_stdin() if not AMB.CHAVE.exists() else AMB.CHAVE.read_bytes()
        achados = AMB.varredura_de_credencial(chave, [AMB.PROJETO, AMB.VAR, Path("/tmp"), Path("/var/tmp"), Path(spec["servicos"]["dir"]),
                                                      Path(spec["home_base"])], ignorar=[AMB.CHAVE])
        _imprime({"ocorrencias": len(achados), "onde": [a["onde"] for a in achados]})
        return 0 if not achados else 1
    if args.cmd == "ancoras":
        if args.acao == "publicar":
            ts, cabecas = ANC.publicar(AMB.PROJETO, spec, AMB.ANCORAS)
            _imprime({"ts": ts, "cabecas": cabecas})
            return 0
        p = ANC.verificar(AMB.PROJETO, spec, AMB.ANCORAS)
        _imprime({"problemas": p})
        return 0 if not p else 1
    if args.cmd == "executar":
        return executar(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
