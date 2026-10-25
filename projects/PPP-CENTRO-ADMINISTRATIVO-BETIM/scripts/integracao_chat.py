#!/usr/bin/env python3
"""Integração Code + Chat (GOV-09 integrado): cenário sintético, pacotes de transferência, cadeia rastreável e pacote de contexto.

O QUE ESTE MÓDULO FAZ (verificável em código): fixture sintética TESTE-INTEGRACAO-001; cálculo reproduzível do impacto econômico (P4);
pacotes de transferência com os metadados exigidos e validação fail-closed; cadeia de encaminhamentos com hash; prova de que nenhuma
premissa passa a APROVADA sem aprovação humana assinada (usa o `RepositorioPremissas` real); pacote de contexto para o Claude Chat.
O QUE ELE NÃO FAZ: não executa o raciocínio dos agentes (isso exige o modelo real), não acessa o Claude Chat e não sincroniza nada com ele.
A transferência para o Chat é MANUAL e supervisionada por humano; o repositório continua sendo a fonte de verdade.

  integracao_chat.py cenario  --saida PASTA [--data AAAA-MM-DD]
  integracao_chat.py contexto --saida PASTA [--projeto RAIZ]
  integracao_chat.py validar  PACOTE.json
"""
import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
from datetime import date
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import governanca as G  # noqa: E402
import premissas_repositorio as PR  # noqa: E402

ID_CENARIO = "TESTE-INTEGRACAO-001"
ID_FONTE = "FONTE-900001"
PRODUTOS = ("C", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "REV")
SIGILO_PERMITIDO = "PUBLICO-TESTE"
CAMPOS_PACOTE = ("identificador", "produto_origem", "produto_destinatario", "versao", "data", "natureza_dados", "classificacao_sigilo",
                 "referencias_premissas", "estado_aprovacao", "resultado_esperado", "corpo", "sha256")
# material que NUNCA entra num pacote de teste (real/sigiloso): documento de referência real, CPF/CNPJ, e-mail, caminhos de áreas sigilosas
PROIBIDO = [re.compile(p, re.I) for p in (r"DR-0*1\b", r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b",
                                          r"[\w.+-]+@[\w-]+\.[\w.]+", r"dados/(restritos|entrada)", r"produtos/DR/saida", r"sk-ant-")]

ENCAMINHAMENTOS = (
    ("C", "P1", "C elabora a ordem de trabalho e a encaminha a P1", "Ordem de trabalho com escopo, premissas e prazos sintéticos"),
    ("P1", "P2", "P1 confere a compatibilidade do escopo", "Parecer de compatibilidade de escopo (sem aprovar escopo)"),
    ("P2", "P3", "P2 processa a alteração fictícia da área", "Área alterada processada e registrada como PROPOSTA"),
    ("P3", "P4", "P3 avalia o impacto sobre receitas comerciais", "Impacto sobre receitas comerciais com premissas PROPOSTA"),
    ("P4", "P5", "P4 calcula o impacto econômico em ambiente reproduzível", "Cálculo reproduzível com hash de entrada e saída"),
    ("P5", "P6", "P5 identifica riscos e reflexos contratuais", "Lista de riscos e reflexos contratuais possíveis"),
    ("P6", "P7", "P6 aponta implicações para documentos de consulta", "Implicações para documentos de consulta pública"),
    ("P7", "REV", "P7 identifica impactos sobre documentos e critérios da licitação", "Impactos sobre edital e critérios"),
    ("REV", "C", "Revisor independente confere versões, fontes sintéticas e cálculos", "Relatório de verificação sem alterar o objeto auditado"),
)


def canonico(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(obj):
    return hashlib.sha256(canonico(obj)).hexdigest()


# ------------------------------------------------------------------------------------------------ cenário e cálculo
def fixture_cenario():
    """Cenário sintético. Todos os valores são inventados para teste; a fonte é uma fixture."""
    prem = [
        ("PREM-900001", "P2", "HIPOTESE", "m2", 150, "Acréscimo fictício de área comercial (de 1200 para 1350 m²)"),
        ("PREM-900002", "P3", "HIPOTESE", "BRL/m2/mes", "85.00", "Aluguel médio fictício por m²"),
        ("PREM-900003", "P3", "HIPOTESE", "fracao", "0.08", "Vacância fictícia"),
        ("PREM-900004", "P4", "HIPOTESE", "BRL/m2", "3200.00", "Custo fictício de obra por m²"),
        ("PREM-900005", "P4", "HIPOTESE", "fracao_a_a", "0.10", "Taxa de desconto fictícia"),
        ("PREM-900006", "P4", "HIPOTESE", "anos", 20, "Prazo fictício de análise"),
    ]
    return {
        "id": ID_CENARIO, "estado": "PROPOSTA", "natureza_dados": "SINTETICO", "versao_cenario": 1, "data_base": "2026-01",
        "fonte": {"id": ID_FONTE, "tipo": "FIXTURE_DE_TESTE", "descricao": "Valores inventados para teste; sem relação com documentos reais"},
        "premissas": [{"id": i, "versao": 1, "produto": p, "natureza": n, "unidade": u, "valor": v, "descricao": d, "status": "PROPOSTA",
                       "justificativa_hipotese": "valor sintético da fixture de teste", "data_base": "2026-01"} for i, p, n, u, v, d in prem],
    }


def _valor(fix, pid):
    return Decimal(str(next(p["valor"] for p in fix["premissas"] if p["id"] == pid)))


def calculo_p4(fix):
    """Impacto econômico determinístico (Decimal, arredondamento fixo). Mesma entrada → mesma saída, com hash de entrada e de saída."""
    area, aluguel, vac = _valor(fix, "PREM-900001"), _valor(fix, "PREM-900002"), _valor(fix, "PREM-900003")
    obra, taxa, prazo = _valor(fix, "PREM-900004"), _valor(fix, "PREM-900005"), int(_valor(fix, "PREM-900006"))
    q = Decimal("0.01")
    receita_anual = (area * aluguel * 12 * (1 - vac)).quantize(q, ROUND_HALF_EVEN)
    fator = sum(1 / (1 + taxa) ** t for t in range(1, prazo + 1))
    vpl_receita = (receita_anual * fator).quantize(q, ROUND_HALF_EVEN)
    capex = (area * obra).quantize(q, ROUND_HALF_EVEN)
    entrada = {p["id"]: str(p["valor"]) for p in fix["premissas"]}
    saida = {"delta_receita_anual_brl": str(receita_anual), "vpl_receita_brl": str(vpl_receita), "capex_brl": str(capex),
             "vpl_liquido_brl": str(vpl_receita - capex)}
    return {"entrada": entrada, "saida": saida, "sha256_entrada": sha(entrada), "sha256_saida": sha(saida)}


# ------------------------------------------------------------------------------------------------ pacotes
def montar_pacote(origem, destino, passo, fix, data, resultado_esperado, tarefa, referencias=None):
    corpo = {"cenario": fix["id"], "tarefa": tarefa, "observacao": "Conteúdo de TESTE. Nenhuma premissa aqui está aprovada."}
    p = {"identificador": f"PKG-{fix['id']}-{passo:02d}", "produto_origem": origem, "produto_destinatario": destino, "versao": 1, "data": data,
         "natureza_dados": "SINTETICO", "classificacao_sigilo": SIGILO_PERMITIDO,
         "referencias_premissas": sorted(referencias or [x["id"] for x in fix["premissas"]]), "estado_aprovacao": "PROPOSTA",
         "resultado_esperado": resultado_esperado, "corpo": corpo}
    p["sha256"] = sha({k: v for k, v in p.items() if k != "sha256"})
    return p


def validar_pacote(p):
    """Lista de problemas (vazia = pacote aceitável para transferência de TESTE)."""
    if not isinstance(p, dict):
        return ["pacote não é um objeto JSON"]
    problemas = [f"campo ausente ou vazio: {c}" for c in CAMPOS_PACOTE if c not in p or p[c] in (None, "", [])]
    if problemas:
        return problemas
    if p["natureza_dados"] != "SINTETICO":
        problemas.append(f"natureza_dados {p['natureza_dados']!r}: só SINTETICO é aceito")
    if p["classificacao_sigilo"] != SIGILO_PERMITIDO:
        problemas.append(f"classificacao_sigilo {p['classificacao_sigilo']!r}: só {SIGILO_PERMITIDO} é aceito")
    if p["estado_aprovacao"] != "PROPOSTA":
        problemas.append("estado_aprovacao deve ser PROPOSTA (APROVADA decorre de aprovação humana assinada, nunca de um pacote)")
    for campo in ("produto_origem", "produto_destinatario"):
        if p[campo] not in PRODUTOS:
            problemas.append(f"{campo} desconhecido: {p[campo]!r}")
    if not isinstance(p["referencias_premissas"], list) or not all(G.PADRAO_PREMISSA.fullmatch(str(r)) for r in p["referencias_premissas"]):
        problemas.append("referencias_premissas devem ser identificadores PREM-nnn")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(p["data"])):
        problemas.append("data deve ser AAAA-MM-DD")
    texto = json.dumps(p, ensure_ascii=False)
    for rx in PROIBIDO:
        if rx.search(texto):
            problemas.append(f"conteúdo proibido em pacote de teste (material real ou sigiloso): padrão {rx.pattern}")
    if p["sha256"] != sha({k: v for k, v in p.items() if k != "sha256"}):
        problemas.append("sha256 não confere (pacote alterado após a emissão)")
    return problemas


# ------------------------------------------------------------------------------------------------ cadeia
def _verificar_cadeia(linhas):
    prev, problemas = "0" * 64, []
    for i, l in enumerate(linhas, 1):
        r = json.loads(l)
        if r["seq"] != i or r["prev"] != prev or r["hash"] != sha({k: v for k, v in r.items() if k != "hash"}):
            problemas.append(f"linha {i}: cadeia de transferências inválida")
        prev = r["hash"]
    return problemas


def verificar_cadeia_arquivo(caminho):
    return _verificar_cadeia([l for l in Path(caminho).read_text(encoding="utf-8").splitlines() if l])


def executar_cenario(saida, data=None):
    """Roda a MECÂNICA do cenário. Devolve o relatório (cada verificação PASSOU/FALHOU; execução por agentes NAO_EXECUTADO)."""
    data = data or date.today().isoformat()
    saida = Path(saida)
    (saida / "pacotes").mkdir(parents=True, exist_ok=True)
    fix = fixture_cenario()
    (saida / "fixture.json").write_text(json.dumps(fix, ensure_ascii=False, indent=1), encoding="utf-8")
    verif = {}
    calc1, calc2 = calculo_p4(fix), calculo_p4(fix)
    verif["calculo_p4_reproduzivel"] = calc1 == calc2
    (saida / "calculo-p4.json").write_text(json.dumps(calc1, indent=1), encoding="utf-8")

    # 1) premissas no repositório REAL de premissas (em diretório temporário, nunca no registro do projeto)
    tmp = Path(tempfile.mkdtemp(prefix="integracao-"))
    try:
        (tmp / "fontes").mkdir()
        (tmp / "fontes" / f"{ID_FONTE}.json").write_text(json.dumps(fix["fonte"]), encoding="utf-8")
        repo = PR.RepositorioPremissas(tmp)
        for p in fix["premissas"]:
            prem = {k: v for k, v in p.items() if k != "descricao"} | {"descricao": p["descricao"]}
            repo.propor(prem, "teste-integracao")
        verif["premissas_registradas_como_proposta"] = all(repo.estado(p["id"], 1) == "PROPOSTA" for p in fix["premissas"])
        try:
            repo.ler_aprovada("PREM-900001")
            verif["nenhuma_premissa_aprovada_automaticamente"] = False
        except PermissionError:
            verif["nenhuma_premissa_aprovada_automaticamente"] = True
        try:
            repo.propor(dict(fix["premissas"][0], versao=2, status="APROVADA"), "teste-integracao")
            verif["declarar_aprovada_e_recusado"] = False
        except PermissionError:
            verif["declarar_aprovada_e_recusado"] = True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 2) cadeia de encaminhamentos
    prev, linhas, todos_validos = "0" * 64, [], True
    for i, (o, d, tarefa, esperado) in enumerate(ENCAMINHAMENTOS, 1):
        pacote = montar_pacote(o, d, i, fix, data, esperado, tarefa)
        todos_validos &= not validar_pacote(pacote)
        nome = f"{i:02d}-{o}-para-{d}.json"
        (saida / "pacotes" / nome).write_text(json.dumps(pacote, ensure_ascii=False, indent=1), encoding="utf-8")
        reg = {"seq": i, "pacote": pacote["identificador"], "origem": o, "destino": d, "sha256_pacote": pacote["sha256"], "prev": prev}
        reg["hash"] = sha(reg)
        prev = reg["hash"]
        linhas.append(json.dumps(reg, sort_keys=True))
    (saida / "cadeia-de-transferencias.jsonl").write_text("\n".join(linhas) + "\n", encoding="utf-8")
    verif["pacotes_validos"] = bool(todos_validos)
    verif["cadeia_de_transferencias_integra"] = not _verificar_cadeia(linhas)
    verif["cadeia_cobre_c_p1_a_p7_e_revisor"] = [(a, b) for a, b, *_ in ENCAMINHAMENTOS] == [("C", "P1"), ("P1", "P2"), ("P2", "P3"), ("P3", "P4"),
                                                                                          ("P4", "P5"), ("P5", "P6"), ("P6", "P7"), ("P7", "REV"), ("REV", "C")]

    # 3) conferência mecânica do "revisor": recalcula e compara (não substitui a revisão por agente)
    verif["revisor_mecanico_confere_calculo"] = calculo_p4(fix)["sha256_saida"] == calc1["sha256_saida"]
    verif["revisor_mecanico_confere_fonte_fixture"] = fix["fonte"]["tipo"] == "FIXTURE_DE_TESTE" and fix["natureza_dados"] == "SINTETICO"

    proposta = {"cenario": ID_CENARIO, "estado": "PROPOSTA", "proposto_por": "C (mecânica do cenário; sem raciocínio de agente)",
                "impacto": calc1["saida"], "portao_humano_aplicavel": "Coordenador humano: alteração de área comercial afeta receitas, CAPEX e escopo "
                "(política: nenhum agente aprova escopo, prazo, risco, preço ou publicação); publicação exigiria aprovação separada",
                "aprovada": False}
    (saida / "proposta-de-decisao.json").write_text(json.dumps(proposta, ensure_ascii=False, indent=1), encoding="utf-8")
    verif["proposta_nao_e_aprovada"] = proposta["aprovada"] is False and proposta["estado"] == "PROPOSTA"
    relatorio = {
        "cenario": ID_CENARIO, "data": data,
        "verificacoes_mecanicas": {k: ("PASSOU" if v else "FALHOU") for k, v in verif.items()},
        "execucao_por_agentes_reais": "NAO_EXECUTADO: exige chamada real ao modelo (sem credencial provisionada por humano); aqui só a mecânica foi exercida",
        "transferencia_para_o_claude_chat": "NAO_EXECUTADO: sem acesso à interface do Claude Chat nesta sessão; usar o roteiro manual supervisionado",
    }
    (saida / "resultado-integracao.json").write_text(json.dumps(relatorio, ensure_ascii=False, indent=1), encoding="utf-8")
    return relatorio


# ------------------------------------------------------------------------------------------------ contexto para o Chat
INSTRUCOES = """# Instruções globais SUGERIDAS para o projeto PPP — Centro Administrativo de Betim (Claude Chat)

Fonte de verdade: o REPOSITÓRIO. Este projeto de chat é espelho de trabalho, não fonte oficial de premissas.
1. Dados: use apenas o que o pacote de contexto traz; não cole documentos sigilosos nem pessoais.
2. Premissas: tudo que você propuser é PROPOSTA. Nenhum agente aprova escopo, prazo, risco, preço ou publicação.
3. Cada conversa atende UMA frente (C ou P1..P7). Não assuma o que outra conversa "decidiu": só vale o que veio num pacote com identificador.
4. Ao enviar algo a outra frente, gere um pacote com: identificador, origem, destinatário, versão, data, natureza dos dados, sigilo,
   referências de premissas, estado de aprovação e resultado esperado (ver TEMPLATE-PACOTE.json).
5. Não declare sincronização com o repositório: ela é manual e supervisionada por humano.
6. O c-orquestrador coordena; não é substituído por outra ferramenta.
"""
ARQUIVOS_DO_CONTEXTO = ("MATRIZ-DE-AGENTES.md", "REGRAS-DE-TRANSFERENCIA.md", "TEMPLATE-PACOTE.json", "FIXTURE-TESTE-INTEGRACAO-001.json")


def construir_contexto(saida, projeto, data=None):
    """Pacote de contexto SINTÉTICO e versionado para carregar manualmente no Claude Chat. Só texto gerado aqui + a matriz de agentes pública."""
    saida, projeto = Path(saida), Path(projeto)
    saida.mkdir(parents=True, exist_ok=True)
    matriz = json.loads((projeto / "governanca/matriz-agentes.json").read_text(encoding="utf-8"))
    linhas = ["# Matriz de agentes (resumo; fonte: governanca/matriz-agentes.json do repositório)", "",
              "| Agente | Área de escrita | Skills autorizadas |", "|---|---|---|"]
    def limpo(itens):                                      # áreas restritas não vão para o Chat: nem o caminho
        return ", ".join("(área restrita; omitida)" if any(rx.search(i) for rx in PROIBIDO) else i for i in itens) or "—"
    for ag, d in matriz["agentes"].items():
        linhas.append(f"| {ag} | {limpo(d.get('escrita') or [])} | {', '.join(d.get('skills') or [])} |")
    regras = ["# Regras de transferência entre frentes", "",
              "- Transferência é MANUAL e supervisionada: copiar o pacote JSON da frente de origem para a conversa da frente de destino.",
              "- O pacote só vale se validar (scripts/integracao_chat.py validar). Pacote com estado diferente de PROPOSTA, natureza diferente de SINTETICO",
              "  ou com material proibido (documento de referência real, CPF/CNPJ, e-mail, áreas sigilosas, chaves) é recusado.",
              "- O retorno do Chat ao repositório passa por registro humano; nada do Chat vira premissa APROVADA por si.", ""]
    template = montar_pacote("<ORIGEM>", "<DESTINO>", 0, fixture_cenario(), "AAAA-MM-DD", "<resultado esperado>", "<tarefa>")
    template["produto_origem"], template["produto_destinatario"] = "C", "P1"
    arquivos = {"INSTRUCOES-GLOBAIS-SUGERIDAS.md": INSTRUCOES, "MATRIZ-DE-AGENTES.md": "\n".join(linhas) + "\n", "REGRAS-DE-TRANSFERENCIA.md": "\n".join(regras),
                "TEMPLATE-PACOTE.json": json.dumps(template, ensure_ascii=False, indent=1),
                "FIXTURE-TESTE-INTEGRACAO-001.json": json.dumps(fixture_cenario(), ensure_ascii=False, indent=1)}
    for nome, conteudo in arquivos.items():
        for rx in PROIBIDO:
            if rx.search(conteudo):
                raise SystemExit(f"contexto recusado: {nome} contém material proibido ({rx.pattern})")
        (saida / nome).write_text(conteudo, encoding="utf-8")
    manifesto = {"pacote": "CONTEXTO-CHAT-PPP-BETIM", "versao": 1, "data": data or date.today().isoformat(), "natureza_dados": "SINTETICO",
                 "classificacao_sigilo": SIGILO_PERMITIDO, "fonte_de_verdade": "repositório (não este pacote)",
                 "exclui": ["dados/", "logs/", "registros/", "produtos/", "documentos da Prefeitura ou do Monte Carmo", "credenciais"],
                 "arquivos": {n: hashlib.sha256(c.encode("utf-8")).hexdigest() for n, c in sorted(arquivos.items())}}
    (saida / "MANIFESTO.json").write_text(json.dumps(manifesto, ensure_ascii=False, indent=1), encoding="utf-8")
    return manifesto


def verificar_contexto(pasta):
    """Confere o manifesto contra os arquivos (detecta arquivo alterado, ausente ou fora do manifesto)."""
    pasta = Path(pasta)
    m = json.loads((pasta / "MANIFESTO.json").read_text(encoding="utf-8"))
    problemas = []
    for nome, h in m["arquivos"].items():
        arq = pasta / nome
        if not arq.is_file():
            problemas.append(f"{nome}: ausente")
        elif hashlib.sha256(arq.read_bytes()).hexdigest() != h:
            problemas.append(f"{nome}: alterado depois do manifesto")
    extras = {p.name for p in pasta.iterdir()} - set(m["arquivos"]) - {"MANIFESTO.json"}
    problemas += [f"{x}: arquivo fora do manifesto" for x in sorted(extras)]
    return problemas


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cenario")
    c.add_argument("--saida", required=True)
    c.add_argument("--data")
    x = sub.add_parser("contexto")
    x.add_argument("--saida", required=True)
    x.add_argument("--projeto", default=str(Path(__file__).resolve().parent.parent))
    v = sub.add_parser("validar")
    v.add_argument("pacote")
    a = ap.parse_args(argv)
    if a.cmd == "cenario":
        r = executar_cenario(a.saida, a.data)
        print(json.dumps(r, ensure_ascii=False, indent=1))
        return 0 if all(v == "PASSOU" for v in r["verificacoes_mecanicas"].values()) else 1
    if a.cmd == "contexto":
        print(json.dumps(construir_contexto(a.saida, a.projeto), ensure_ascii=False, indent=1))
        return 0
    problemas = validar_pacote(json.loads(Path(a.pacote).read_text(encoding="utf-8")))
    for p in problemas:
        print("PROBLEMA:", p, file=sys.stderr)
    return 1 if problemas else 0


if __name__ == "__main__":
    sys.exit(main())
