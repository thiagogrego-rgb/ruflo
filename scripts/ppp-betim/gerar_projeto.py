from pathlib import Path
import json
import re
import sys
import zipfile
import hashlib
import unittest
import tempfile
import shutil

PROJECT = "PPP-CENTRO-ADMINISTRATIVO-BETIM"
ROOT = Path.cwd() / PROJECT

AGENTS = {
    "c-orquestrador": (
        "Coordenação e governança",
        "Planejar atividades, monitorar C e P1-P7, consolidar decisões, dependências, cronogramas e comunicação institucional.",
        "cronograma, registros de decisões, status dos produtos",
        "plano de trabalho, relatório gerencial, atas e minutas",
        "mudança de escopo, prazo ou preço"
    ),
    "p1-diagnostico": (
        "Diagnóstico e modelo",
        "Comparar alternativas de contratação, manter a matriz de 17 serviços e analisar experiências de PPPs comparáveis.",
        "documento-base, matriz de serviços, referências",
        "diagnóstico, análise de alternativas, matriz de serviços",
        "escolha do modelo e matriz final"
    ),
    "p2-engenharia": (
        "Engenharia e TI",
        "Consolidar levantamento físico, programa de necessidades, layout, CAPEX, OPEX, reinvestimentos, TI e Praça do Encontro.",
        "plantas, laudos, formulários, requisitos P1",
        "quadro de áreas, CAPEX, OPEX, cronograma, TI",
        "divisão de áreas e orçamento-base"
    ),
    "p3-mercado": (
        "Mercado e imóvel",
        "Analisar o Monte Carmo, contratos comerciais, demanda, vacância, aluguéis e receitas da Praça e publicidade.",
        "documentos do shopping, áreas P2, estudo externo",
        "estudo comercial, cenários de receita, avaliação",
        "premissas de receita comercial"
    ),
    "p4-modelagem": (
        "Modelagem econômico-financeira",
        "Construir comparador público, plano de negócios, value for money, capacidade fiscal e sensibilidades.",
        "P1, P2, P3, riscos P5, dados fiscais",
        "fluxo de caixa, comparador, VfM e cenários",
        "contraprestação, desconto e receitas"
    ),
    "p5-juridico": (
        "Jurídico",
        "Preparar modelagem jurídica, matriz de riscos, minutas de edital, contrato e anexos.",
        "escopo P1, encargos P2, modelo P4",
        "minutas, matriz de riscos, conformidade",
        "alocação de riscos e equilíbrio contratual"
    ),
    "p6-participacao": (
        "Consulta e audiência pública",
        "Preparar materiais, catalogar contribuições, analisar impactos e propor respostas fundamentadas.",
        "documentos liberados, contribuições recebidas",
        "matriz de contribuições, respostas, relatório",
        "acolhimento de contribuições e publicação"
    ),
    "p7-licitacao": (
        "Apoio à licitação",
        "Analisar esclarecimentos, impugnações, propostas, habilitação e consistência econômico-financeira.",
        "edital vigente, propostas, P4 e P5",
        "minutas de respostas e relatórios técnicos",
        "respostas oficiais e julgamento"
    ),
    "controlador-dr": (
        "Controle do data request",
        "Catalogar documentos e pendências dos 73 itens e 11 blocos do DR-01/2026.",
        "lista oficial do DR, documentos recebidos",
        "inventário, status e minutas de cobrança",
        "comunicação externa"
    ),
    "revisor-independente": (
        "Verificação independente",
        "Conferir fontes, reproduzir cálculos, detectar divergências e registrar achados sem modificar o objeto auditado.",
        "artefatos versionados, fontes e cálculos",
        "relatório de verificação e ressalvas",
        "não possui competência decisória"
    )
}

# Nome: (consumidores, objetivo, procedimento, saída)
SKILLS = {
    "ingestao-data-request": (
        "Todas",
        "Catalogar documentos recebidos e relacioná-los ao DR-01.",
        "Inventariar; calcular hash; identificar origem; relacionar item; conferir completude; classificar sigilo; apontar pendências.",
        "inventário e registro de fontes"
    ),
    "base-premissas": (
        "Todas",
        "Registrar e versionar hipóteses e dados compartilhados.",
        "Verificar fonte, unidade, data-base e natureza; identificar conflitos; propor versão; mapear dependências; solicitar revisão.",
        "registro de premissas e histórico"
    ),
    "verificacao-independente": (
        "Todas",
        "Conferir resultados sem modificar o objeto auditado.",
        "Identificar versão; conferir fontes; reproduzir cálculos; comparar produtos; documentar testes e achados.",
        "relatório independente"
    ),
    "execucao-orcamentaria-municipal": (
        "P4",
        "Reconciliar despesas e contratos municipais por serviço.",
        "Importar execução 2023-2026; separar empenhado, liquidado e pago; tratar duplicidades; reconciliar contratos e exercícios.",
        "base histórica de custos"
    ),
    "comparador-publico": (
        "P4",
        "Projetar custos comparáveis da provisão pública por 30 anos.",
        "Alinhar escopo; consolidar despesas e pessoal; incluir investimentos e riscos; projetar fluxos; calcular valor presente.",
        "comparador público reproduzível"
    ),
    "programa-necessidades-layout": (
        "P2",
        "Dimensionar ambientes e área comercial remanescente.",
        "Conferir formulários; consolidar postos e ambientes; aplicar parâmetros rastreáveis; conciliar área útil e bruta.",
        "programa de necessidades e quadro de áreas"
    ),
    "analise-varejo-shopping": (
        "P3",
        "Analisar desempenho comercial do Monte Carmo.",
        "Conciliar contratos e lojas; medir ABL, aluguel, vacância, faturado e recebido; construir cenários.",
        "indicadores comerciais e premissas"
    ),
    "perfil-demanda-publico": (
        "P3",
        "Estimar demanda potencial gerada pelo Centro Administrativo.",
        "Agregar servidores e atendimentos; revisar amostra; estimar frequência e consumo; testar sazonalidade e sobreposição.",
        "perfil de demanda e cenários"
    ),
    "capex-opex-ciclo-vida": (
        "P2",
        "Estimar investimento, operação e reposições em 30 anos.",
        "Levantar quantitativos; associar preços e datas; separar CAPEX/OPEX; programar manutenções e reinvestimentos.",
        "orçamento e fluxo de ciclo de vida"
    ),
    "ti-como-servico": (
        "P2",
        "Dimensionar infraestrutura, suporte e serviços tecnológicos.",
        "Inventariar sistemas; medir capacidade; estruturar alternativas; definir SLA, segurança, continuidade e custos.",
        "arquitetura de TI e indicadores"
    ),
    "avaliacao-imobiliaria": (
        "P3",
        "Apoiar avaliação de áreas comerciais conforme normas pertinentes.",
        "Definir objeto; verificar áreas; reunir amostras; selecionar método aplicável; calcular; registrar ressalvas.",
        "estudo de apoio à avaliação"
    ),
    "plano-negocios-ppp": (
        "P4 e P7",
        "Construir fluxo de caixa e métricas de viabilidade.",
        "Importar entradas versionadas; modelar receita, tributos, custos, financiamento; calcular VPL, TIR e contraprestação proposta.",
        "plano de negócios reproduzível"
    ),
    "value-for-money": (
        "P4",
        "Comparar cenário PPP com provisão pública.",
        "Alinhar escopo, prazo, preço e risco; calcular fluxos descontados; verificar dupla contagem; analisar fatores qualitativos.",
        "relatório VfM"
    ),
    "capacidade-fiscal-ppp": (
        "P4",
        "Verificar comprometimento fiscal e restrições legais.",
        "Validar RCL; identificar compromissos e Finisa; atualizar normas aplicáveis; simular limites, garantias e cenários.",
        "estudo de capacidade fiscal"
    ),
    "matriz-riscos-ppp": (
        "P5 e P4",
        "Identificar riscos, mitigação, alocação proposta e impactos.",
        "Catalogar eventos; avaliar causas e consequências; propor alocação; associar cláusulas e efeitos econômicos.",
        "matriz de riscos versionada"
    ),
    "indicadores-mecanismo-pagamento": (
        "P5 e P2",
        "Definir indicadores e mecanismos de remuneração.",
        "Relacionar serviços, metas e pesos; definir medição, fórmulas, descontos e testes de casos-limite.",
        "caderno de indicadores e algoritmo"
    ),
    "minutas-ppp": (
        "P5",
        "Preparar edital, contrato e anexos em versões controladas.",
        "Utilizar modelos autorizados; inserir cláusulas rastreáveis; conferir referências, remissões, obrigações e riscos.",
        "minutas e matriz de conformidade"
    ),
    "consulta-publica": (
        "P6",
        "Sistematizar contribuições e respostas de consulta.",
        "Catalogar manifestações; preservar original; classificar temas; atribuir frente; propor respostas e revisões.",
        "matriz de contribuições e relatório"
    ),
    "apresentacao-padrao-ceabe": (
        "C",
        "Produzir apresentações segundo o padrão CEABE.",
        "Inspecionar template; selecionar informações aprovadas; produzir gráficos rastreáveis; revisar sigilo e legibilidade.",
        "apresentação editável"
    )
}

POLICY = """# Governança obrigatória

- Autonomia supervisionada, decisões críticas reservadas ao coordenador.
- Nenhum agente aprova escopo, prazo, risco, preço ou publicação.
- Aprovação interna não substitui competência institucional.
- Toda premissa possui fonte ou natureza explícita de hipótese.
- Cálculos críticos devem ser reproduzíveis.
- Registro aprovado não pode ser sobrescrito.
- Mudança compartilhada exige análise de impacto.
- O revisor não modifica o objeto que audita.
- Informações PUBLICO, INTERNO, RESTRITO e PESSOAL têm acessos distintos.
- Publicação exige aprovação humana separada.
- Sem mecanismo confiável de aprovação, bloquear a transição.
"""

PROMPT = """# PROJETO — Implantação da PPP Centro Administrativo de Betim

## P — Papel
Arquiteto técnico e implementador do ambiente multiagente Claude Code.

## R — Referências
Documento original da PPP, decisões A1-A4 e arquivos presentes neste repositório.

## O — Objetivo
Inspecionar, completar, testar e homologar progressivamente dez agentes,
dezenove skills e os registros de governança.

## J — Julgamento
Priorizar integridade, segurança, rastreabilidade e reprodutibilidade.

## E — Entradas e restrições
Não inventar fontes, ferramentas, arquivos, aprovações ou resultados.
Não iniciar análises definitivas com dados reais antes da homologação.
Não presumir integração automática com Claude Projects.
Não sobrescrever configurações ou skills preexistentes sem inspeção.

## T — Saídas
Arquivos, scripts, testes, relatório de execução, pendências e manual.

## O — Validação
Distinguir PLANEJADO, CRIADO, TESTADO, APROVADO e OPERACIONAL.
Registrar testes executados e evidências.
Iniciar inspecionando o ambiente e produzindo inventário.
"""

def write(relative, content):
    path = ROOT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")

def create_project():
    if ROOT.exists():
        raise RuntimeError(
            f"Diretório já existe: {ROOT}. "
            "Nada foi sobrescrito."
        )
    ROOT.mkdir(parents=True)
    # Cópia byte a byte do gerador em execução; a origem não é alterada.
    gerador = Path(__file__).resolve().read_bytes()
    (ROOT / "scripts").mkdir()
    (ROOT / "scripts/gerar_projeto.py").write_bytes(gerador)
    write("scripts/gerar_projeto.py.sha256",
          f"{hashlib.sha256(gerador).hexdigest()}  gerar_projeto.py")
    write("CLAUDE.md", POLICY + """
# Trabalho por frentes
C: coordenação; P1: diagnóstico; P2: engenharia; P3: mercado;
P4: econômico-financeiro; P5: jurídico; P6: consulta; P7: licitação.

# Procedimento
1. Identificar tarefa, fontes, versões e permissões.
2. Consultar registros e dependências.
3. Escolher agente e skill.
4. Executar análise com método verificável.
5. Registrar resultado, limitações e hipóteses.
6. Solicitar revisão independente.
7. Submeter decisões críticas ao coordenador.
""")
    write("README.md", f"""# {PROJECT}

Pacote inicial para Claude Code + Claude Projects.

## Estado do pacote

Este pacote é um bootstrap estrutural, não um ambiente homologado.

Os testes iniciais não demonstram segurança integral, funcionamento dos
agentes ou integração automática ao Claude Projects.

A utilização de dados reais restritos permanece condicionada à
implementação e homologação dos controles de governança.

Comece pelo `00-LEIA-ME-PRIMEIRO.md`.

O documento original `PPP Centro Administrativo de Betim —
Funções e agentes de análise.md` precisa ser colocado em `referencias/`.

## Como utilizar o pacote

**Requisito para executar o gerador:** Python 3.11 ou superior.

### Opção 1 — Recebi o ZIP

Extraia `{PROJECT}.zip` em uma pasta de sua escolha.

Abra o diretório extraído no Claude Code e leia `00-LEIA-ME-PRIMEIRO.md`.

O projeto já contém sua estrutura inicial, agentes e skills.
**Não é necessário executar novamente o gerador.**

O arquivo `scripts/gerar_projeto.py` acompanha o pacote para referência,
auditoria e reprodução em ambiente separado. Seu SHA-256 está registrado
em `scripts/gerar_projeto.py.sha256` e é conferido pelos testes.

### Opção 2 — Estou trabalhando no repositório

A fonte oficial é `scripts/ppp-betim/gerar_projeto.py` no repositório.
O gerador cria o projeto no diretório atual; execute-o a partir de uma
pasta vazia fora do repositório:

```bash
mkdir ppp-betim && cd ppp-betim
python3 /caminho/do/repositorio/scripts/ppp-betim/gerar_projeto.py
```

No Windows, utilize `py` em vez de `python3`.

Se o diretório de destino já existir, o gerador interrompe a execução sem
sobrescrever arquivos.

O ZIP só será produzido depois que todos os testes obrigatórios passarem.
Em seguida, o gerador confere o conteúdo do ZIP (gerador, README, dez
agentes e 19 skills) e o remove se algum item faltar. Essa verificação
atesta a integridade da distribuição, não a homologação funcional.

## O que ele efetivamente entrega

| Componente | Situação após execução bem-sucedida |
|---|---|
| Estrutura de diretórios | Criada |
| Dez arquivos de agentes | Criados, não homologados |
| Dezenove arquivos SKILL.md | Criados, não homologados |
| Instruções do Claude Projects | Criadas como texto; sem integração automática |
| Políticas fundamentais | Criadas como texto; sem bloqueio técnico |
| Validador inicial de premissas | Criado; cobre campos obrigatórios, natureza e status, mas não o tipo de `versao` |
| Gerador em `scripts/gerar_projeto.py` | Cópia idêntica à fonte, com SHA-256 conferido nos testes |
| Testes (4 estruturais + 6 de governança) | Executados e aprovados; condição para gerar o ZIP |
| Conteúdo do ZIP | Verificado pelo gerador após a criação |
| Homologação funcional | Pendente |

## Melhorias registradas para a próxima versão

- Validar `versao` como inteiro positivo.
- Utilizar efetivamente `governanca/schemas/premissa.schema.json` no
  validador, em vez de manter dois mecanismos de validação potencialmente
  divergentes.
""")
    write("00-LEIA-ME-PRIMEIRO.md", """# Guia de implantação

1. Verifique os arquivos e o resultado dos testes.
2. Inclua o documento original na pasta referencias.
3. Abra esta pasta como projeto no Claude Code.
4. Execute o prompt mestre.
5. Inspecione as três skills preexistentes sem sobrescrevê-las.
6. Configure aprovações externas e permissões efetivas.
7. Faça os testes funcionais antes de usar dados reais.
8. Prepare Claude Projects apenas com conteúdo autorizado.

Não confunda geração de arquivos com homologação.
""")
    write("01-PROMPT-MESTRE-PROJETO.md", PROMPT)
    write("governanca/politica-aprovacoes.md", POLICY)
    write("governanca/politica-premissas.md", """# Premissas
Campos obrigatórios: ID, versão, produto, natureza, unidade,
data-base quando aplicável, fonte ou hipótese, status e dependências.

Estados: PROPOSTA, EM_VERIFICACAO, VERIFICADA, APROVADA,
REJEITADA, SUBSTITUIDA.

Uma hipótese aprovada para cenário continua sendo hipótese.
Aprovação exige mecanismo humano independente da IA.
""")
    write("governanca/politica-sigilo.md", """# Sigilo
PUBLICO: divulgado oficialmente.
INTERNO: restrito ao ambiente de trabalho autorizado.
RESTRITO: acesso específico segundo necessidade.
PESSOAL: minimização e proteção adicional.

Não considerar o nome da pasta uma barreira de segurança.
Validar permissões efetivas do sistema de arquivos.
Não transferir documentos restritos automaticamente ao Projects.
""")
    write("governanca/politica-publicacao.md", """# Publicação
Aprovação técnica e autorização de publicação são atos separados.
Validar versão, destino, autorização humana, anexos e metadados.
Na ausência de autorização verificável, bloquear.
""")

    for name, (title, mission, inputs, outputs, gate) in AGENTS.items():
        tools = "Read, Grep, Glob"
        if name != "revisor-independente":
            tools += ", Write"
        write(f".claude/agents/{name}.md", f"""---
name: {name}
description: {title} da PPP Centro Administrativo de Betim.
tools: {tools}
---

# PROJETO — {title}

## P — Papel
Especialista responsável por {title.lower()}.

## R — Referências
Documento original, CLAUDE.md, políticas e versões aprovadas.

## O — Objetivo
{mission}

## J — Julgamento
Rastreabilidade, coerência técnica, legalidade aplicável,
qualidade da evidência e identificação de riscos.

## E — Entradas e restrições
Entradas: {inputs}.
Não inventar valores nem usar fontes inexistentes.
Não alterar registros aprovados.
Não executar decisões reservadas ao coordenador.
Respeitar sigilo e autonomia supervisionada.

## T — Saídas
{outputs}.
Indicar fontes, versões, pendências e status de verificação.

## O — Validação
Submeter resultados críticos à verificação independente.
Portão de aprovação: {gate}.
Não declarar aprovação ou publicação sem evidência humana.
""")

    for name, (users, obj, procedure, result) in SKILLS.items():
        write(f".claude/skills/{name}/SKILL.md", f"""---
name: {name}
description: {obj} Aplicável à PPP Centro Administrativo de Betim.
---

# PROJETO — {name}

## P — Papel
Especialista metodológico para {users}.

## R — Referências e contexto
Documento-base, fontes catalogadas, políticas de premissas
e versões aprovadas do projeto.

## O — Objetivo
{obj}

## J — Julgamento esperado
Integridade, coerência de escopo, origem dos dados,
qualidade das evidências e cálculo reproduzível.

## E — Entradas, procedimento e restrições
Entradas: arquivos autorizados, premissas versionadas
e contratos de interface pertinentes.

Procedimento:
{procedure}

Não fabricar fontes. Não decidir parâmetros críticos.
Não substituir profissional habilitado.
Não publicar ou alterar premissas aprovadas.
Cálculos quantitativos devem utilizar código ou planilha.

## T — Tipo de saída
{result}.
Incluir IDs das fontes, versões, data-base e ressalvas.

## O — Observações de validação
Testar execução normal, dados ausentes,
entradas conflitantes e operação não autorizada.
Se houver cálculos, exigir recálculo independente.
Não declarar a skill testada apenas por existir SKILL.md.
""")

    for product in ["C"] + [f"P{i}" for i in range(1, 8)]:
        write(f"produtos/{product}/README.md",
              f"# Produto {product}\n\nÁrea de trabalho do produto.\n"
              "Versões aprovadas exigem registro de governança.\n")

    for directory in (
        "dados/entrada", "dados/processados", "dados/restritos",
        "registros/fontes", "registros/premissas",
        "registros/decisoes", "registros/verificacoes",
        "registros/entregaveis", "registros/auditoria",
        "referencias", "testes/fixtures"
    ):
        write(f"{directory}/.gitkeep", "")

    write(".gitignore", """__pycache__/
*.pyc
.venv/
.env
# Conteúdo de dados/ e registros/ fica fora do git; a estrutura (.gitkeep) não.
dados/**/*
!dados/**/
!dados/**/.gitkeep
registros/**/*
!registros/**/
!registros/**/.gitkeep
*.zip
""")

    write("projects/instrucoes-projects.md", """# PROJETO — Claude Projects

## P — Papel
Assistente de acompanhamento das frentes C e P1-P7.

## R — Referências
Somente o contexto autorizado e as decisões formalizadas.

## O — Objetivo
Discutir resultados, resumir estudos e preparar propostas.

## J — Julgamento
Clareza, rastreabilidade e prudência técnica.

## E — Restrições
Não presumir sincronização com Claude Code.
Não registrar aprovação institucional por conta própria.
Não compartilhar dados restritos sem autorização.

## T — Saídas
Sínteses, relatórios, pendências e minutas.

## O — Validação
Informar fontes, versões e decisões ainda pendentes.
""")

    chats = ["C - Coordenação e governança"] + [
        f"P{i} - {AGENTS[f'p{i}-{slug}'][0]}"
        for i, slug in [
            (1,"diagnostico"), (2,"engenharia"),
            (3,"mercado"), (4,"modelagem"),
            (5,"juridico"), (6,"participacao"),
            (7,"licitacao")
        ]
    ] + ["CONTROLE - Data Request e verificação"]
    write("projects/roteiro-conversas.md",
          "# Conversas propostas\n\n" +
          "\n".join(f"- {x}" for x in chats) +
          "\n\nCriar somente com acesso autorizado.\n")

    write("arquitetura/catalogo-skills.md",
          "# Catálogo\n\n" +
          "\n".join(f"- `{k}` — {v[0]}" for k,v in SKILLS.items()))
    write("arquitetura/catalogo-agentes.md",
          "# Agentes\n\n" +
          "\n".join(f"- `{k}` — {v[0]}" for k,v in AGENTS.items()))

    write("governanca/schemas/premissa.schema.json",
          json.dumps({
              "$schema":"https://json-schema.org/draft/2020-12/schema",
              "type":"object",
              "required":["id","versao","produto","natureza",
                          "unidade","status"],
              "properties":{
                  "id":{"type":"string"},
                  "versao":{"type":"integer","minimum":1},
                  "produto":{"type":"string"},
                  "natureza":{"enum":["OBSERVADO","CALCULADO","HIPOTESE"]},
                  "unidade":{"type":"string","minLength":1},
                  "status":{"enum":["PROPOSTA","EM_VERIFICACAO",
                     "VERIFICADA","APROVADA","REJEITADA","SUBSTITUIDA"]},
                  "fonte_id":{"type":["string","null"]},
                  "justificativa_hipotese":{"type":["string","null"]}
              },
              "additionalProperties":True
          }, indent=2, ensure_ascii=False))

    write("scripts/governanca.py", '''"""Validações iniciais. Aprovação humana permanece bloqueada."""
import json
from pathlib import Path

def validar_premissa(p):
    obrigatorios = ("id","versao","produto","natureza",
                    "unidade","status")
    faltantes = [x for x in obrigatorios if x not in p]
    if faltantes:
        raise ValueError(f"Campos ausentes: {faltantes}")
    if not p["unidade"]:
        raise ValueError("Unidade ausente")
    if p["natureza"] not in ("OBSERVADO","CALCULADO","HIPOTESE"):
        raise ValueError("Natureza inválida")
    if p["status"] not in ("PROPOSTA","EM_VERIFICACAO",
                          "VERIFICADA","APROVADA",
                          "REJEITADA","SUBSTITUIDA"):
        raise ValueError("Status inválido")
    if p["natureza"] == "HIPOTESE":
        if not p.get("justificativa_hipotese"):
            raise ValueError("Hipótese sem justificativa")
    elif not p.get("fonte_id"):
        raise ValueError("Fonte obrigatória")
    if p["status"] == "APROVADA":
        raise PermissionError("Aprovação humana não configurada")
    return True

def aprovar_decisao(*args, **kwargs):
    raise PermissionError(
        "Mecanismo externo de autorização não configurado"
    )

def autorizar_publicacao(*args, **kwargs):
    raise PermissionError(
        "Publicação bloqueada até autorização humana verificável"
    )
''')

    write("testes/test_governanca.py", '''import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from governanca import validar_premissa, aprovar_decisao, autorizar_publicacao

BASE = dict(id="PREM-001", versao=1, produto="P3",
            natureza="HIPOTESE", unidade="BRL/m2/mes",
            status="PROPOSTA", justificativa_hipotese="Teste sintético")

class TestGovernanca(unittest.TestCase):
    def test_hipotese_valida(self):
        self.assertTrue(validar_premissa(BASE.copy()))
    def test_hipotese_sem_justificativa(self):
        p = BASE.copy()
        p.pop("justificativa_hipotese")
        with self.assertRaises(ValueError):
            validar_premissa(p)
    def test_dado_sem_fonte(self):
        p = BASE.copy()
        p["natureza"] = "OBSERVADO"
        with self.assertRaises(ValueError):
            validar_premissa(p)
    def test_aprovacao_bloqueada(self):
        p = BASE.copy()
        p["status"] = "APROVADA"
        with self.assertRaises(PermissionError):
            validar_premissa(p)
    def test_decisao_bloqueada(self):
        with self.assertRaises(PermissionError):
            aprovar_decisao()
    def test_publicacao_bloqueada(self):
        with self.assertRaises(PermissionError):
            autorizar_publicacao()
''')

    write("testes/test_estrutura.py", '''import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
class TestEstrutura(unittest.TestCase):
    def test_agentes(self):
        self.assertEqual(len(list((ROOT/".claude/agents").glob("*.md"))),10)
    def test_skills(self):
        self.assertEqual(len(list((ROOT/".claude/skills").glob("*/SKILL.md"))),19)
    def test_frontmatter(self):
        files = list((ROOT/".claude/agents").glob("*.md"))
        files += list((ROOT/".claude/skills").glob("*/SKILL.md"))
        for file in files:
            text = file.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\\n"),
                            str(file))
            self.assertIn("description:", text)
            self.assertIn("## O — Objetivo", text)
    def test_gerador_incluido(self):
        gerador = (ROOT/"scripts/gerar_projeto.py").read_bytes()
        registro = (ROOT/"scripts/gerar_projeto.py.sha256").read_text(
            encoding="utf-8").split()[0]
        self.assertEqual(hashlib.sha256(gerador).hexdigest(), registro)
''')

    write("RELATORIO-ESTADO.md", """# Estado do pacote

- Agentes: arquivos gerados, não homologados no Claude.
- Skills: instruções metodológicas geradas, sem scripts específicos.
- Governança: validador mínimo com bloqueio conservador.
- Schemas: primeiro schema de premissas.
- Aprovações: bloqueadas até integração humana confiável.
- Proteção de diretórios: ainda depende do sistema operacional.
- Testes: verificações estruturais e casos básicos.
- Fonte original DR e demais insumos: pendentes de importação.
- Integração ao Projects: pendente.

Não utilizar dados reais até avaliação da segurança.
""")

def create_zip():
    target = Path.cwd() / (PROJECT + ".zip")
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for file in ROOT.rglob("*"):
            if file.is_file() and "__pycache__" not in file.parts:
                z.write(file, file.relative_to(ROOT.parent))
    try:
        verificar_zip(target)
    except Exception:
        target.unlink()
        raise
    return target

def verificar_zip(target):
    """Confere integridade e conteúdo mínimo da distribuição."""
    with zipfile.ZipFile(target) as z:
        if z.testzip() is not None:
            raise RuntimeError("Falha de integridade ZIP")
        nomes = {n.split("/", 1)[1] for n in z.namelist() if "/" in n}
    esperados = ["README.md", "scripts/gerar_projeto.py",
                 "scripts/gerar_projeto.py.sha256"]
    esperados += [f".claude/agents/{a}.md" for a in AGENTS]
    esperados += [f".claude/skills/{s}/SKILL.md" for s in SKILLS]
    faltantes = [x for x in esperados if x not in nomes]
    if faltantes:
        raise RuntimeError(f"ZIP incompleto: {faltantes}")
    agentes = [n for n in nomes if re.fullmatch(r"\.claude/agents/[^/]+\.md", n)]
    skills = [n for n in nomes if re.fullmatch(r"\.claude/skills/[^/]+/SKILL\.md", n)]
    if (len(agentes), len(skills)) != (10, 19):
        raise RuntimeError(
            f"ZIP com {len(agentes)} agentes e {len(skills)} skills; esperado 10 e 19")

if __name__ == "__main__":
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11+ necessário")
    try:
        create_project()
        suite = unittest.defaultTestLoader.discover(
            str(ROOT / "testes"), pattern="test_*.py"
        )
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if not result.wasSuccessful():
            raise RuntimeError("Testes iniciais falharam")
        archive = create_zip()
        print("\nPROJETO:", ROOT)
        print("ZIP:", archive)
        print("VERIFICAÇÃO DO ZIP: OK")
        print("TESTES INICIAIS: PASSARAM")
        print("HOMOLOGAÇÃO FUNCIONAL: PENDENTE")
    except Exception as e:
        print("ERRO:", e)
        sys.exit(1)
