# PPP-CENTRO-ADMINISTRATIVO-BETIM

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

**Requisitos:** Python 3.11 ou superior e as dependências de
`requirements.txt` (`python3 -m pip install -r requirements.txt`). Sem elas,
o gerador não executa e a validação e a aprovação de premissas falham fechadas.

### Opção 1 — Recebi o ZIP

Extraia `PPP-CENTRO-ADMINISTRATIVO-BETIM.zip` em uma pasta de sua escolha.

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
| Validação de premissas (GOV-01) | JSON Schema aplicado; versões imutáveis com cadeia de hashes; testada com dados sintéticos |
| Aprovação humana (GOV-02) | Assinatura Ed25519 verificada; registro de aprovadores vazio; proteção efetiva depende de controles externos |
| Gerador em `scripts/gerar_projeto.py` | Cópia idêntica à fonte, com SHA-256 conferido nos testes |
| Testes (4 estruturais + 6 de governança + 22 de GOV-01/02) | Executados e aprovados; condição para gerar o ZIP |
| Conteúdo do ZIP | Verificado pelo gerador após a criação |
| Homologação funcional | Pendente |

## Integridade de premissas e aprovação humana

Ver `governanca/GOV-01-02-fronteira-de-confianca.md`: regras implementadas,
fronteira de confiança, permissões necessárias e riscos residuais.
