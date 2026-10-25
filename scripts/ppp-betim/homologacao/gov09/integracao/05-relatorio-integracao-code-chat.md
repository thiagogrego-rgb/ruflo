# Relatório de integração Code + Chat (Trilha B) — GOV-09 integrado

**A verdade desconfortável primeiro:** não existe, hoje, evidência de que o Claude Chat esteja alinhado com o repositório — nem de que seja o contrário. Esta sessão **não tem acesso** ao Claude Chat/Projects.
Tudo que depende de uma conversa real está **NÃO EXECUTADO**. O que se provou é a **mecânica do lado do repositório** (cenário, pacotes, cadeia, não-aprovação automática, pacote de contexto).
Não há sincronização automática e **não se declara** nenhuma.

## 1. Classificação por tipo de teste

| Tipo | Teste | Resultado | Evidência |
|---|---|---|---|
| Infraestrutura | S01–S10 do piloto | ver `../RELATORIO-FINAL-GOV-09.md` (10 PASSOU, S04 NÃO EXECUTADO) | `rodada-r1/r2.json` |
| Agentes nomeados | Dez agentes por papel, sessão `claude` real, modelo simulado | PASSOU (S08) | log do guardião |
| Skills carregadas | 19 skills do projeto exercitadas; recusa de não autorizadas e externas | PASSOU (S08, modelo simulado) | idem |
| Cenário integrado (mecânica) | TESTE-INTEGRACAO-001: fixture, premissas PROPOSTA, cálculo, 9 pacotes, cadeia | PASSOU (10 verificações) | `cenario-TESTE-INTEGRACAO-001/resultado-integracao.json` |
| Agentes executando o cenário | C, P1–P7, Revisor produzindo conteúdo | **NÃO EXECUTADO** (exige modelo real; sem credencial) | — |
| Conversa no Claude Chat | CH-01…CH-10 | **NÃO EXECUTADO** (sem acesso) | `02-roteiro-validacao-chat.md` |
| Transferência de contexto Code→Chat | Manual supervisionada | **NÃO EXECUTADO** (pacote e plano prontos) | `pacote-contexto-chat/`, `04-plano…` |
| Integração automatizada | Sincronização automática | **NÃO EXISTE** (por desenho); não testada | — |
| Manual supervisionado | Roteiro para humano | Preparado; **NÃO EXECUTADO** | `02-roteiro…` |

## 2. Cenário integrado TESTE-INTEGRACAO-001

Sintético, estado inicial PROPOSTA, fonte `FONTE-900001` marcada `FIXTURE_DE_TESTE`, seis premissas HIPOTESE (área +150 m², aluguel, vacância, custo de obra, taxa, prazo).
Cálculo reproduzível (Decimal): receita anual adicional R$ 140.760,00; CAPEX R$ 480.000,00; hashes de entrada e saída gravados. Conferido por fórmula independente nos testes unitários.

Verificações mecânicas (todas PASSOU): cálculo reproduzível · premissas registradas como PROPOSTA no `RepositorioPremissas` real · **nenhuma premissa aprovada automaticamente** (`ler_aprovada` bloqueia; declarar `APROVADA` é recusado) ·
9 pacotes válidos · cadeia de transferências íntegra e na ordem pedida (C→P1→P2→P3→P4→P5→P6→P7→Revisor→C) · proposta final não aprovada, com o portão humano apontado (coordenador humano: escopo/preço/CAPEX; publicação exigiria aprovação separada).

## 3. Resultados por frente

| Frente | Agente oficial (S08) | Skills autorizadas testadas | Pacote recebido/emitido (mecânica) | Execução real do agente | Conversa no Chat |
|---|---|---|---|---|---|
| C | c-orquestrador | 4 | PASSOU (emite 01; recebe 09) | NÃO EXECUTADO | NÃO EXECUTADO |
| P1 | p1-diagnostico | 3 | PASSOU (02) | NÃO EXECUTADO | NÃO EXECUTADO |
| P2 | p2-engenharia | 7 | PASSOU (03) | NÃO EXECUTADO | NÃO EXECUTADO |
| P3 | p3-mercado | 6 | PASSOU (04) | NÃO EXECUTADO | NÃO EXECUTADO |
| P4 | p4-modelagem | 9 | PASSOU (05; cálculo reproduzível) | NÃO EXECUTADO | NÃO EXECUTADO |
| P5 | p5-juridico | 6 | PASSOU (06) | NÃO EXECUTADO | NÃO EXECUTADO |
| P6 | p6-participacao | 4 | PASSOU (07) | NÃO EXECUTADO | NÃO EXECUTADO |
| P7 | p7-licitacao | 4 | PASSOU (08) | NÃO EXECUTADO | NÃO EXECUTADO |
| Revisor | revisor-independente (sem ferramenta Write) | 3 | PASSOU (emite 09; confere mecanicamente) | NÃO EXECUTADO | NÃO EXECUTADO |
| Controlador DR | controlador-dr | 3 | fora do cenário | NÃO EXECUTADO | n/a |

"Pacote … PASSOU" significa que o pacote **valida** e está na cadeia. **Não** significa que um agente o produziu ou que uma conversa o recebeu.

## 4. Os dez critérios de julgamento (separados)

1. **Funcionamento técnico do Claude Code** — demonstrado em laboratório (S01–S09); sem chamada real.
2. **Funcionamento das conversas no Claude Chat** — NÃO VERIFICADO.
3. **Contexto comum** — existe no repositório (matriz, políticas, `RepositorioPremissas`); no Chat NÃO VERIFICADO; pacote de contexto preparado.
4. **Rastreabilidade das transferências** — cadeia com hash no repositório (PASSOU); transferência Chat↔repositório depende de humano e não é rastreada automaticamente.
5. **Consistência entre frentes** — apenas por construção (mesmas premissas referenciadas nos 9 pacotes); não verificada em conversas.
6. **Integridade das premissas** — PROPOSTA; aprovação só com assinatura humana; o Chat não é fonte oficial.
7. **Proteção de dados** — pacote recusa natureza ≠ SINTETICO, sigilo ≠ PUBLICO-TESTE e material proibido (documento de referência real, CPF/CNPJ, e-mail, áreas sigilosas, chave); a matriz enviada ao Chat omite a área restrita do DR. O envio efetivo ao Chat é decisão institucional.
8. **Autonomia supervisionada** — nenhuma aprovação automática; em modo headless a gravação exige aprovação humana (R-11).
9. **Intervenção humana necessária** — todo o roteiro CH-01…CH-10, a provisão da credencial, as aprovações e a transferência manual.
10. **Reprodutibilidade** — S10 PASSOU para a infraestrutura (mesmo host); cenário integrado determinístico (mesmos hashes).

## 5. Contexto compartilhado e divergências

Ver `03-matriz-divergencias-code-chat.md`. Pontos que exigem esclarecimento humano: o **Memorial de Arquitetura Aprovada** não está no repositório (a comparação do item 5 não pôde ser feita);
as **três skills preexistentes** não estão nomeadas; `registros/` tem **seis** diretórios, não cinco. Coerência textual entre conversas, quando existir, **não** equivale a sincronização técnica.

## 6. Decisões pendentes (Trilha B)

1. Fornecer o Memorial e identificar as três skills preexistentes e os cinco registros centrais. 2. Autorizar a transferência do pacote de contexto sintético ao projeto existente no Chat (sem recriá-lo, sem apagar conversas).
3. Executar CH-01…CH-10 com um humano e devolver as evidências. 4. Decidir o canal e a política para qualquer dado real no Chat (hoje bloqueado). 5. Decidir se o piloto de agentes reais (modelo real) acontece após S04.
