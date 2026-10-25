# Matriz de divergências Code × Chat

Coluna "Code" = o que foi VERIFICADO no repositório nesta sessão. Coluna "Chat" = **NÃO VERIFICADO** em todas as linhas (sem acesso). Logo, nenhuma
divergência Code × Chat pôde ser medida; abaixo ficam as divergências já visíveis entre o **enunciado** e o **repositório**.

| Item | Code (verificado) | Chat | Divergência | Ação |
|---|---|---|---|---|
| Agentes oficiais | 10 em `.claude/agents` (c-orquestrador, controlador-dr, revisor-independente, p1…p7); `c-orquestrador` preservado, sem Hermes | NÃO VERIFICADO | — | Conferir nomes/descrições no Chat |
| Skills novas | 19 em `.claude/skills` | NÃO VERIFICADO | — | Conferir |
| Skills preexistentes | O repositório diz "três skills preexistentes" (`00-LEIA-ME-PRIMEIRO.md`) **sem nomeá-las** | NÃO VERIFICADO | **Não identificadas** | Humano informa quais são; inspecionar sem sobrescrever |
| Frentes contratuais | 8 diretórios em `produtos/`: C, P1…P7 | NÃO VERIFICADO | — | Conferir conversas |
| Registros de governança | `registros/` tem **6** diretórios: auditoria, decisoes, entregaveis, fontes, premissas, verificacoes | NÃO VERIFICADO | **Enunciado fala em 5** | Humano esclarece qual dos seis não é "central" (ou se a contagem mudou) |
| Memorial de Arquitetura Aprovada | **Não encontrado** no repositório nem nesta sessão | NÃO VERIFICADO | **Sem referência para comparar** | Humano fornece o Memorial (versão e data) para a comparação do item 5 |
| Instruções globais do Chat | Sugestão em `INSTRUCOES-GLOBAIS-SUGERIDAS.md` | NÃO VERIFICADO | Indeterminada | CH-01 |
| Conhecimento do Chat | Manifesto com hashes do pacote sintético | NÃO VERIFICADO | Indeterminada | CH-02 |
| Premissas oficiais | Só no `RepositorioPremissas` (hash encadeado; APROVADA exige assinatura humana) | O Chat **não é fonte** de premissas | Por desenho | Manter |
| Sincronização automática | **Inexistente** | NÃO VERIFICADO | Por desenho | Transferência manual (plano 04) |
| Marcos A1–A4 / Lotes 01–05 | Não há registro deles no repositório lido | NÃO VERIFICADO | Sem referência | Humano fornece o Memorial |
