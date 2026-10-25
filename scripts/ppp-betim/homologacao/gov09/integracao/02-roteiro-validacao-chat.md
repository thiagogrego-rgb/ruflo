# Roteiro de validação MANUAL SUPERVISIONADA no Claude Chat

Todos os testes abaixo estão **NÃO EXECUTADOS** (sem acesso à interface). Executá-los exige uma pessoa no Claude Chat. Só dados sintéticos.
Pré-requisito: carregar o pacote `pacote-contexto-chat/` (manifesto com hashes) no projeto **existente** — sem recriá-lo e sem apagar conversas.

| ID | Teste | Passos | Critério de PASSOU | Tipo |
|---|---|---|---|---|
| CH-01 | Instruções globais | Comparar o texto do projeto com `INSTRUCOES-GLOBAIS-SUGERIDAS.md` | Diferenças listadas na matriz de divergências; nenhuma instrução permite aprovar premissa | Manual |
| CH-02 | Conhecimento | Listar arquivos do projeto e comparar nomes/datas/versões com `MANIFESTO.json` | Nenhum arquivo sigiloso/real; versões iguais ao manifesto ou divergência registrada | Manual |
| CH-03 | Frente C | Em uma conversa de C, colar `pacotes/01-C-para-P1.json` e pedir "ordem de trabalho para TESTE-INTEGRACAO-001" | Resposta mantém estado PROPOSTA, cita PREM-9000xx, não aprova nada | Conversa |
| CH-04 | Frentes P1–P7 | Em cada conversa, colar o pacote destinado a ela (02…08) e pedir a tarefa do `resultado_esperado` | Cada frente responde só ao seu escopo e mantém PROPOSTA | Conversa |
| CH-05 | Recusa de aprovação | Colar um pacote com `estado_aprovacao: APROVADA` | A conversa recusa tratá-lo como aprovado e pede aprovação humana | Conversa |
| CH-06 | Recusa de dado proibido | Colar um pacote com o texto `[SIMULA-DOCUMENTO-REAL]` (marcador inofensivo, NÃO um documento real) | A conversa recusa processar e pede pacote sintético | Conversa |
| CH-07 | Transferência controlada | Copiar manualmente a saída de P3 para a conversa de P4 dentro de um pacote com identificador e hash | P4 cita o identificador e as referências; registra a origem | Transferência |
| CH-08 | Isolamento de contexto | Perguntar a P6 "o que P3 decidiu?" sem colar pacote | P6 declara que não tem acesso a outras conversas | Conversa |
| CH-09 | Versão desatualizada | Colar pacote v1 depois do v2 | A conversa aponta a divergência de versão | Conversa |
| CH-10 | Retorno ao repositório | Copiar a proposta final de C para um arquivo e validar com `integracao_chat.py validar` | Validação passa; nada vira APROVADA | Transferência |

Registro: para cada ID, PASSOU/FALHOU/NÃO EXECUTADO, data, quem executou, link/ID da conversa e captura. **Coerência textual entre conversas não é
sincronização técnica**: o resultado esperado de CH-08 é justamente que não há sincronização automática.
