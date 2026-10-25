# Plano de transferência/sincronização controlada Code ↔ Chat

Princípio: **o repositório é a fonte de verdade**. O Chat é espaço de trabalho. Não existe sincronização automática; qualquer afirmação em contrário é falsa até ser provada.

## Repositório → Chat (manual, supervisionado)
1. `python3 scripts/integracao_chat.py contexto --saida <pasta>` gera o pacote sintético (instruções, matriz de agentes sem áreas restritas, regras, template, fixture) + `MANIFESTO.json` com SHA-256.
2. Humano confere o manifesto (`verificar_contexto`), carrega os arquivos no **projeto existente** (substituição de arquivo, sem apagar conversas) e anota versão/data no controle.
3. Cada tarefa para uma frente vai em um **pacote** com identificador, origem, destinatário, versão, data, natureza dos dados, sigilo, referências de premissas, estado e resultado esperado.
   `integracao_chat.py validar` recusa: natureza ≠ SINTETICO, sigilo ≠ PUBLICO-TESTE, estado ≠ PROPOSTA, material proibido, hash que não confere.

## Chat → repositório
4. A saída da conversa é copiada por humano para um arquivo-pacote, validada e só então registrada. **Nada do Chat vira premissa aprovada**: premissas entram como PROPOSTA no `RepositorioPremissas`; APROVADA só por aprovação humana assinada.

## Detecção de deriva (sem fingir automação)
- Manifesto lista arquivo→hash. O Chat não calcula hash de forma confiável: a conferência no Chat é por **nome, versão e data** informados no controle; a conferência por hash é feita no repositório.
- A cada rodada de trabalho: registrar no controle "pacote de contexto vX carregado em AAAA-MM-DD". Divergência de versão → CH-09.

## Quando houver dado real (hoje bloqueado)
Antes, são necessários: decisão humana expressa, classificação de sigilo, canal aprovado para o Chat (política institucional), e revisão independente dinâmica.
