# Premissas
Campos obrigatórios: ID, versão, produto, natureza, unidade,
data-base quando aplicável, fonte ou hipótese, status e dependências.

Estados: PROPOSTA, EM_VERIFICACAO, VERIFICADA, APROVADA,
REJEITADA, SUBSTITUIDA.

Uma hipótese aprovada para cenário continua sendo hipótese.
Aprovação exige mecanismo humano independente da IA.

Implementação atual (GOV-01/GOV-02): o único status registrável é PROPOSTA;
APROVADA decorre de aprovação humana assinada e verificada. Os demais estados
ainda não possuem evento próprio. Ver `GOV-01-02-fronteira-de-confianca.md`.
