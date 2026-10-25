# Regras de transferência entre frentes

- Transferência é MANUAL e supervisionada: copiar o pacote JSON da frente de origem para a conversa da frente de destino.
- O pacote só vale se validar (scripts/integracao_chat.py validar). Pacote com estado diferente de PROPOSTA, natureza diferente de SINTETICO
  ou com material proibido (documento de referência real, CPF/CNPJ, e-mail, áreas sigilosas, chaves) é recusado.
- O retorno do Chat ao repositório passa por registro humano; nada do Chat vira premissa APROVADA por si.
