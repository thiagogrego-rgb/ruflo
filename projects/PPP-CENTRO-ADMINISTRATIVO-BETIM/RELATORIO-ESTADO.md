# Estado do pacote

- Agentes: arquivos gerados, não homologados no Claude.
- Skills: instruções metodológicas geradas, sem scripts específicos.
- GOV-01: premissas validadas por JSON Schema, versionadas em armazenamento
  append-only com cadeia de hashes; testado com dados sintéticos.
- GOV-02: aprovação de premissas por assinatura Ed25519 de aprovador humano
  registrado; registro distribuído vazio (nenhuma aprovação é aceita).
- Decisões gerais e publicação: bloqueadas.
- Proteção efetiva: depende dos controles externos descritos em
  `governanca/GOV-01-02-fronteira-de-confianca.md` (não configurados).
- Testes: estruturais, governança inicial, GOV-01 e GOV-02.
- Fonte original DR e demais insumos: pendentes de importação.
- Integração ao Projects: pendente.

Não utilizar dados reais até avaliação da segurança.
