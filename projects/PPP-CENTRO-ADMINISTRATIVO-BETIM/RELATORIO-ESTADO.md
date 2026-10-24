# Estado do pacote

- Agentes: arquivos gerados, não homologados no Claude.
- Skills: instruções metodológicas geradas, sem scripts específicos.
- GOV-01: premissas validadas por JSON Schema, versionadas em armazenamento
  append-only com cadeia de hashes; testado com dados sintéticos.
- GOV-02: aprovação de premissas por assinatura Ed25519 de aprovador humano
  registrado; registro distribuído vazio (nenhuma aprovação é aceita).
- GOV-03: serviço guardião (único escritor do armazenamento, identidade do
  proponente via kernel), papel `ancoradores` restrito a checkpoint e âncora de
  checkpoints assinados; validado só contra processos sintéticos sem privilégio.
- GOV-04: série crescente do cadastro de aprovadores contra referência externa
  assinada, lock de dependências com hashes e verificação do ambiente, limites de
  requisição/frequência/crescimento, verificador independente de checkpoints e
  recuperação após interrupção; validado só contra processos sintéticos sem privilégio.
- Decisões gerais e publicação: bloqueadas.
- Proteção efetiva: NÃO declarada. Depende de implantação supervisionada em
  infraestrutura onde o agente não tenha privilégio administrativo
  (`governanca/GOV-03-fronteira-efetiva.md`, seção 10, e
  `governanca/GOV-04-robustez-nucleo.md`, seção 11) — não realizada.
- Testes: estruturais, governança inicial, GOV-01/02 e fronteira GOV-03
  (estes últimos são PULADOS sem Linux e root, e nesse caso a fronteira
  permanece não validada).
- Fonte original DR e demais insumos: pendentes de importação.
- Integração ao Projects: pendente.

Não utilizar dados reais até avaliação da segurança.
