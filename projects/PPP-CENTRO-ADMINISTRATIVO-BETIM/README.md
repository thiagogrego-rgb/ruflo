# PPP-CENTRO-ADMINISTRATIVO-BETIM

Pacote inicial para Claude Code + Claude Projects.

> **Estado do pacote:** bootstrap estrutural, não homologado para operação
> com dados reais. Os nove testes verificam comportamentos iniciais, mas não
> demonstram segurança integral, integração ao Claude Projects, funcionamento
> dos agentes ou conformidade completa dos registros de governança.

Comece pelo `00-LEIA-ME-PRIMEIRO.md`.

O documento original `PPP Centro Administrativo de Betim —
Funções e agentes de análise.md` precisa ser colocado em `referencias/`.

## Como executar

Requisito: Python 3.11 ou superior.

Versão de referência: `scripts/ppp-betim/gerar_projeto.py` no repositório.
Não utilize versões copiadas de conversas anteriores.

Abra o terminal na pasta onde deseja guardar o projeto e rode:

```
python3 caminho/para/gerar_projeto.py        # Linux/macOS
py caminho\para\gerar_projeto.py           # Windows
```

Se a pasta `PPP-CENTRO-ADMINISTRATIVO-BETIM/` já existir, o script é interrompido sem
sobrescrever nada. Renomeie ou remova a pasta antes de rodar de novo.

Se a execução terminar com sucesso, estes dois itens aparecem no mesmo diretório:

- `PPP-CENTRO-ADMINISTRATIVO-BETIM/`: diretório de trabalho.
- `PPP-CENTRO-ADMINISTRATIVO-BETIM.zip`: pacote compactado, gerado somente se todos os testes passarem.

O instalador é intencionalmente conservador: não cria aprovações fictícias,
não habilita publicação e não acessa a rede, o Google Drive nem
informações restritas.

## O que ele efetivamente entrega

| Componente | Situação após execução bem-sucedida |
|---|---|
| Estrutura de diretórios | Criada |
| Dez arquivos de agentes | Criados, não homologados |
| Dezenove arquivos SKILL.md | Criados, não homologados |
| Instruções do Claude Projects | Criadas como texto; sem integração automática |
| Políticas fundamentais | Criadas como texto; sem bloqueio técnico |
| Validador inicial de premissas | Criado; cobre campos obrigatórios, natureza e status, mas não o tipo de `versao` |
| Testes (3 estruturais + 6 de governança) | Executados e aprovados; condição para gerar o ZIP |
| Homologação funcional | Pendente |

## Melhorias registradas para a próxima versão

- Validar `versao` como inteiro positivo.
- Utilizar efetivamente `governanca/schemas/premissa.schema.json` no
  validador, em vez de manter dois mecanismos de validação potencialmente
  divergentes.
