# Revisão independente do guarda de GOV-05 (resumo fiel dos relatórios recebidos)

Origem: dois subagentes novos (modelo `opus`), sem acesso ao raciocínio do autor; receberam só o código e a configuração
em modo somente leitura. Os relatórios são saída de modelo e não têm autoridade de aprovação.

## Revisor A — caminhos, escopo, skills, log, robustez (CONCLUÍDO)
Testou o hook em cópia do projeto, alimentando JSON no stdin (mede só a decisão do hook, não o runtime).

Contornos confirmados com PoC:
- **C1 (média)** `agent_type` vazio/0/false caía na sessão principal (sem restrição de área, skill, Bash, MCP). Correção:
  exigir `str` não vazia; recusar `agent_id` sem `agent_type`. → corrigido (V5).
- **C2 (média)** `touch /*/*/*/*/*/*` levou 88 s (glob sem limite); estourar o timeout do hook libera a ferramenta. Correção:
  limitar resultados e tempo, definir `timeout`. → corrigido (V6) e o fail-aberto do timeout foi medido (V4).
- **C3 (média)** `tar -xf` e `unzip -o` podem sobrescrever áreas protegidas (só tokens visíveis são checados). → corrigido (V7).
- **C4 (baixa)** Bash grava fora do projeto enquanto Write recusa. → NÃO corrigido; coberto pelo sandbox (V14).

Plausíveis não confirmadas: TOCTOU de symlink por processo concorrente; caminho relativo resolvido contra o `cwd` do evento
(medido depois: o `tool_input` chega com caminho absoluto); `ask` sob `bypassPermissions` (medido: headless não aprovou).
Sem impacto de segurança: mensagens de erro de tipos inesperados; `skill` lido antes de `name` (corrigido, V12).
Sólido: symlinks de diretório/pendentes, `..`, NUL, fora do projeto, caixa, prefixo de skill, matriz ilegível, log sem injeção,
wrapper `|| exit 2`, `permissions.deny` como segunda camada.

## Revisor B — análise de comandos de terminal (INTERROMPIDO — NÃO EXECUTADO)
O subagente leu o hook e a configuração e foi interrompido por um classificador de segurança ao montar os casos de teste;
não entregou contornos, PoCs nem falsos positivos. O pedido não foi refeito com outras palavras. A única observação
entregue: um filtro sobre o texto do comando, tokenizado com `shlex`, não reproduz a interpretação do bash e não deve ser
tratado como fronteira de segurança; para garantia real a proteção precisa estar no SO (montagem somente leitura, usuário
sem permissão de escrita, sandbox do Claude Code ou arquivos imutáveis). Isso coincide com o medido em GOV-06.

## Limite da independência
Revisores são modelos; um deles não concluiu. Os achados V1–V4, V8–V13 vieram da bateria de runtime do próprio autor
(não independente). Recomenda-se revisão humana independente antes de dados reais (GOV-06, seção 9).
