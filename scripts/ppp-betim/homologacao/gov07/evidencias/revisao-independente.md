# Revisão independente (GOV-07) — registro

Dois revisores novos, somente leitura, sem executar nada (nenhum teste dinâmico). Dados sintéticos. Não homologam.

## Guarda (`guarda_*.py`, `settings.json`, `matriz-agentes.json`)
- 1 expansão de variável/shell não modelada (alta, certo) · 2 substituição de comando só vale para escrita (alta, certo)
- 3 here-doc/redirecionamentos (média) · 4 interpretadores embutidos, `-c` combinado, versões (alta)
- 5 allowlist de leitura com comandos que escrevem (média) · 6 `cd`, symlink, hardlink (média)
- 8 glob dinâmico/extglob (média) · 9 log não gravável não bloqueia (média, certo); timeout 30 s no hook / 10 s no guarda: margem correta
- 11 matcher não cobre Task/Agent, WebFetch, WebSearch, SendMessage, Enter/ExitWorktree (alta, certo); `deny` só de `Edit`
- 12 `agent_type` não autenticado (média após ler a matriz) · 13 TOCTOU (média) · 14 script confiável isenta argumentos (média)
- Conclusão: o guarda é trilha e aviso, não barreira. Não executado: validade da semântica do matcher no harness.

## Isolamento (`isolamento.py`, `jaula.py`, `iniciar_sessao.py`, `papeis.json`) — 21 achados
Altos: 1 settings do sandbox no HOME do papel; 2 e 3 `aplicar` segue links; 4 segredos em argv; 5 fail-open sem papel;
10 `ro-bind /` expõe segredos do host. Médios: 6, 7, 8, 9, 11, 14–20. Baixos: 12, 13, 21.
Corrigidos em GOV-07: 1, 5, 7, 9, 12, 14. Abertos: 2, 3, 4, 6, 8, 10, 11, 13 (parcial), 15–21.
Não executado pelo revisor: `verificar_configuracao.py`, `settings.json`, `sandbox-recomendado.json`; qualquer teste dinâmico.
