# Revisão independente (GOV-08) — registro

Dois revisores novos, somente leitura, sem executar código (nenhum teste dinâmico). Dados sintéticos. Não homologam.

## Rodada 1
- Serviços (log, gateway, ponte, guarda): 18 achados. Altos: quebra de linha Unicode derruba a cadeia no reinício; tamanho de bloco negativo e
  `Content-Length` ambíguo contornam o limite de corpo; payload autodeclarado e sem cota. Médios: slowloris/memória, slots globais, `%`/`;` no caminho,
  escrita parcial, truncamento sem marca, guarda aberto por padrão, exceção que sai sem código 2, servidor de log não autenticado, ponte sem checar namespace,
  ambiente por lista negra. Baixos: upstream http, core dump, janela entre bind e chmod, chattr +a não verificado.
- Isolamento e lançador: 18 achados. Altos: dono da saída do DR expõe a pasta; sem `--new-session` (TIOCSTI). Médios: settings do papel, MCP/agents no HOME,
  lista negra de opções, DoS da auditoria, sonda destrutiva e "negado" para qualquer erro, erros engolidos, operações por caminho, userns aninhado, visibilidade do host.

## Rodada 2 (releitura das correções)
- Serviços: 13 CORRIGIDOS, 5 PARCIAIS (conteúdo autodeclarado; prazo total; slots; uid 65534 na jaula; "fim" de melhor esforço). Novos: linha parcial (N1), cota
  compartilhada de `rede.jsonl` (N2), timeout após o corpo (N3), uid 65534 (N4), ancestrais do socket (N5).
- Isolamento: 5 CORRIGIDOS, 2 ACEITO-DOCUMENTADO, 11 PARCIAIS. Novos: terminal sem o sysctl falhava aberto; `os.access` em filesystem somente leitura; ancestrais do
  socket; bind de escrita antes do ocultar; flags de teste.
- Tratados depois da rodada 2 (sem nova revisão): N2, N3, N5, terminal sem sysctl, sondas em fs somente leitura, auditoria robusta, `aplicar` confirmando pela
  auditoria, ancestrais de `home_base`/dono de papel, cruzamento papéis×agentes×matriz, `closerange`. N1 virou procedimento (R29); N4 virou R30.
Não executado pelos revisores: qualquer teste dinâmico; `jaula.py` e `isolamento_so._tem_so_anexar` na rodada 2 do primeiro revisor.
