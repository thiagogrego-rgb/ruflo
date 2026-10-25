# Relatório final GOV-09 — Piloto controlado de infraestrutura e API (Trilha A)

**A verdade desconfortável primeiro:** a chamada real à API **não foi feita** (S04 = NÃO EXECUTADO) e **não existe infraestrutura de homologação**.
Tudo que passou passou em **laboratório**, com **modelo simulado** e **credencial canário sintética**. O piloto prova que o encanamento e os bloqueios
funcionam neste contêiner; não prova que funcionarão na rede, no proxy e com a credencial da instituição. **Dados reais continuam bloqueados.**

Confiança: [Certo] para o que está medido abaixo (há evidência em arquivo); [Provável] para o que se espera na homologação; [Chutando] onde indicado.

## 1. Commit testado e como a evidência se prende a ele

| Item | Valor |
|---|---|
| Commit de código testado | `61d8435400cb3215bc6f98a4b71727fd5a97614b` |
| Geração do projeto a partir desse commit | VERIFICAÇÃO DO ZIP: OK; TESTES INICIAIS: PASSARAM (10 agentes, 19 skills) |
| Suíte completa (`unittest discover`, árvore gerada) | **430 testes, OK, 1 pulado** (`suite-final.txt`) |
| Código instalado nas rodadas | SHA-256 `3f433fb4603bb78a…` nas duas rodadas; cada arquivo do pacote instalado é byte a byte igual ao do commit (conferido com `git show`/`cmp`) |
| Evidências | `rodada-r1.json/.md`, `rodada-r2.json/.md`, `S10-reprodutibilidade.json`, `registro-credencial.jsonl`, `inventario-contas-permissoes.md` |

Este relatório e os arquivos de evidência foram commitados **depois** do commit testado; eles não alteram código.

## 2. Resultados S01–S10 (duas rodadas, instalação limpa entre elas)

Classificação: PASSOU / FALHOU / NÃO EXECUTADO. "Tipo" separa laboratório de integração real.

| ID | Tipo de teste | r1 | r2 | Evidência-chave |
|---|---|---|---|---|
| S01 | Infraestrutura | PASSOU | PASSOU | `claude` real sob uid do papel p3; capEff/capBnd = 0, `no_new_privs`, netns próprio, chave do operador ausente do ambiente. Só o papel p3 foi sondado; binário e versão no campo volátil |
| S02 | Infraestrutura | PASSOU | PASSOU | Auditoria + sondagem de ~800+ operações de permissão; 13 contas conferidas com `id/getent`, sem shell de login |
| S03 | Infraestrutura | PASSOU | PASSOU | 7 recusas do lançador, cada uma com a **mensagem esperada**; controle positivo (`--dry-run`) OK |
| **S04** | **Integração real** | **NÃO EXECUTADO** | **NÃO EXECUTADO** | Sem credencial provisionada por humano; modo laboratório não conta como chamada real |
| S05 | Infraestrutura | PASSOU | PASSOU | Credencial ausente de argv/ambiente/arquivos varridos; nenhum dos 10 papéis lê o arquivo; **controle positivo**: a varredura acha um canário plantado em argv |
| S05b | Infraestrutura | PASSOU | PASSOU | Chave rotacionada ausente de argv/ambiente/arquivos ao fim |
| S06 | Infraestrutura | PASSOU | PASSOU | Só `lo`; sem rota ao IP do provedor nem ao DNS; `/v1/messages` 200; `/v1/models`, GET e `/v1/files` 403; **o destino recebeu apenas `/v1/messages`** (requisições proibidas não chegaram) |
| S07 / S07b | Infraestrutura | PASSOU | PASSOU | 11 cadeias íntegras, `chattr +a`, dono `ppp-guardiao` 0640, âncora publicada e conferida — antes e depois das falhas |
| S08 | Agentes nomeados + skills (modelo **simulado**) | PASSOU | PASSOU | 10 agentes, 19 skills; decisões lidas do **log do guardião**; recusa de skill não autorizada e externa; recusa em área alheia; revisor sem a ferramenta `Write` |
| S09 | Falha e recuperação | PASSOU | PASSOU | F1–F6 (ver §5) |
| S10 | Reprodutibilidade | PASSOU | — | 10 cenários PASSOU idênticos nas duas rodadas, S04 NÃO EXECUTADO nas duas, mesmo código instalado |

**Leitura honesta do S10:** ele compara a evidência **determinística** (booleanos e contagens estáveis); ignora o campo `volatil` (pids, durações, códigos da rajada).
Duas rodadas no **mesmo host** mostram estabilidade, não independência de ambiente.

Histórico que não aparece no resultado final (declarado de propósito): antes da rodada final houve rodadas com FALHOU por defeito do **teste** (F5, critérios de S01/S06/S08, F1/F2) e por
defeito **real** do gateway/supervisor (§6). O `registro-credencial.jsonl` mostra instalações/revogações de várias tentativas; só as rodadas finais estão preservadas como JSON.

## 3. Segurança do gateway, credenciais, logs e isolamento

- **Gateway:** unix socket → HTTPS único; POST exato em `/v1/messages` e `/v1/messages/count_tokens`; credencial do cliente descartada, chave injetada; CA/proxy CONNECT testados com servidores TLS locais
  (CA correta 200; CA errada 502 sem entrega); limitador antes da auditoria; teto de 64 conexões abertas; backlog 128; corpo drenado nas recusas.
- **Credencial:** entra por stdin/terminal oculto; arquivo 0600 da conta do gateway; registro só com tamanho e impressão de 8 hex; **revogação derruba o gateway em execução** (F4, sem intervenção manual) e a rotação religa com a nova.
- **Logs:** escritos só pelo serviço de log; hash encadeado; `chattr +a` (o próprio root consegue anexar mas não truncar); âncoras externas detectam truncagem/reescrita do que já foi ancorado.
- **Isolamento:** conta de SO por papel + jaula bwrap + netns vazio; guardião por agente (defesa em profundidade).

## 4. Chamada real à API

**NÃO EXECUTADA.** Motivo: nenhuma credencial foi provisionada por responsável humano por canal seguro (e nenhuma foi pedida no chat; a do sandbox não foi reutilizada).
Pré-condições para executar: `piloto.py credencial instalar` (humano) → serviços em unidades de sistema → `piloto.py executar --modo api-real`.
O modo `api-real` **recusa** `permitir_teste`/upstream divergente, e a exceção HTTP só vale com credencial marcada SINTETICO.

## 5. Falha e recuperação (S09)

F1 serviço de log cai → sessões recusadas (supervisor congelado para a janela ser determinística), socket remanescente detectado como morto, supervisor reinicia, cadeias íntegras ·
F2 gateway cai → sessão falha sem vazar nada, reinício OK · F3 destino indisponível → erro propagado sem travar · F4 revogação/rotação · F5 adulteração (em **cópia** dos logs: edição, remoção, truncagem detectadas; no original nenhum dos 10 papéis escreve; root não trunca) ·
F6 rajada de 12 conexões: 4×200 e 8×429, sem erro de conexão, com o motivo registrado no log.

## 6. Achados do piloto e das revisões independentes

Duas revisões de contexto limpo, somente leitura (segurança do código; validade das evidências). Resumo e disposição:

| # | Achado | Gravidade | Disposição |
|---|---|---|---|
| 1 | `credencial revogar` não derrubava o gateway em execução; F4 mascarava | Alto | **Corrigido** (supervisor compara inode/mtime; F4 sem `kill` manual) |
| 2 | Config de laboratório (`permitir_teste`, http local) podia sobreviver até o modo real | Alto | **Corrigido** (removida ao fim; `api-real` recusa; exceção só com credencial SINTETICO) |
| 3 | DoS: auditoria de recusas antes do limitador; sem teto de threads | Médio | **Parcialmente corrigido** (limitador antes da auditoria, teto 64). Gotejamento de cabeçalho ainda ocupa slot (R-05) |
| 4 | `shell=True` como root em `criar_contas` | Médio | **Corrigido** (argv, regex e validador) |
| 5 | `instalar` seguia links, apagava logs, trocava código com serviços no ar | Médio | **Corrigido** (recusa links; arquiva logs/âncoras; exige supervisor parado; valida dados da árvore copiada) |
| 6 | Âncoras: não protegem contra root no mesmo host nem a cauda pós-âncora | Médio (limite de desenho) | **Declarado** (R-02/R-03); âncora periódica no supervisor; destino externo é decisão humana |
| 7 | TLS/proxy: CA substitui (texto dizia "acrescenta"); arquivo de CA sem verificação; proxy `http` em claro | Médio-baixo | **Corrigido** CA; proxy http e prefixos de cabeçalho **declarados** (R-04/R-07) |
| 8 | Supervisor herdava ambiente do root; config inválida derrubava | Baixo | **Corrigido** |
| 9 | Evidências: "recusado" = qualquer `is_error` (S08/S03/S05...) | Alto (validade) | **Corrigido**: S08 usa o log do guardião e `tool_use_id`; S03 exige a mensagem; S05 tem controle positivo; S10 exige rótulo/início distintos, mesmo modo e mesmo código |
| 10 | S01 só p3; F5 em cópia; F6 tolerante | Médio | **Declarado** (limites abaixo) |

Defeitos reais encontrados **pelo piloto** (não pelos revisores): recusa com corpo não lido causava reset no cliente; backlog 5 causava `EAGAIN` em rajada; `+a` permite anexar (teste F5 errado).
Estes três têm teste de regressão.

## 7. Matriz de riscos residuais

| ID | Risco | Sev. | Mitigação / dono |
|---|---|---|---|
| R-01 | Nenhuma chamada real feita; TLS real, streaming/SSE real, 429 do provedor não exercitados | Alto | Humano provisiona credencial; rodar S04 |
| R-02 | Âncoras no mesmo host: root refaz cadeias e âncoras sem deixar rastro | Alto | Destino externo/WORM assinado (decisão humana) |
| R-03 | Registros posteriores à última âncora não são cobertos | Médio | Âncora periódica (já) + exigir idade máxima na verificação |
| R-04 | Proxy `http` leva `Proxy-Authorization` em claro; CA corporativa dá acesso à credencial e ao conteúdo | Médio | Proxy `https`/mTLS; aceite formal do risco |
| R-05 | Gotejamento de cabeçalhos mantém slot por até 30 s/leitura | Médio | Prazo total de cabeçalho (não implementado) |
| R-06 | O gateway não limita volume/custo de uso da chave | Médio | Teto de gasto no provedor |
| R-07 | Cabeçalhos repassados por prefixo (`accept*`, `anthropic-*`, `x-app`) | Baixo | Lista exata após observar o tráfego real |
| R-08 | Sem systemd, cgroups, firewall por uid, backup | Alto | Implantação de homologação (humano) |
| R-09 | `chattr +a` validado só neste sistema de arquivos | Médio | Repetir na homologação |
| R-10 | Varredura de credencial é pontual (bytes literais; sem memória/swap) | Baixo | Revisão dinâmica |
| R-11 | Em modo headless, gravar exige aprovação humana: agentes não gravam sozinhos | Operacional | Definir o fluxo de aprovação |
| R-12 | S08 usa modelo simulado: não prova julgamento dos agentes | Médio | Teste com modelo real após S04 |
| R-13 | S01 sondou só p3; F5 adulterou cópia; 2 rodadas no mesmo host | Médio | Ampliar na homologação |
| R-14 | Registro de credencial não é encadeado; operador vem de `SUDO_USER` | Baixo | Usar loginuid e ancorar o registro |

## 8. Decisões humanas pendentes (Trilha A)

1. Provisionar a credencial por canal seguro e **autorizar** S04. 2. Escolher destino externo das âncoras. 3. Autorizar infraestrutura de homologação (serviços, firewall por uid).
4. Decidir proxy/CA corporativa e aceitar R-04. 5. Definir teto de gasto (R-06). 6. Definir fluxo de aprovação de gravações headless (R-11). 7. Revisão independente **dinâmica** na homologação.
8. Aceitar (ou não) os componentes listados em §9. 9. **Manter bloqueio de dados reais.**

## 9. Critérios de aceite e recomendação

**Recomendação: ACEITE TÉCNICO CONDICIONADO, restrito ao laboratório; REJEITAR qualquer uso com dados reais e qualquer declaração de homologação.**

Componentes que um humano pode aceitar (verificados em laboratório, sintético): lançador por papel, isolamento de rede e de arquivos, gateway (política de caminhos, injeção/descarte de credencial, limites), serviço de log encadeado e âncoras
(com os limites R-02/R-03), supervisor com revogação efetiva, ferramental de instalação/credencial/varredura.

Condições para qualquer avanço: S04 PASSOU com credencial legítima · homologação com unidades de sistema e firewall por uid · âncora externa · nova rodada S01–S10 na homologação com **dois** operadores · revisão independente dinâmica.

Mapa dos entregáveis pedidos no GOV-09 original: (1) plano de implantação → `governanca/GOV-09-piloto-controlado.md` §2 · (2) inventário de contas/permissões → `inventario-contas-permissoes.md` ·
(3) registro de credenciais → `registro-credencial.jsonl` e §3 do GOV-09 · (4) resultado da API → §4 (NÃO EXECUTADO) · (5) segurança do gateway → §3 e §6 · (6) agentes e skills → S08 · (7) falha e recuperação → §5 ·
(8) riscos residuais → §7 · (9) revisão independente → §6 e `parecer-independente.md` · (10) recomendação → §9.
