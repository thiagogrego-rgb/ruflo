# GOV-08 — Correção dos riscos críticos de segurança (isolamento, credencial, rede, auditoria)

**Status: NÃO LIBERADO PARA DOCUMENTOS REAIS. NÃO HOMOLOGADO.** Este documento não aprova, não publica e não decide nada.
Tudo foi medido com dados sintéticos, em ambiente de laboratório, por testes automatizados e por dois revisores
independentes (leitura estática). Nenhuma alteração foi aplicada a produção. Aprovação institucional é humana.

Legenda: **PASSOU**, **FALHOU**, **NÃO EXECUTADO**. Recusa voluntária do modelo **não** conta como bloqueio: os testes de runtime
usam o `claude` real contra um **modelo falso roteirizado** que nunca recusa; se uma ferramenta falha, quem barrou foi o hook, o
`deny`, o SO, a jaula ou a lista de ferramentas do agente.

## 1. Matriz de riscos atualizada
Estados: **CORRIGIDO** (controle efetivo, testado), **MITIGADO** (reduzido, resíduo descrito), **ABERTO**, **NÃO EXECUTADO**.

| # | Risco | Estado | Evidência / resíduo |
|---|---|---|---|
| C1 | `aplicar` (root) seguir link/hardlink/corrida plantado por agente | **CORRIGIDO** | operações por descritor `O_NOFOLLOW`+`fstat`; 5 testes de ataque (link para arquivo, para pasta, para `registros/`, hardlink, troca de pasta por link durante 5 s de execuções repetidas, link em `tmp` do home) PASSARAM; `home_base` precisa ser do root; raiz com ancestral gravável por papel é recusada |
| C2 | Credencial em argv, ambiente da sessão, logs ou arquivos | **CORRIGIDO** no modo `gateway` | a sessão nunca recebe a chave; chave só em arquivo 0600 do serviço ou descritor herdado; não há opção de argv nem variável de ambiente; testes de `/proc`, argv, logs, ambiente PASSARAM. Resíduo: quem usa a sessão pode **usar** a chave pelo gateway (não lê, mas gasta) |
| C3 | Rede sem restrição nem auditoria | **CORRIGIDO** no modo `gateway` | namespace de rede vazio + gateway que só encaminha `POST` a dois caminhos exatos de um único destino `https`; cada requisição auditada antes do envio; sem registro, nada sai (503) |
| C4 | Agente alterar/forjar/apagar o próprio registro de auditoria | **CORRIGIDO** contra agentes | nenhum papel escreve em `logs/`; só o serviço de log (conta própria) grava, com cadeia de hash e origem pelo kernel. Resíduo: **ver R20** (administrador, truncamento do fim) |
| C5 | Escrita do controlador DR onde os agentes leem | **CORRIGIDO** | DR escreve só em `produtos/DR/saida`; pasta-casca do administrador impede que o dono exponha a saída; agentes P1–P7 não atravessam `produtos/DR` (kernel, jaula, guarda e `deny`) |
| C6 | Conta compartilhada por P1–P7 | **CORRIGIDO** no SO | uma conta por agente; cada um grava só na própria pasta; sondagem de 10 papéis PASSOU. Resíduo: sessões **do mesmo papel** compartilham conta e HOME (R18) |
| C7 | `deny` de leitura como defesa adicional | **CORRIGIDO** (camada extra) | gerado por papel pelo lançador; bloqueia `Read`, `Grep` e `Glob` **sozinho**, com o hook desligado (controle sem a regra vaza). Efeito colateral aceito: R19 |
| C8 | Cobertura de `Task`, `WebFetch` e equivalentes | **CORRIGIDO** | matcher `.*`; ferramenta desconhecida é recusada; `deny` de `WebFetch/WebSearch/Task/Agent`; **medido**: os agentes não têm essas ferramentas (`No such tool available`); o verificador recusa agente com ferramenta fora de `Read/Grep/Glob/Write/Skill` |
| R1–R17 | Riscos herdados de GOV-06/07 | ver seção 8 | |
| R18 | Sessões do mesmo papel compartilham conta e HOME (persistência de injeção de prompt) | **ABERTO** | `--strict-mcp-config` e fonte `user`/`local` desligadas; o vetor de persistência por MCP **não foi demonstrado** neste ambiente (NÃO EXECUTADO) |
| R19 | `deny` age antes do hook: leitura negada por `deny` não aparece no log encadeado | **ABERTO (aceito)** | a negação existe e aparece em `permission_denials` da saída do claude; a trilha encadeada registra o que o hook decide |
| R20 | Log: dados do hook são autodeclarados; sem âncora externa o administrador reescreve; truncar o fim é indetectável | **ABERTO** | mitigação entregue: `logd.py --cabeca` (seq+hash) para publicar fora do serviço; **não** automatizada |
| R21 | Cota/gasto por papel no gateway | **ABERTO** | limites de conexão por papel e globais; sem teto de gasto |
| R22 | Login por assinatura (OAuth) não passa pelo gateway | **ABERTO (limitação)** | só chave de API |
| R23 | O conteúdo das requisições vai ao provedor do modelo | **ABERTO (inerente)** | decisão jurídica/contratual, fora do código |
| R24 | `ro-bind /` expõe arquivos do host (somente leitura) | **MITIGADO** | ocultos `/root /home /mnt /media /run /var/tmp /tmp` e os homes dos outros papéis; `/etc /opt /usr /var/lib` continuam legíveis. Lista branca de montagens: NÃO IMPLEMENTADO |
| R25 | Sem seccomp; sem `--new-session` (TIOCSTI) | **MITIGADO** | `--disable-userns`; o lançador **recusa** terminal de controle com `dev.tty.legacy_tiocsti=1`. Seccomp: NÃO IMPLEMENTADO |
| R26 | Montagem detectada só por `st_dev` | **ABERTO** | bind mount no mesmo filesystem não é visto |
| R27 | Auditoria é instantânea; `aplicar` exige sessões paradas | **ABERTO (operacional)** | reauditar periodicamente é manual |
| R28 | Modo legado do guarda (`PPP_LOG_LEGADO=1`) | **MITIGADO** | padrão é FECHADO: sem serviço de log confirmado a operação é recusada; o legado só é ligado pelo lançador sem papel (sintético) |

## 2. Correções implementadas
- **Isolamento sem seguir links** (`isolamento_so.py`): `aplicar` abre cada diretório/arquivo por descritor (`O_NOFOLLOW`,
  conferência de `dev/ino`), não toca em links (só `lchown` do próprio link), em arquivos com mais de um link físico, em
  montagens nem em arquivos especiais; entrada que some ou é trocada durante a execução vira aviso (nunca é seguida).
  Sentinela aberta com `O_NONBLOCK` (FIFO não trava). Profundidade máxima. Homes: `home_base` do root, um erro de um papel não
  impede os demais. `auditar` recusa link, hardlink, ACL/capability, arquivo especial, montagem, ancestral gravável, log
  inesperado e erro de leitura (nunca vira "conforme"). `sondar` não é mais destrutiva (acesso em vez de truncar/apagar) e
  separa **negação do kernel** (EACCES/EPERM) de **falha inconclusiva**.
- **Credencial e rede** (`gateway.py`, `entrada_jaula.py`, `jaula.py`, `iniciar_sessao.py`): jaula com namespace de rede
  vazio (`--unshare-net`), sem namespaces de usuário aninhados (`--disable-userns`), `/root /home /mnt /media /run /var/tmp /tmp`
  e homes de outros papéis ocultos. Ponte `127.0.0.1` → socket do gateway só roda se o namespace estiver mesmo isolado, o
  gateway for um socket e o ambiente passar por **lista branca**. Gateway: proxy reverso de um destino `https` com host fixo,
  `POST` em `/v1/messages` e `/v1/messages/count_tokens` apenas, entrada estrita (só dígitos, sem `Content-Length` duplicado nem
  com `Transfer-Encoding`, bloco hexadecimal puro), cabeçalhos por lista branca, prazo de leitura, limites global e por papel,
  `RLIMIT_CORE=0` e `PR_SET_DUMPABLE=0`, auditoria antes do envio (503 se indisponível), servidor de log autenticado pelo uid.
- **Logs** (`logd.py`): único escritor de `logs/`; origem pelo `SO_PEERCRED`; cadeia `hash = sha256(prev + canônico ASCII)`;
  taxa por origem, tamanho máximo, truncamento marcado com `sha256` do original; escrita parcial reabsorvida do disco; recusa
  iniciar com cadeia corrompida, arquivo ausente ou sem `chattr +a`; `--verificar` e `--cabeca`.
- **Guarda** (`guarda_base.py`, `guarda_ferramentas.py`): grava pelo serviço de log e confere que o servidor é a conta esperada
  (dentro da jaula o uid real do servidor não é visível: o lançador confere o dono do socket no host); **padrão fechado** (sem
  confirmação do log, recusa); `ensure_ascii`; qualquer exceção sai com código 2; matcher `.*`; ferramenta desconhecida recusada.
- **Lançador** (`iniciar_sessao.py`): só root; lista **branca** de opções repassáveis ao claude (`--agents`, `--allowedTools`,
  `--system-prompt` etc. recusados, inclusive `--agent=`); `--strict-mcp-config` e `--setting-sources project`; settings do papel
  gerado pelo root (`fchmod` 0644, `/var/tmp`, pode ser lido e não trocado) com `deny` de leitura por papel e de rede; confere
  socket (tipo, dono, pasta) dos serviços; fecha descritores herdados; recusa terminal inseguro.
- **Especificação** (`papeis.json` v2, `isolamento_base.py`): 10 papéis = 10 contas; `produtos/DR` (casca do administrador) e
  `produtos/DR/saida` (conta do DR); validação estrita (modos octais, escrita = o dono da área e só ele, área sigilosa nunca de
  conta de papel, sem escrita por grupo, sem bits especiais indevidos, gid ≠ uid, serviços e rede obrigatórios).

## 3. Configurações de isolamento (resumo)
Arquivos: `governanca/papeis.json`, `scripts/{isolamento,isolamento_base,isolamento_so,jaula,iniciar_sessao,entrada_jaula,logd,gateway}.py`,
`.claude/settings.json` (matcher `.*`, `deny` de `WebFetch/WebSearch/Task/Agent`), hooks. Serviços (instalar fora da árvore do
projeto, como root imutável; contas `ppp-guardiao` e `ppp-rede` com grupo `ppp-leitura`; **nunca root**):
```
# EXEMPLO (não aplicado) — logd.service
User=ppp-guardiao  SupplementaryGroups=ppp-leitura  NoNewPrivileges=yes  ProtectSystem=strict  ReadWritePaths=<projeto>/logs
RuntimeDirectory=ppp-betim/log  ExecStart=/usr/bin/python3 -I -B /opt/ppp-betim/scripts/logd.py --raiz <projeto>
# EXEMPLO (não aplicado) — gateway.service
User=ppp-rede  SupplementaryGroups=ppp-leitura  NoNewPrivileges=yes  LoadCredential=chave:/etc/ppp-betim/chave-api
RuntimeDirectory=ppp-betim/gw  ExecStart=/usr/bin/python3 -I -B /opt/ppp-betim/scripts/gateway.py --raiz <projeto> --chave-arquivo %d/chave
# firewall do host (recomendado): só o uid ppp-rede sai para o destino da API; todos os demais uids, sem saída
```

## 4. Matriz de permissões por papel (gerada de `papeis.json`)
| Área | coordenador | controlador-dr | revisor | p1 | p2 | p3 | p4 | p5 | p6 | p7 |
|---|---|---|---|---|---|---|---|---|---|---|
| `.` (ppp-admin:ppp-leitura 0750) | L- | L- | L- | L- | L- | L- | L- | L- | L- | L- |
| `registros` (ppp-guardiao:ppp-leitura 0750) | L- | L- | L- | L- | L- | L- | L- | L- | L- | L- |
| `dados/entrada` (ppp-admin:ppp-restrito 0750) | -- | L- | L- | -- | -- | -- | -- | -- | -- | -- |
| `dados/restritos` (ppp-admin:ppp-restrito 0750) | -- | L- | L- | -- | -- | -- | -- | -- | -- | -- |
| `logs` (ppp-guardiao:ppp-logs 0750) | L- | -- | L- | -- | -- | -- | -- | -- | -- | -- |
| `produtos` (ppp-admin:ppp-leitura 0750) | L- | L- | L- | L- | L- | L- | L- | L- | L- | L- |
| `produtos/C` (ppp-coord:ppp-leitura 2750) | LE | L- | L- | L- | L- | L- | L- | L- | L- | L- |
| `produtos/DR` (ppp-admin:ppp-dr-leitura 0750) | L- | L- | L- | -- | -- | -- | -- | -- | -- | -- |
| `produtos/DR/saida` (ppp-dr:ppp-dr-leitura 2750) | L- | LE | L- | -- | -- | -- | -- | -- | -- | -- |
| `produtos/P1` (ppp-p1:ppp-leitura 2750) | L- | L- | L- | LE | L- | L- | L- | L- | L- | L- |
| `produtos/P2` (ppp-p2:ppp-leitura 2750) | L- | L- | L- | L- | LE | L- | L- | L- | L- | L- |
| `produtos/P3` (ppp-p3:ppp-leitura 2750) | L- | L- | L- | L- | L- | LE | L- | L- | L- | L- |
| `produtos/P4` (ppp-p4:ppp-leitura 2750) | L- | L- | L- | L- | L- | L- | LE | L- | L- | L- |
| `produtos/P5` (ppp-p5:ppp-leitura 2750) | L- | L- | L- | L- | L- | L- | L- | LE | L- | L- |
| `produtos/P6` (ppp-p6:ppp-leitura 2750) | L- | L- | L- | L- | L- | L- | L- | L- | LE | L- |
| `produtos/P7` (ppp-p7:ppp-leitura 2750) | L- | L- | L- | L- | L- | L- | L- | L- | L- | LE |

L = lê e lista; E = cria/altera/renomeia; - = negado pelo kernel.

Logs: nenhum papel escreve; `coordenador` e `revisor` leem. Dados sigilosos: só `controlador-dr` e `revisor`. Saída do DR:
`coordenador`, `controlador-dr` e `revisor`. `registros/`: ninguém de sessão escreve. Cada agente P1–P7 grava só em `produtos/Pn`.

## 5. Testes positivos e negativos (PASSOU/FALHOU/NÃO EXECUTADO)
| Controle | Tipo | Resultado |
|---|---|---|
| Matriz prevista = kernel, 10 papéis, mais de 800 operações e ataques | +/− | PASSOU |
| Operações legítimas: coordenador→C, DR→DR/saida, cada Pn→Pn, revisor lê tudo que a matriz dá | + | PASSOU |
| Nenhum papel escreve fora da própria pasta; agentes não leem a saída do DR | − | PASSOU |
| Links, hardlink e troca de pasta por link contra `aplicar` (alvo fora do projeto intacto) | − | PASSOU |
| Dono da saída do DR altera modo/grupo: nenhum agente lê (e a auditoria acusa) | − | PASSOU |
| FIFO como sentinela não trava; sonda inconclusiva é reprovada; ancestral gravável recusa `aplicar` | − | PASSOU |
| Jaula: sem rede do host, sem `userns` aninhado, homes de outros papéis e pastas do host ocultos | − | PASSOU |
| Controle positivo: sem jaula de rede a conexão ao host funciona | controle | PASSOU |
| Credencial: ausente do ambiente, argv, logs e de `/proc` do gateway para outros papéis; arquivo da chave ilegível | − | PASSOU |
| Chave só por arquivo 0600/descritor; não existe opção de argv | − | PASSOU |
| Gateway: injeta chave e descarta a do cliente; corpo em pedaços e fluxo atravessam | + | PASSOU |
| Gateway: 6 formas de corpo malformado e 6 de caminho ambíguo não chegam ao destino | − | PASSOU |
| Gateway: uid sem papel negado; sem log nada é enviado (503); destino fora do ar vira 502 auditado | − | PASSOU |
| Log: origem pelo kernel (forja não vale); cadeia cresce, verifica, sobrevive a reinício | + | PASSOU |
| Log: adulteração, remoção, troca e inserção detectadas; cadeia corrompida impede o serviço | − | PASSOU |
| Log: separadores Unicode no conteúdo não quebram a cadeia; taxa por origem; truncamento com hash | − | PASSOU |
| Log: servidor impostor no socket não vale como confirmação | − | PASSOU |
| `claude` real como conta sem privilégio, na jaula, pelo gateway: lê a pasta própria e a de outro produto | + | PASSOU |
| Idem: restritos, entrada, logs, saída do DR, `Grep/Glob` sobre restritos: nada vaza | − | PASSOU |
| Idem: `WebFetch`, `Task`, `Bash` não existem para o agente | − | PASSOU |
| Papéis com direito (DR, revisor, coordenador) leem exatamente o que a matriz dá | + | PASSOU |
| Controles de software quebrados (`settings.json` inválido, hook em timeout, guarda ausente e sem `deny`) | − | PASSOU: nada vaza, nada é escrito fora da pasta própria, a escrita legítima funciona |
| Controle sem jaula e sem conta com o guarda ausente: marcadores vazam e `registros/` é escrito | controle | PASSOU (prova que o teste discrimina) |
| `deny` de leitura gerado pelo lançador sozinho (hook desligado) bloqueia `Read/Grep/Glob`; sem a regra vaza | −/controle | PASSOU |
| Sem serviço de log: o hook recusa até a leitura legítima; a sessão inteira falha antes de qualquer envio | − | PASSOU (a segunda parte é o teste lento `PPP_TESTES_LENTOS=1`) |
| Lançador: opções fora da lista branca, root obrigatório, socket de serviço de outra conta, terminal inseguro, sem log/gateway | − | PASSOU |
| Verificador: agente com ferramenta fora do escopo, deny de rede ausente, matcher que não cobre `Task` | − | PASSOU |
| Guarda: ferramenta desconhecida recusada; internas aceitas | −/+ | PASSOU |
| Vetor de persistência por MCP no HOME | — | NÃO EXECUTADO (o claude, em modo `-p`, não iniciou o MCP nem sem a proteção) |
| Conversa **real** com a API através do gateway (credencial real) | — | NÃO EXECUTADO |
| Instalação dos serviços como unidades do sistema, contas reais, firewall por uid | — | NÃO EXECUTADO |
| Windows/WSL2, sessão interativa, `seccomp` | — | NÃO EXECUTADO |

## 6. Evidências de proteção de credenciais
Chave real nunca em: argv do lançador (`--dry-run` mascara; teste varre), ambiente da sessão (`env`), `cmdline`/`environ` do
gateway, `rede.jsonl` e `guarda-*.jsonl`, arquivo legível pelos papéis. O destino registrou sempre a chave **injetada** pelo
gateway; o marcador `gateway-local-sem-valor` e a "chave do operador" (variável de ambiente do lançador) nunca chegaram ao destino.
O gateway não é legível por outros papéis em `/proc/<pid>/{environ,mem,maps,fd}`.

## 7. Evidências de integridade dos logs
Cadeia verificável, origem por `SO_PEERCRED`, alteração/remoção/troca/inserção detectadas, serviço recusa iniciar sobre cadeia
corrompida, escrita direta impossível para os dez papéis (sondagem). **Limites**: truncar o **fim** da cadeia não é detectado sem
âncora externa (`--cabeca`); quem controla a conta do serviço ou root reescreve tudo.

## 8. Reanálise dos riscos herdados
R1 (heurística de terminal): **MITIGADO** — agentes não têm terminal; a jaula e as contas valem sem a heurística. R2 (plataforma):
Linux/bubblewrap/setpriv; Windows NÃO EXECUTADO. R3 (mesmo usuário): **CORRIGIDO** no desenho e no teste de kernel; implantação real NÃO
EXECUTADA. R4 (lançador não obrigatório): **ABERTO** — depende do operador; mitigação: o hook é fechado por padrão, então sessão sem
lançador também não age. R5 (timeout fail-open do hook): **MITIGADO** (kernel, jaula e `deny` seguram). R6–R7: **ABERTO** (matriz depende
de aprovação humana). R8 (manifesto sem assinatura): **ABERTO**. R9 (`agent_type` não autenticado): **MITIGADO** (uma conta por agente).
R10 (TOCTOU): **CORRIGIDO** em `aplicar`. R11–R12: mantidos. R13 (revisão de Bash): **MITIGADO** (sem Bash nos agentes). R14: NÃO
EXECUTADO. R15–R17: mantidos.

## 9. Parecer técnico independente
Dois revisores novos, somente leitura, sem executar código (**sem teste dinâmico**). Resultado e tratamento:
- **Serviços (log, gateway, ponte, guarda): 18 achados** — corrigidos: quebra de cadeia por separadores Unicode (alta), tamanho de bloco
  negativo e `Content-Length` ambíguo (alta), cotas e prazos (média), caminho com `%`/`;` e prefixo `/v1/` amplo (média), escrita parcial
  que envenena a cadeia (média), truncamento silencioso (média), guarda aberto por padrão e exceção que sai sem código 2 (média), servidor
  de log não autenticado (média), ponte sem checagem de namespace e ambiente por lista negra (média), `--upstream` http (baixa), core dump
  (baixa), janela entre `bind` e `chmod` (baixa), `chattr +a` não verificado (baixa). **Aceitos e documentados**: dados do hook
  autodeclarados e taxa/cota (R20), fim da cadeia, uso da chave pelo gateway (R21), registro "fim" sem garantia.
- **Isolamento e lançador: 18 achados** — corrigidos: dono da saída do DR expondo a pasta (alta, pasta-casca), lançador sem root (média),
  lista negra de opções do claude (média), erros engolidos e `aplicar` sem auditoria, ancestral e `home_base` (média), sonda destrutiva e
  "negado" para qualquer erro (média), traversal que trava com FIFO (média), `userns` aninhado (média), homes de outros papéis visíveis
  (média), descritores herdados (baixa). **Aceitos**: terminal de controle (TIOCSTI) só **recusado**, não eliminado (R25); `ro-bind /`
  parcial (R24); `st_dev` (R26); sessões do mesmo papel (R18).
Os revisores confirmaram que a ordem `setpriv → bwrap → entrada → claude`, `no_new_privs` e o bounding set zerado estão corretos.
**O parecer não homologa o desenho**: a revisão é estática; a revisão dinâmica por pessoa qualificada continua pendente.

## 10. Recomendação formal: **BLOQUEAR** dados reais
Não declaro homologação geral. Riscos críticos de GOV-07 (links em operação privilegiada, credencial na sessão, rede aberta, logs
graváveis pelo papel, escrita do DR, conta compartilhada P1–P7, `deny` de leitura, cobertura de ferramentas) estão **corrigidos no
laboratório**. Para liberar é preciso, nesta ordem:
1. Instalar serviços e contas reais; rodar `aplicar`, `auditar`, `sondar`, a suíte e o teste lento em ambiente **equivalente ao de produção**.
2. Repetir uma conversa **real** com a API através do gateway, com chave de API real no arquivo do serviço (NÃO EXECUTADO).
3. Configurar firewall por uid, publicar a cabeça das cadeias fora do serviço e definir tetos de gasto (R20, R21).
4. Decidir os abertos (R18 mesmo papel, R19 trilha dos `deny`, R22 OAuth, R23 provedor do modelo, R24 lista branca de montagens).
5. Revisão **dinâmica** independente por pessoa qualificada e teste de intrusão.
6. Aceite humano expresso e assinado pelo coordenador; autenticação humana não é suprida por allowlist.
Sem 1–6, dados reais permanecem proibidos.
