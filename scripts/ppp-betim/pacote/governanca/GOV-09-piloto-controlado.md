# GOV-09 — Piloto controlado de infraestrutura e API

Status: **piloto de LABORATÓRIO executado; homologação institucional NÃO realizada; chamada real à API NÃO EXECUTADA.**
Dados: exclusivamente sintéticos. Nenhum resultado aqui autoriza dados reais nem declara homologação geral.

## 1. O que cada prova vale

| Camada | O que foi demonstrado | O que NÃO foi |
|---|---|---|
| Laboratório (este contêiner) | Contas reais, processos reais, `claude` real sob a conta do papel, jaula, gateway, serviço de log, supervisor, falhas e recuperação, âncoras, duas rodadas reprodutíveis | Qualquer chamada ao provedor real; qualquer propriedade de uma infraestrutura institucional |
| Homologação institucional | — (não existe ainda) | Tudo: systemd, firewall por uid, cgroups, âncora fora do host, rede/proxy reais, credencial real |

O destino da API no laboratório é um **modelo simulado local** com uma **credencial canário sintética**. Isso comprova o encanamento
(sessão → jaula → gateway → destino) e os bloqueios; **não equivale a uma chamada real**.

## 2. Plano de implantação na homologação (executado por HUMANO, com autorização)

Pré-requisitos: Linux com `setpriv`, `bwrap`, `chattr` (sistema de arquivos com atributo `a`), `claude` instalado, user namespaces habilitados.

1. `python3 scripts/piloto.py preflight` — nada deve estar NOK.
2. Revisar `governanca/papeis.json`; em seguida `sudo python3 scripts/piloto.py contas criar` (sem shell; nomes validados).
3. Árvore do projeto **sem dados reais**: `sudo python3 scripts/piloto.py instalar --origem <árvore>`. Recusa: dados sem marca `SINTETICO`, link simbólico no código,
   supervisor em execução. Logs e âncoras da instalação anterior são **arquivados**, não apagados.
4. Credencial (seção 3). Só depois, serviços: no piloto, `piloto.py supervisor`; **na homologação use unidades systemd** (não incluídas) com
   `User=ppp-guardiao`/`ppp-rede`, `NoNewPrivileges`, `CapabilityBoundingSet=`, e **firewall por uid** liberando saída apenas para a conta `ppp-rede`.
5. `servicos.json` de homologação: `upstream` = o de `papeis.json`; **sem** `permitir_teste`; `proxy_arquivo`/`ca_arquivo` somente se a rede exigir
   (CA **substitui** o repositório do sistema; arquivo do root, sem escrita para outros).
6. Âncoras: definir destino **fora do host** (outro host ou mídia de escrita única). O padrão local não protege contra root.
7. `sudo python3 scripts/piloto.py executar --modo api-real --saida <pasta>`: S04 só roda com credencial legítima; demais cenários que dependem de roteiro simulado ficam NÃO EXECUTADO.

## 3. Provisionamento seguro da credencial (sem chat, sem argv, sem log)

- O responsável humano obtém a chave pelo canal seguro da instituição e executa, no servidor:
  `gerenciador-de-segredos ler <nome> | sudo python3 scripts/piloto.py credencial instalar --rotulo <ticket>` **ou** digita no prompt sem eco.
- A CLI **não aceita** a credencial por argumento. O arquivo `/etc/ppp-betim/chave-api` fica `0600` da conta `ppp-rede` (escrita atômica, `O_EXCL|O_NOFOLLOW`).
- O registro (`evidencias/registro-credencial.jsonl`, 0600 do root) guarda ação, rótulo, tamanho e uma impressão de 8 hex — nunca o valor.
- `credencial revogar` remove o arquivo e o **supervisor derruba o gateway em execução** (verificado no F4 sem intervenção manual); rotação (novo arquivo) religa o gateway com a nova chave.
- `piloto.py varredura` procura o valor em argv/ambiente de todos os processos e em arquivos de pastas definidas, sem imprimi-lo.
- Nenhuma credencial do ambiente de desenvolvimento/sandbox é reutilizada. Nenhuma é pedida por chat.

## 4. Cenários (S01–S10) e o tipo de teste de cada um

| ID | Tipo | Verifica (resumo) |
|---|---|---|
| S01 | Infraestrutura | `claude` real roda como uid do papel: sem capabilities, `no_new_privs`, namespace de rede próprio, sem a chave do operador no ambiente |
| S02 | Infraestrutura | Auditoria/sondagem de permissões do SO por papel + inventário `id/getent` |
| S03 | Infraestrutura | Lançador recusa: não-root, sem papel, opção fora da lista, serviço de log ausente, papel inexistente, configuração adulterada (mensagem esperada por caso) |
| S04 | **Integração real** | Chamada real pelo gateway. **NÃO EXECUTADO** sem credencial humana |
| S05 | Infraestrutura | Credencial ausente de argv/ambiente/arquivos; nenhum papel lê o arquivo; controle positivo da varredura |
| S06 | Infraestrutura | Só loopback; sem rota ao IP do provedor nem ao DNS; gateway aceita `/v1/messages` e recusa o resto |
| S07/S07b | Infraestrutura | Cadeias íntegras, só-anexar, âncora publicada e conferida, antes e depois das falhas |
| S08 | Agentes nomeados + skills (modelo SIMULADO) | Decisões do guardião lidas do log encadeado: skills autorizadas permitidas, não autorizadas e externas recusadas; gravação em área alheia recusada; DAC do SO |
| S09 | Falha e recuperação | F1 log cai · F2 gateway cai · F3 destino indisponível · F4 revogação/rotação · F5 adulteração de logs (em cópia) · F6 rajada |
| S10 | Reprodutibilidade | Duas rodadas independentes, mesma evidência determinística |

Limites assumidos: S08 não prova o **julgamento** dos agentes (modelo simulado). Em modo headless a gravação exige aprovação humana (política padrão): o guardião
registra `permitido` na área própria e a gravação é negada pela falta de aprovação — comportamento seguro e esperado, que implica fluxo operacional com humano.

## 5. Achados do piloto e das revisões independentes (corrigidos)

1. Teste F5 usava `echo >>` esperando recusa: `chattr +a` **permite anexar**; o registro estranho quebrou a cadeia e o serviço recusou subir (fail-closed). Teste corrigido.
2. Recusas (403/429) com corpo não lido causavam reset de conexão no cliente → o gateway agora drena (limitado) o corpo antes de fechar.
3. Backlog de 5 do `listen` fazia metade de uma rajada de 40 conexões receber `EAGAIN` → backlog 128 + teto de 64 conexões abertas.
4. Recusas eram auditadas antes do limitador (inundação do log só-anexar) → limitador por papel/uid antes de qualquer auditoria.
5. `credencial revogar` não derrubava o gateway em execução → supervisor compara inode/mtime da credencial e derruba/religa.
6. `servicos.json` de laboratório podia sobreviver até o modo real → removido ao fim do laboratório; `api-real` recusa `permitir_teste` e `upstream` divergente; a exceção HTTP só vale com credencial marcada `SINTETICO`.
7. `shell=True` como root na criação de contas → argv sem shell, nomes validados por regex e pelo validador da especificação.
8. `instalar` seguia links simbólicos, apagava logs, trocava código com serviços no ar → recusa links, arquiva logs, exige supervisor parado, valida os dados da árvore que será copiada.
9. Reinstalação deixava âncoras antigas ao lado de logs novos (falso `REESCRITA`) → âncoras antigas arquivadas.
10. Arquivo de CA sem verificação de dono/modo e texto "acrescenta" (na verdade substitui) → verificação e texto corrigidos.

## 6. Riscos residuais (resumo; matriz completa no relatório final)

R-01 sem chamada real · R-02 âncora no mesmo host não protege contra root · R-03 cauda após a última âncora não é coberta ·
R-04 proxy `http` leva `Proxy-Authorization` em claro até o proxy; CA corporativa dá acesso ao conteúdo · R-05 gotejamento de cabeçalhos ainda ocupa um slot por até 30 s por leitura (mitigado pelo teto de 64) ·
R-06 o gateway não limita volume/custo de uso da chave (definir teto no provedor) · R-07 cabeçalhos encaminhados por prefixo (`accept*`, `anthropic-*`, `x-app`) ·
R-08 sem systemd/cgroups/firewall por uid na homologação ainda · R-09 `chattr +a` validado só no sistema de arquivos do laboratório · R-10 varredura de credencial é pontual (bytes literais).

## 7. Decisões humanas pendentes

1. Provisionar a credencial pelo canal seguro e **autorizar** a execução de S04. 2. Escolher o destino externo das âncoras. 3. Autorizar a infraestrutura de homologação (unidades de serviço, firewall por uid).
4. Definir proxy/CA corporativa (se houver) e aceitar o risco R-04. 5. Definir teto de gasto no provedor. 6. Definir o fluxo de aprovação humana para gravações headless.
7. Revisão independente **dinâmica** na homologação. 8. Aceite humano dos componentes verificados; **dados reais permanecem bloqueados**.
