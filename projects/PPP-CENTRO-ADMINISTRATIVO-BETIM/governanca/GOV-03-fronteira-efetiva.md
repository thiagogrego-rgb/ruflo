# GOV-03 — Fronteira de confiança efetiva

**Estado:** implementada como serviço guardião e **validada somente contra processos
sintéticos sem privilégio**. **Não homologada.** Nenhuma proteção em produção pode ser
declarada antes da implantação supervisionada da seção 10.

> **Premissa do modelo de ameaças.** O agente real que desenvolveu este pacote executa
> como `root` no próprio contêiner. Contra `root`, nenhuma permissão de arquivo, usuário
> de SO ou serviço local oferece fronteira: ele pode alterar código, trocar a chave de
> verificação, finalizar o guardião e ler memória de processos. Por isso a fronteira só
> pode ser **testada** contra agentes sintéticos sem privilégio e só será **efetiva**
> numa infraestrutura em que o agente de produção não tenha privilégio administrativo
> sobre o guardião, as chaves e os registros.

## 1. Modelo de ameaças

Adversário: agente de IA com controle integral do **próprio** ambiente de execução
(arquivos, subprocessos, terminais, sockets), mas sem privilégio administrativo sobre o
guardião, o aprovador humano e a âncora. Fora do escopo: comprometimento de `root` do
host do guardião, do kernel, do hardware e do aprovador humano (tratados em 8).

| # | Ameaça | Controle | Tipo | Teste |
|---|---|---|---|---|
| T1 | Modificar o verificador/schemas | Código de propriedade de `root`, sem escrita por terceiros; o guardião **recusa iniciar** se houver escrita por terceiros | Preventivo (depende do SO) | `agente_nao_modifica_verificador`, `guardiao_recusa_codigo_gravavel` |
| T2 | Alterar o cadastro de aprovadores | Cadastro de `root`, assinado pela raiz de governança; a assinatura é revalidada a **cada** verificação | Preventivo + falha fechada | `agente_nao_altera_cadastro...`, `cadastro_de_aprovadores_exige_assinatura_da_raiz`, `cadastro_adulterado_com_guardiao_em_execucao...` |
| T3 | Obter chave privada | Chaves de aprovador fora da máquina do agente; chave do guardião `0600` do serviço; `/proc` do guardião inacessível a outros uids | Preventivo (SO) | `agente_nao_obtem_chave_privada` |
| T4 | Cadastrar identidade própria | Cadastro só muda com assinatura da raiz (offline) | Preventivo (criptográfico) | `agente_nao_cadastra_identidade_propria...` |
| T5 | Aprovar o que produziu | Aprovação exige assinatura de aprovador humano cadastrado; proponentes e aprovadores são conjuntos disjuntos | Preventivo (criptográfico + configuração) | idem; `config_recusa...` |
| T6 | Reverter/excluir versão e aprovação | Sem escrita no armazenamento (só o guardião escreve); sem operação de exclusão na API. **Contra `root`/guardião comprometido: só detecção**, via checkpoint ancorado | Preventivo (agente sem privilégio) / **Detectivo** (host) | `agente_nao_reverte_nem_exclui`, `rollback_no_host_do_guardiao_e_detectado` |
| T7 | Falsificar identidade do proponente | Identidade obtida do kernel (`SO_PEERCRED`) e mapeada na configuração; campos do pedido não alteram identidade nem papel | Preventivo | `agente_nao_falsifica_proponente`, `identidade_vem_do_kernel...` |
| T8 | Contornar por terminal/subprocesso | Subprocessos herdam o uid do agente; o assinador recusa chave dentro do projeto e exige terminal — **atrito, não controle**; a barreira real é a chave estar ilegível | Preventivo (SO) | `agente_nao_contorna_por_terminal_ou_subprocesso` |
| T9 | Adulterar o conteúdo que o humano assina | A assinatura cobre o SHA-256 da versão guardada; envelope alterado em trânsito não vira aprovação | Preventivo (criptográfico) | `agente_adultera_o_que_o_humano_assina` |
| T10 | Ancorador usado para escrever | Papel `ancoradores`: só `{"op":"checkpoint"}` | Preventivo | seção 4 |

## 2. Arquitetura de isolamento

```
   AGENTE(S) (uid próprio, sem privilégio)      APROVADOR HUMANO (outro dispositivo)
        │  socket Unix                                 │ chave privada Ed25519 (nunca no host)
        ▼  SO_PEERCRED → uid → identidade              ▼ assina {id, versão, SHA-256}
   ┌──────────────── GUARDIÃO (uid de serviço, não-root) ────────────────┐
   │ valida (JSON Schema) · grava append-only · verifica assinatura      │
   │ lê cadastro assinado pela RAIZ DE GOVERNANÇA (chave offline)        │
   │ emite CHECKPOINTS assinados (chave do guardião)                     │
   └────────────┬───────────────────────────────────────┬────────────────┘
        código e cadastro: root, só leitura        ANCORADOR (uid próprio)
                                                    solicita checkpoint → grava em
                                                    meio externo (WORM / remoto protegido)
```

- **Agente:** não tem escrita em código, cadastro, configuração, armazenamento, chaves
  nem no diretório do socket. Só fala com o socket.
- **Guardião:** único com escrita em `registros/`. Recusa iniciar se rodar como `root`,
  se código/configuração/cadastro tiverem escrita por terceiros, se a chave não for
  `0600` do serviço, ou se papéis forem conflitantes.
- **Aprovador humano:** assina fora do host. O guardião só tem a chave **pública**.
- **Raiz de governança:** assina `aprovadores.json`; a chave fica offline.

## 3. Papéis e identidades

| Papel | Identificação | Pode | Não pode |
|---|---|---|---|
| Proponente | uid de SO → id na configuração | propor, exportar versão, consultar estado, registrar uma aprovação **já assinada** | ancorar; aprovar por conta própria |
| Ancorador | uid de SO em `ancoradores` | solicitar `checkpoint` e nada mais | propor, aprovar, consultar, exportar |
| Aprovador | chave Ed25519 no cadastro | assinar aprovações | escrever no guardião |
| Raiz de governança | chave offline | assinar o cadastro | — |

## 4. Papel `ancoradores`

- Lista de uids na configuração (`ancoradores`, inteiros ≥ 1). Ausente → **ninguém** ancora.
- Conjunto **disjunto** de proponentes e do uid do guardião; o guardião recusa iniciar
  se houver interseção. `root` (uid 0) é rejeitado pelo schema.
- O ancorador só é aceito com o pedido exatamente igual a `{"op":"checkpoint"}`; qualquer
  campo extra, outra operação ou pedido que não seja objeto é negado.
- Proponentes **não** herdam a permissão (corrigido nesta etapa — ver seção 8).
- Identidade e papel vêm exclusivamente do kernel: campos como `uid`, `papel` ou
  `proponente` enviados pelo cliente são ignorados ou causam recusa.

## 5. Aprovação externa

1. O agente propõe via guardião; o guardião grava o envelope canônico da versão.
2. O humano obtém o envelope (por canal administrativo) e confere o conteúdo.
3. Em dispositivo próprio, `assinar_aprovacao.py assinar --envelope ...` mostra o envelope
   e o SHA-256 e assina `{premissa, versão, SHA-256, aprovador, data}`.
4. O agente entrega a aprovação ao guardião, que valida formato, vínculo com a versão
   guardada, cadastro assinado pela raiz, papel/produto e segregação de funções.

O canal 2 não precisa ser confiável **para integridade**: se o envelope for alterado, o
SHA-256 assinado não confere com o guardado e a aprovação é recusada. O risco restante é
de **disponibilidade** e de o humano aprovar sem revisar o conteúdo (administrativo).

## 6. Ancoragem do histórico

O guardião emite checkpoints encadeados (`seq`, hash do anterior), assinados com a chave
do guardião, contendo os hashes de todas as versões e aprovações. **Implementado:** emissão,
encadeamento e verificação (`ancora.verificar_checkpoint`). **Não implementado:** agendamento,
transporte e custódia externa — são administrativos:

- cópia em armazenamento com retenção imutável (WORM/object lock em modo de conformidade),
  ou em repositório remoto com branch protegida (sem force-push nem exclusão), com
  credencial de **escrita apenas**; opcionalmente carimbo de tempo RFC 3161;
- a chave pública do guardião deve ser conhecida do verificador por canal independente.

É controle **detectivo**: não impede remover ou reverter; permite provar, depois, que algo
ancorado desapareceu ou mudou. O que ocorrer após o último checkpoint externo não é coberto.
Git local e o disco do guardião **não** são âncora (o `ultimo.json` local é conveniência).

## 7. Configurações propostas (não aplicadas)

`/etc/ppp-betim/guardiao.json` (`root:root`, `0644`, nunca gravável pelo agente):

```json
{
  "formato": 1,
  "registros": "/var/lib/ppp-betim/registros",
  "aprovadores": "/etc/ppp-betim/aprovadores.json",
  "chave_raiz_governanca": "<64 hex da chave PÚBLICA da raiz>",
  "chave_privada_guardiao": "/var/lib/ppp-betim/guardiao.pem",
  "socket": "/run/ppp-betim/guardiao.sock",
  "proponentes": {"<uid agente P3>": "agente-p3", "<uid agente P4>": "agente-p4"},
  "ancoradores": [<uid ancorador>]
}
```

| Caminho | Dono | Modo |
|---|---|---|
| `/opt/ppp-betim/` (código, venv com `jsonschema` e `cryptography`) | root | `0755`, sem escrita por terceiros |
| `/etc/ppp-betim/{guardiao.json,aprovadores.json,aprovadores.json.sig}` | root | `0644` |
| `/var/lib/ppp-betim/{registros,guardiao.pem}` | `ppp-guardiao` | `0700` / `0600` |
| `/run/ppp-betim/` | `ppp-guardiao` | `0755` (socket `0666`; a autorização é por `SO_PEERCRED`) |

Unidade systemd sugerida (**não testada**): `User=ppp-guardiao`, `NoNewPrivileges=yes`,
`CapabilityBoundingSet=` (vazio), `ProtectSystem=strict`, `ReadWritePaths=/var/lib/ppp-betim`,
`RuntimeDirectory=ppp-betim`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_UNIX`,
`ExecStart=/opt/ppp-betim/venv/bin/python -I -B /opt/ppp-betim/scripts/guardiao.py /etc/ppp-betim/guardiao.json`.
Cada agente deve rodar em **uid próprio**, fora de `sudo`, `docker` e grupos de disco.

## 8. Resultados observados (ambiente de desenvolvimento)

Execução: guardião, agente, aprovador humano e ancorador como uids sintéticos distintos
(`setuid` em subprocessos; nenhum usuário foi criado). Chaves e dados sintéticos, descartados.

| Verificação | Resultado contra agente **sem privilégio** |
|---|---|
| Modificar o verificador | Negado (anexar, substituir, `sitecustomize`, módulo-sombra, schema, `chmod`) |
| Alterar o cadastro de aprovadores | Negado; com `root` adulterando o cadastro, o guardião em execução passa a **negar** aprovações e a não reconhecer as já feitas |
| Obter a chave privada | Negado (chave do humano, do guardião, `/proc/<pid>/mem` e `environ`) |
| Cadastrar identidade própria | Negado (3 identidades assinadas com chave do agente) |
| Aprovar o que produziu | Negado; estado permanece `PROPOSTA` |
| Reverter / excluir última versão e aprovação | Negado (unlink, rename, rmdir, operações inexistentes, reescrita); **com `root` do host: apenas detectado** pelo checkpoint externo |
| Falsificar o proponente | Negado (campo no pedido, uid não cadastrado) |
| Contornar por terminal/subprocesso | Negado (`setuid(0)`, `kill`, `sudo`, escrita via subprocesso, assinador via pty sem a chave) |
| Ancoragem | `ancoradores` obtêm checkpoints encadeados; proponentes e não cadastrados são negados |

**Contra o agente real desta sessão (root): todas essas verificações seriam burladas.**

**Suíte:** 21 testes de fronteira (`testes/test_fronteira.py`), 22 de GOV-01/02 e os 10 iniciais.
Sem Linux/root, os de fronteira são **pulados** com o aviso "fronteira NÃO homologada".

**Controles negativos** (cada um enfraquece um controle; esperado: algum teste falha):

| Mutação | Detectada por |
|---|---|
| M1 proponente volta a pedir checkpoint | `proponente_nao_adquire_permissao_de_ancoragem` |
| M2 ancorador deixa de ser restrito a `checkpoint` | `ancorador_so_ancora...` |
| M3 papel aceito por campo do cliente | `identidade_vem_do_kernel...`, `ancorador_so_ancora...` |
| M4 uid aceito por campo do cliente | `identidade_vem_do_kernel...` |
| M5 ancorador = proponente/guardião | `config_recusa_ancoradores...` |
| M6 schema aceita ancorador uid 0 | `config_recusa_ancoradores...` |
| M7 cadastro sem verificar a raiz | `cadastro_de_aprovadores_exige...`, `cadastro_adulterado_com_guardiao_em_execucao...` |
| M8 sem verificação de proteção do código | `guardiao_recusa_codigo_gravavel...` |
| M9 guardião aceita rodar como root | `guardiao_recusa_configuracao_insegura` |
| M10 sem verificação de proteção da configuração | `guardiao_recusa_configuracao_insegura` |

**Falhas e lacunas encontradas e tratadas:**
1. **Proponentes podiam pedir `checkpoint`** (ramo remanescente no guardião). Nenhum dos 11
   testes anteriores cobria isso. Reproduzido (teste vermelho), corrigido e coberto.
2. **A verificação de proteção do código do guardião não tinha teste**; a mutação M8 teria
   passado despercebida. Teste adicionado.
3. **Dependência de ordem entre testes** (um teste destrutivo de rollback precedia outro):
   renomeado e documentado.
4. **Testes de recusa deixavam guardiões órfãos.** Nos controles negativos M8 e M10 o guardião
   passou a iniciar; o teste estourava o prazo sem encerrar o processo (dois guardiões vivos
   como uid sintético) e, por apontar para o socket principal, poderia tomá-lo. Corrigido: os
   testes de recusa usam `tentar_iniciar`, que sempre encerra o processo, com socket próprio.
   Reexecução dos 10 controles: todos detectados, nenhum processo residual.
5. A sessão anterior foi interrompida por HTTP 529; foi retomada pelo estado do repositório.

## 9. Riscos residuais e limitações

| # | Risco | Situação |
|---|---|---|
| R1 | Rollback sem rastro | **Detectável**, não prevenido; só para o que já foi ancorado externamente. Agendamento/transporte pendentes; não há CLI de verificação (apenas API) |
| R2 | Reescrita de versões não aprovadas | Prevenida contra agente sem privilégio; contra `root`/guardião comprometido, só detectável via âncora |
| R3 | Proponente declarado | Resolvido contra o cliente (kernel). Agentes que compartilham um uid compartilham identidade; o mapa uid→id é administrativo |
| R4 | Agente com escrita em código/cadastro | Prevenido se o agente não é root e o código é de `root`; o guardião recusa iniciar caso contrário |
| R5 | `root` anula tudo | **Inalterado.** É a premissa do modelo |
| R9 | Cadastro assinado sem série/validade: reapresentar um cadastro antigo, já assinado, reativa aprovadores revogados | **Tratado no GOV-04** (série crescente + referência externa assinada + marca d'água); a efetividade contra o host depende da mídia externa |
| R10 | Dependências Python (`jsonschema`, `cryptography`) fora da verificação de proteção do guardião | **Tratado no GOV-04** (lock com hashes + verificação do ambiente na inicialização); restam interpretador, stdlib e bibliotecas de sistema |
| R11 | Guardião comprometido pode apagar/reescrever registros (não forjar aprovações) e emitir checkpoints falsos | Detectável só com âncora independente e carimbo de tempo |
| R12 | Sem limitação de taxa: propostas ou checkpoints em excesso consomem disco | **Tratado no GOV-04** na aplicação (tamanho, frequência, crescimento); o limite real é a cota do SO |
| R13 | `SO_PEERCRED` em namespaces/contêineres reporta o uid do namespace do guardião | Validar na implantação (mapa de uid) |
| R14 | Revisão humana do conteúdo e custódia da chave do aprovador (token de hardware recomendado) | Administrativo; atrito do assinador (tty, confirmação) **não** é segurança |
| R15 | Unidade systemd e permissões da seção 7 não foram testadas | Pendente |

## 10. Implantação supervisionada (nada abaixo foi executado)

Cada etapa exige autorização humana específica; o agente não executa nenhuma delas.

1. **Infraestrutura separada**: VM/host em que o agente de produção não tenha `root`, `sudo`,
   `docker` nem acesso ao disco do guardião. Registrar a topologia.
2. **Cerimônia da raiz** (offline, duas pessoas): gerar a chave da raiz; assinar o cadastro
   com `assinar_aprovacao.py assinar-registro`; guardar a chave offline.
3. **Contas de SO** (humano autoriza): `ppp-guardiao` (sem login), um uid por agente
   proponente, `ppp-ancorador`; sem sobreposição e fora de grupos privilegiados.
4. **Instalação**: pacote de uma versão marcada; conferir o SHA-256; venv de `root`; permissões
   da seção 7.
5. **Chave do guardião**: gerada pelo serviço; registrar a chave pública por canal independente.
6. **Aprovadores**: cada humano gera a chave no próprio dispositivo; a raiz assina o cadastro.
7. **Ancoragem**: tarefa do `ancorador` que solicita checkpoint periodicamente e o grava em
   meio externo com retenção imutável; simulado de restauração em ambiente de homologação.
8. **Teste de aceitação**: reexecutar `test_fronteira.py` com as **contas reais** (ajustando as
   constantes de uid) e as nove verificações adversariais da tabela da seção 8, a partir do
   runtime real do agente (não de um processo sintético).
9. **Critério**: qualquer falha crítica impede a homologação. A revisão deve ser feita por
   pessoa independente de quem implementou.
10. **Operação**: rotação e revogação de chaves, revisão periódica do cadastro, auditoria.
