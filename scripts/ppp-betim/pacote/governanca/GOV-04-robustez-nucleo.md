# GOV-04 — Robustez do núcleo de governança

**Estado:** implementado e testado com dados e identidades sintéticos. **Não homologado.**

> **Premissa que não mudou.** O agente real que desenvolveu este pacote executa como `root`
> no próprio contêiner. Contra `root`, nenhum controle local resiste. Tudo abaixo foi
> validado contra processos sintéticos **sem privilégio**, e as proteções que dependem de
> mídia, contas e permissões externas só valem depois da implantação supervisionada
> (seção 11), que **não foi realizada**.

Este documento complementa `GOV-03-fronteira-efetiva.md` e trata dos riscos **R9** (replay do
cadastro assinado), **R10** (dependências Python fora da verificação) e **R12** (consumo de
recursos). Leia-o junto com as seções 9 e 10 do GOV-03.

## 1. Controles implementados × testes executados × dependências de infraestrutura

| Controle | Implementado | Testes executados (resumo) | Depende de infraestrutura |
|---|---|---|---|
| Série crescente no cadastro assinado | `serie.py`, `aprovadores.schema.json` (`serie`) | crescente, replay, duplicada, ausente/ inválida (`test_serie.py`) | — |
| Referência externa assinada pela raiz | `serie.py`, `referencia-serie.schema.json` | ausente, adulterada, de outra raiz, lixo; em execução e na inicialização | **Mídia que o agente e o host do guardião não consigam reverter** (sem ela, só vale contra agente sem privilégio) |
| Marca d'água de série do guardião | `serie.py` | persistência, corrupção, recuperação, queda na gravação | Diretório do serviço protegido do agente |
| Lock de dependências com hashes | `requirements.lock`, `gerar_lock.py` | instalado de verdade em venv descartável; hash adulterado rejeitado pelo pip | Venv de `root` fora do alcance do agente |
| Verificação do ambiente na inicialização | `ambiente.py`, `guardiao.py` | ausente, incompatível, arquivo adulterado/apagado/injetado, permissões, `-I`, `pycache_prefix` | Python/stdlib/bibliotecas de sistema protegidos pelo SO (não verificados) |
| Limites de requisição (tamanho, prazo) | `limites.py`, `guardiao.py` | acima do limite, gotejamento, cliente parado, uid sem papel | — |
| Limites de frequência e de conexões | `limites.py`, `guardiao.py` | por identidade, isolamento entre identidades, tetos de conexão | uids distintos por agente (agentes que dividem um uid dividem a cota) |
| Limites de crescimento | `premissas_repositorio.py`, `guardiao.py` | bytes, versões, premissas, total, checkpoints (quantidade, bytes, intervalo) | **Cota do sistema de arquivos** (o limite real de disco) |
| Verificador independente de checkpoints | `verificar_ancora.py` | 31 testes: válido, inválido, regressões assinadas, armazenamento | Cópias dos checkpoints em meio externo; chave do guardião por outro canal |
| Recuperação após interrupção | `guardiao.py`, `premissas_repositorio.py`, `serie.py` | temporários, checkpoint pela metade, pastas vazias, `kill -9` | — |
| Ferramenta do humano para a série | `assinar_aprovacao.py` | recusa série que não aumenta; exige `--anterior`/`--primeiro` | Terminal e chave do aprovador fora do host (atrito, não segurança) |

## 2. Ameaças tratadas

| # | Ameaça | Controle | Tipo |
|---|---|---|---|
| A1 | Reapresentar cadastro antigo, ainda assinado, que inclui aprovador depois revogado | Piso = maior entre a referência externa e a marca d'água | Preventivo (com a mídia externa); **detectivo** via série nos checkpoints ancorados |
| A2 | Reapresentar cadastro novo com a mesma série e outro conteúdo | Hash fixado pela referência e pela marca d'água | Preventivo |
| A3 | Remover/adulterar a referência | Assinatura da raiz; arquivo de `root`, fora do armazenamento do guardião | Preventivo (assinatura) + administrativo (mídia) |
| A4 | Biblioteca de terceiros alterada, apagada ou com arquivo injetado | Versões exatas, hashes do RECORD, arquivos não listados, proteção de diretórios | Preventivo na inicialização; detectivo depois |
| A5 | Código de inicialização injetado (`.pth`, `sitecustomize`, `PYTHONPATH`, `.pyc`) | `-I`, proteção de `sys.path`/`.pth`, `-X pycache_prefix` | Preventivo na inicialização |
| A6 | Requisições gigantes ou lentas, flood de operações | Limites de bytes, prazo total de leitura, balde de fichas por uid, tetos de conexão | Preventivo |
| A7 | Esgotar disco com propostas ou checkpoints | Limites de bytes/versões/premissas/checkpoints | Preventivo parcial; **a cota do SO é o limite real** |
| A8 | Queda durante a gravação deixa o sistema travado ou inconsistente | Gravação atômica, recuperação na inicialização | Preventivo/recuperação |
| A9 | Rollback do histórico no host | Verificador independente sobre cópias externas | **Detectivo** |
| A10 | Humano assina cadastro com série menor por engano | `assinar-registro` recusa | Preventivo (erro humano) |

## 3. Série do cadastro e referência externa

**Regras (código em `serie.py`).** O cadastro `aprovadores.json` contém `serie` (inteiro ≥ 1) dentro
dos bytes assinados. Um cadastro é aceito se e somente se:

1. a assinatura da raiz confere (como no GOV-02);
2. `serie` é inteiro válido (booleano, zero, texto e ausência são recusados);
3. `serie ≥ piso`, onde `piso = max(serie_minima da referência, série da marca d'água)`;
4. se `serie == serie_minima`, o SHA-256 do cadastro é o fixado pela referência;
5. se `serie` é igual à da marca d'água, o SHA-256 é o já aceito.

A referência (`referencia-serie.json`) é um documento assinado pela raiz com
`serie_minima` e `sha256_cadastro`. A marca d'água (`registros/estado/serie-cadastro.json`)
guarda a maior série aceita e é gravada de forma atômica. A verificação se repete a **cada**
operação que consulta o cadastro, e também ao emitir checkpoints: um cadastro retrocedido
bloqueia aprovações e ancoragem (falha fechada), em vez de ser ancorado.

**O que o guardião exige da referência** (e recusa iniciar sem isso): arquivo de propriedade de
`root` (não do serviço), caminho sem escrita por terceiros e fora de `registros/`.

**O que o guardião não consegue verificar:** que a mídia onde a referência mora seja de fato
independente. Para a proteção valer contra o host do guardião, a referência deve ser entregue por
meio que ele e o agente não reescrevam — por exemplo, volume somente leitura montado de outro
sistema, objeto com retenção imutável (WORM) lido por montagem, ou repositório com branch
protegida sincronizado por um serviço sem acesso do agente. Com a referência no mesmo disco e
gravável por `root` do host, um atacante `root` restaura referência, cadastro e marca d'água
antigos e o controle some.

**Ordem ao trocar de série:** publicar o **cadastro** novo primeiro e a **referência** depois.
Referência à frente do cadastro bloqueia o guardião (série abaixo do piso) até o cadastro chegar.

**Reversão legítima (procedimento humano, com a raiz).** A série **nunca diminui**. Para voltar a
um conjunto anterior de aprovadores, assine um **novo** cadastro com o conteúdo desejado e série
maior que a vigente:

1. editar `aprovadores.json` com o conteúdo desejado e `serie = N+1` (ou maior);
2. `assinar_aprovacao.py assinar-registro --chave raiz.pem --registro aprovadores.json --anterior <cadastro vigente>`
   (recusa se a série não superar a anterior);
3. implantar cadastro + `.sig`; depois emitir e publicar a referência com
   `assinar-referencia ... --anterior-referencia <referência vigente>`;
4. conferir que o guardião aceitou (marca d'água = N+1) e anexar o registro da mudança.

Série emitida por engano **alta demais** não se corrige baixando: emite-se outra, maior, com o
conteúdo correto. **Marca d'água perdida ou ilegível:** é recusada (não presumida). Após
investigação, o administrador remove `registros/estado/serie-cadastro.json`; o guardião a
recria a partir da referência, que continua sendo o piso. **Referência perdida:** restaurar a
última cópia e confrontar com a série do último checkpoint ancorado
(`verificar_ancora.py --serie-minima N`) antes de reativar.

## 4. Ambiente Python reproduzível e verificável

- **Reprodutível:** `requirements.lock` lista 9 distribuições com 265 hashes SHA-256 de *wheels*
  (nunca sdist, então nenhum código de build de terceiros roda). Gerado por `scripts/gerar_lock.py`
  (ferramenta de manutenção, com rede). Instalação:
  `python3 -m venv /opt/ppp-betim/venv && /opt/ppp-betim/venv/bin/pip install --require-hashes --only-binary=:all: --no-deps -r requirements.lock`.
  Suporte declarado: **CPython ≥ 3.11 (testado apenas em 3.13)**; PyPy não é suportado.
- **Verificável:** na inicialização (formato 2) o guardião confere, **antes de importar**
  `jsonschema`/`cryptography`: versão exata de cada dependência; hash de cada arquivo contra o
  RECORD; ausência de arquivos de código não listados; proteção dos diretórios do pacote, de cada
  entrada de `sys.path` e de `.pth`/`sitecustomize`/`usercustomize`; modo isolado (`-I`); e
  `-X pycache_prefix`. O mesmo vale para `python3 -I scripts/ambiente.py --lock requirements.lock`.
- **Limites:** o RECORD não é assinado; quem reescreve o pacote **e** o RECORD o engana — a barreira
  real é a propriedade/permissão dos diretórios. O interpretador, a biblioteca padrão e as
  bibliotecas de sistema (ex.: libffi) não são verificados por hash. Sem `-X pycache_prefix`,
  `.pyc` adulterado com a fonte intacta seria executado (demonstrado); com o prefixo, o bytecode
  em disco deixa de ser carregado.
- **Atualizar dependências:** regenerar o lock, revisar o diff, rodar a suíte no venv novo, e só
  então reinstalar como `root`.

## 5. Limites de recursos

Os valores abaixo são os padrões; o formato 2 aceita sobrescritas em `limites` (validadas pelo schema).

| Limite | Estrito (formato 2) | Legado (formato 1) |
|---|---|---|
| `max_requisicao_bytes` | 65 536 | 1 048 576 |
| `prazo_leitura_s` (total, por requisição) | 5 | 10 |
| `operacoes_por_minuto` / `rajada` (por uid) | 120 / 30 | 600 / 500 |
| `max_conexoes` / `max_conexoes_por_identidade` | 16 / 4 | 32 / 8 |
| `max_premissas` / `max_versoes_por_premissa` | 2 000 / 50 | 100 000 / 10 000 |
| `max_bytes_por_versao` / `max_bytes_total` | 16 KiB / 64 MiB | 1 MiB / 10 GiB |
| `max_checkpoints` / `max_bytes_checkpoints` | 2 000 / 256 MiB | 100 000 / 10 GiB |
| `intervalo_minimo_checkpoint_s` | 10 | 0 |

Comportamento: uid **sem papel** é recusado sem ler a requisição; excesso de frequência ou de
conexões recebe erro imediato (`LimiteExcedido`, `ServidorOcupado`); o balde é por uid, então
agentes que dividem um uid dividem a cota. O servidor atende conexões em threads com a escrita
serializada por trava, porque limitar a *contagem* de requisições não limita o *tempo* que um
cliente lento prenderia um servidor de thread única.

**Os limites são de aplicação, não de segurança do disco.** A barreira real contra esgotamento é
uma **cota/volume dedicado** para `/var/lib/ppp-betim` (medida de infraestrutura, não implementada
aqui). Uid em quantidade (um atacante que controle muitos uids) não é coberto.

## 6. Verificador independente de checkpoints

`scripts/verificar_ancora.py` é um arquivo único que não importa nada do projeto (só biblioteca
padrão e `cryptography`) e só **lê**. Uso:

```
verificar_ancora.py --chave-guardiao <64 hex> --checkpoints DIR_OU_ARQ [...]
                    [--inicio N] [--registros DIR] [--serie-minima N] [--json]
```

Confere, por checkpoint, formato estrito e assinatura; na cadeia, `seq` contíguo, encadeamento por
hash e monotonicidade (nada já ancorado some ou muda; a série do cadastro não diminui nem repete
com outro conteúdo). Com `--registros`, confronta o armazenamento atual com o último checkpoint.
Saída: `0` sem violações, `1` violações, `2` erro de uso/leitura.

Rotina recomendada: o ancorador solicita checkpoints periodicamente; um processo sem acesso do
agente os copia para o meio externo; o auditor roda o verificador **fora do host do guardião**,
com a chave pública do guardião obtida por outro canal.

**Limites:** só prova o que foi ancorado antes — o que ocorreu depois do último checkpoint externo
não é coberto; uma chave de guardião comprometida permite forjar checkpoints; os arquivos de
aprovação são conferidos por hash, **não** têm a assinatura revalidada; apagar toda a cadeia local
e recomeçar do `seq` 1 não deixa rastro local (só a cópia externa denuncia); é controle
**detectivo**, não impede nada.

## 7. Perfis estrito e legado; configuração de produção

Formato **1** (legado) continua aceito para compatibilidade com o GOV-03 e imprime
`AVISO: perfil legado` em `stderr`; **não** deve ir para produção. `--estrito` recusa o formato 1.
Chaves do formato 2 (`referencia_serie`, `limites`) em configuração de formato 1 são **recusadas**
(para não criar falsa sensação de proteção). Formato 2:

```json
{
  "formato": 2,
  "registros": "/var/lib/ppp-betim/registros",
  "aprovadores": "/etc/ppp-betim/aprovadores.json",
  "chave_raiz_governanca": "<64 hex da chave PÚBLICA da raiz>",
  "chave_privada_guardiao": "/var/lib/ppp-betim/guardiao.pem",
  "socket": "/run/ppp-betim/guardiao.sock",
  "referencia_serie": "/srv/ppp-betim-externo/referencia-serie.json",
  "proponentes": {"<uid agente P3>": "agente-p3"},
  "ancoradores": [<uid ancorador>],
  "limites": {}
}
```

`ExecStart` sugerido (**não testado**):
`/opt/ppp-betim/venv/bin/python -I -B -X pycache_prefix=/nonexistent /opt/ppp-betim/scripts/guardiao.py --estrito /etc/ppp-betim/guardiao.json`.
O restante da unidade segue o GOV-03, seção 7.

## 8. Compatibilidade

- Assinaturas existentes preservadas; parâmetros novos são **opcionais**: `carregar_aprovadores(..., politica_serie=None)`,
  `aprovacao.verificar(..., politica_serie=None)`, `RepositorioPremissas(..., politica_serie=None, limites=None)`,
  `ancora.emitir_checkpoint(..., cadastro=None)`, `Guardiao(..., estrito=False)`. O checkpoint ganha o campo
  opcional `cadastro`; checkpoints anteriores continuam válidos.
- `exigir_protegido` e `ConfiguracaoInsegura` foram movidos para `protecao.py` e continuam exportados por `guardiao`.
- **Mudanças de comportamento intencionais:** (1) `assinar-registro` passou a exigir `--anterior`,
  `--primeiro` ou `--sem-serie` (o antigo uso sem flags é recusado); (2) o guardião atende em threads
  e recusa uid sem papel sem ler a requisição (a mensagem de erro é a mesma); (3) a recuperação na
  inicialização remove temporários e pastas vazias e conclui checkpoint pela metade; (4) ele passou a
  recusar iniciar com `ultimo.json` ilegível ou à frente dos arquivos.
- Os 53 testes anteriores continuam passando **sem alteração de arquivo**.

## 9. Testes executados

Pacote gerado: **198 testes** (188 nos arquivos-fonte + 10 iniciais), todos aprovados em cerca de 1 minuto (Linux, root).
Os testes de integração (`test_robustez.py`, `test_fronteira.py`) exigem Linux e root e um Python que satisfaça o
`requirements.lock`; sem isso são **pulados** e a fronteira permanece não validada.

| Arquivo | Testes | Cobre |
|---|---|---|
| `test_aprovacao.py` | 8 | (anterior, GOV-02) |
| `test_premissas.py` | 14 | (anterior, GOV-01) |
| `test_fronteira.py` | 21 | (anterior, GOV-03) |
| `test_serie.py` | 19 | série crescente, replay, duplicada, ausente/inválida, referência ausente/adulterada, marca d'água, interrupção, reversão legítima |
| `test_limites.py` | 22 | balde de fichas, perfis, crescimento (bytes/versões/premissas/total), leitura com prazo e limite |
| `test_ambiente.py` | 29 | lock, marcadores, dependência ausente/incompatível, arquivo adulterado/apagado/injetado, permissões, `-I`/`pycache_prefix`, gerador do lock |
| `test_verificar_ancora.py` | 31 | checkpoint válido e inválido, regressões assinadas, armazenamento, independência da ferramenta |
| `test_assinatura_serie.py` | 12 | ferramenta do humano via pseudo-terminal (série que não aumenta, referência) |
| `test_robustez.py` | 32 | guardião real (formato 2): inicialização, replay em execução, ambiente, limites, checkpoints, recuperação, `kill -9` |
| Iniciais gerados (`test_estrutura.py`, `test_governanca.py`) | 10 | estrutura e governança inicial (inalterados) |

**Correspondência com a lista de validação pedida:** cadastro com série crescente (`test_serie`, `test_robustez`);
cadastro anterior reapresentado (idem, incluindo o ataque do R9 ponta a ponta); série duplicada; âncora externa
ausente e adulterada (na inicialização e em execução); checkpoint válido e inválido (`test_verificar_ancora`,
`test_robustez`); dependência ausente ou incompatível (`test_ambiente`, `test_robustez`); requisição acima do
limite; excesso de operações por identidade; interrupção durante gravação e recuperação sem perda de integridade
(`test_serie`, `test_robustez`, incluindo `kill -9`); preservação dos testes anteriores (arquivos idênticos,
todos passando); regeneração do pacote e verificação do ZIP (seção 9, abaixo).

### Controles negativos (falhas introduzidas deliberadamente)

Cada mutação enfraquece **um** controle numa cópia isolada do pacote e roda os testes pertinentes; o esperado é
que algum teste falhe. Resultado: **71 de 71 detectadas**.

Na primeira rodada (70 mutações) duas não foram detectadas — MS3 e ML6 —; foram acrescentados testes específicos e, numa segunda rodada na versão final, ambas passaram a ser detectadas, junto com a MG23 (teto de bytes de checkpoints, adicionado depois).

| Mutação | Controle enfraquecido | Resultado | Detectada por |
|---|---|---|---|
| MA1 | versão instalada não é comparada ao lock | detectada | `test_versao_incompativel` |
| MA2 | hash do RECORD não é conferido | detectada | `test_arquivo_adulterado_e_detectado_pelo_record` |
| MA3 | arquivo de código não listado é aceito | detectada | `test_arquivo_de_codigo_injetado_no_pacote` |
| MA4 | arquivo do RECORD ausente é aceito | detectada | `test_arquivo_removido_do_pacote` |
| MA5 | modo isolado não é exigido | detectada | `test_modo_isolado_exigido` |
| MA6 | pycache_prefix não é exigido | detectada | `test_bytecode_em_disco_exige_pycache_prefix` |
| MA7 | marcadores de ambiente são ignorados | detectada | `test_dependencia_com_marcador_falso_nao_e_exigida` |
| MA8 | proteção do diretório do pacote não é conferida | detectada | `test_arquivo_do_pacote_gravavel_por_terceiros_e_recusado`, `test_diretorio_do_pacote_gravavel_por_terceiros_e_recusado`, `test_link_simbolico_dentro_do_pacote_ |
| MA9 | proteção de .pth/sitecustomize não é conferida | detectada | `test_pth_e_sitecustomize_gravaveis_sao_recusados` |
| MA10 | RECORD lido de Distribution.files (omite arquivos apagados) | detectada | `test_arquivo_removido_do_pacote`, `test_sem_record_nao_ha_como_conferir` |
| MG1 | guardião não passa a política de série ao repositório | detectada | `test_referencia_removida_ou_adulterada_em_execucao_bloqueia`, `test_replay_de_cadastro_antigo_em_execucao_bloqueia_aprovacoes_e_checkpoints`, `test_serie_nova_ |
| MG2 | guardião não valida o cadastro ao iniciar | detectada | `test_inicia_com_cadastro_serie_e_referencia_coerentes`, `test_recusa_cadastro_antigo_reapresentado_antes_de_iniciar`, `test_recusa_cadastro_sem_serie`, `test_r |
| MG3 | ambiente Python não é verificado ao iniciar | detectada | `test_recusa_dependencia_ausente_ou_incompativel`, `test_recusa_lock_malformado`, `test_recusa_sem_modo_isolado_ou_sem_pycache_prefix` |
| MG4 | referência externa pode ser do próprio serviço | detectada | `test_recusa_referencia_sob_controle_do_proprio_guardiao` |
| MG5 | referência externa pode ficar dentro do armazenamento | detectada | `test_recusa_referencia_sob_controle_do_proprio_guardiao` |
| MG6 | limite de frequência não é aplicado | detectada | `test_excesso_de_operacoes_por_identidade_nao_afeta_outras_identidades` |
| MG7 | limite de frequência vira um único balde global | detectada | `test_excesso_de_operacoes_por_identidade_nao_afeta_outras_identidades` |
| MG8 | prazo de leitura vira 1 hora | detectada | `test_cliente_parado_recebe_erro_de_prazo_e_nada_e_gravado` |
| MG9 | teto de conexões por identidade removido | detectada | `test_limite_de_conexoes_por_identidade_e_global` |
| MG10 | teto global de conexões removido | detectada | `test_limite_de_conexoes_por_identidade_e_global` |
| MG11 | uid sem papel só é recusado depois de ler a requisição | detectada | `test_uid_sem_papel_e_recusado_sem_ler_a_requisicao` |
| MG12 | intervalo mínimo entre checkpoints ignorado | detectada | `test_limites_de_checkpoint_intervalo_e_quantidade` |
| MG13 | máximo de checkpoints ignorado | detectada | `test_limites_de_checkpoint_intervalo_e_quantidade` |
| MG14 | recuperação de checkpoints removida | detectada | `test_reinicio_recupera_temporarios_e_conclui_checkpoint_gravado_pela_metade`, `test_reinicio_recusa_cadeia_local_de_checkpoints_adulterada_ou_com_lacuna` |
| MG15 | ultimo.json à frente dos arquivos é aceito | detectada | `test_reinicio_recusa_cadeia_local_de_checkpoints_adulterada_ou_com_lacuna` |
| MG16 | checkpoint local adulterado é aceito | detectada | `test_reinicio_recusa_cadeia_local_de_checkpoints_adulterada_ou_com_lacuna` |
| MG17 | checkpoint não atesta o cadastro | detectada | `test_checkpoints_atestam_o_cadastro_e_passam_na_ferramenta_independente`, `test_replay_de_cadastro_antigo_em_execucao_bloqueia_aprovacoes_e_checkpoints` |
| MG18 | pastas vazias da queda não são recuperadas | detectada | `test_reinicio_recupera_temporarios_e_conclui_checkpoint_gravado_pela_metade` |
| MG19 | temporários da marca d'água não são recuperados | detectada | `test_reinicio_recupera_temporarios_e_conclui_checkpoint_gravado_pela_metade` |
| MG20 | schema aceita chaves do formato 2 no formato 1 | detectada | `test_formato_1_nao_aceita_chaves_do_formato_2` |
| MG21 | formato 2 não exige referência | detectada | `test_formato_2_exige_referencia` |
| MG22 | --estrito deixa de recusar o formato 1 | detectada | `test_estrito_recusa_formato_1_e_legado_inicia_com_aviso_explicito` |
| MG23 | teto de bytes do diretório de checkpoints removido | detectada | `test_limites_de_checkpoint_intervalo_e_quantidade` |
| MH1 | assinar-registro aceita série que não aumenta | detectada | `test_recusa_assinar_serie_que_diminui_ou_repete` |
| MH2 | assinar-registro dispensa --anterior/--primeiro | detectada | `test_recusa_cadastro_sem_serie_e_sem_referencia_de_comparacao` |
| MH3 | assinar-referencia aceita série mínima menor | detectada | `test_referencia_nao_diminui_nem_repete_com_outro_conteudo` |
| MH4 | assinar-referencia não confere a assinatura do cadastro | detectada | `test_referencia_exige_cadastro_assinado_pela_mesma_raiz_e_com_serie` |
| MH5 | assinar-registro não confere o cadastro anterior | detectada | `test_cadastro_anterior_de_outra_raiz_e_recusado` |
| ML1 | balde de fichas nunca recusa | detectada | `test_excesso_de_operacoes_por_identidade`, `test_identidades_sao_independentes`, `test_recusa_nao_consome_ficha_e_informa_a_espera`, `test_relogio_que_recua_na |
| ML2 | reposição ultrapassa a rajada | detectada | `test_reposicao_com_o_tempo_e_limite_pela_rajada` |
| ML3 | tabela de identidades cresce sem limite | detectada | `test_memoria_limitada_descarta_a_identidade_menos_recente` |
| ML5 | leitura sem limite de bytes | detectada | `test_limite_vale_mesmo_com_o_envio_em_pedacos`, `test_requisicao_acima_do_limite` |
| ML6 | leitura sem prazo total | detectada | `test_prazo_vencido_entre_duas_leituras_e_timeout_limpo_e_nao_valueerror` |
| MR1 | tamanho máximo da versão ignorado | detectada | `test_versao_acima_do_limite_de_bytes_e_recusada_sem_gravar` |
| MR2 | máximo de versões por premissa ignorado | detectada | `test_limite_de_versoes_por_premissa` |
| MR3 | máximo de premissas ignorado | detectada | `test_limite_de_premissas_nao_impede_novas_versoes_das_existentes` |
| MR4 | máximo total de bytes ignorado | detectada | `test_limite_total_de_bytes_conta_tambem_temporarios_orfaos` |
| MS1 | piso de série deixa de ser aplicado | detectada | `test_aprovador_revogado_nao_volta_por_replay_do_cadastro_antigo`, `test_cadastro_anterior_reapresentado_e_recusado`, `test_marca_dagua_corrompida_bloqueia_e_a_ |
| MS2 | série igual à da referência com outro hash é aceita | detectada | `test_serie_duplicada_contra_a_referencia_em_host_novo` |
| MS3 | série igual à da marca d'água com outro hash é aceita | detectada | `test_serie_duplicada_contra_a_marca_dagua_com_referencia_defasada` |
| MS4 | marca d'água nunca é gravada | detectada | `test_cadastro_anterior_reapresentado_e_recusado`, `test_interrupcao_na_gravacao_da_marca_dagua_nao_corrompe_e_recupera`, `test_marca_dagua_corrompida_bloqueia_ |
| MS5 | assinatura da referência não é verificada | detectada | `test_referencia_externa_adulterada_bloqueia` |
| MS6 | referência ausente/ilegível é tolerada | detectada | `test_referencia_externa_adulterada_bloqueia`, `test_referencia_externa_ausente_bloqueia` |
| MS7 | série ausente/inválida é aceita | detectada | `test_serie_ausente_ou_invalida` |
| MS8 | política de série aceita cadastro sem assinatura da raiz | detectada | `test_politica_exige_cadastro_assinado` |
| MS9 | carregar_aprovadores não consulta a política | detectada | `test_aprovador_revogado_nao_volta_por_replay_do_cadastro_antigo`, `test_cadastro_anterior_reapresentado_e_recusado`, `test_interrupcao_na_gravacao_da_marca_dag |
| MS10 | repositório não repassa a política ao verificar aprovações | detectada | `test_aprovador_revogado_nao_volta_por_replay_do_cadastro_antigo` |
| MS11 | marca d'água gravada sem troca atômica | detectada | `test_interrupcao_na_gravacao_da_marca_dagua_nao_corrompe_e_recupera` |
| MS12 | marca d'água corrompida é ignorada | detectada | `test_marca_dagua_corrompida_bloqueia_e_a_referencia_ainda_protege_apos_recuperacao` |
| MV1 | assinatura do checkpoint não é verificada | detectada | `test_assinatura_e_chave` |
| MV2 | encadeamento por hash não é conferido | detectada | `test_encadeamento_rompido_com_assinatura_valida` |
| MV3 | lacuna na sequência não é detectada | detectada | `test_lacuna_na_sequencia` |
| MV4 | versão ancorada removida não é detectada | detectada | `test_adulteracao_de_versao_e_lacuna_no_armazenamento`, `test_rollback_no_armazenamento_e_detectado`, `test_versao_ancorada_alterada`, `test_versao_ancorada_rem |
| MV5 | aprovação ancorada removida não é detectada | detectada | `test_aprovacao_ancorada_removida_ou_trocada`, `test_remocao_da_aprovacao_no_armazenamento_e_detectada` |
| MV6 | queda da série do cadastro não é detectada | detectada | `test_serie_do_cadastro_diminuiu` |
| MV7 | série repetida com outro conteúdo não é detectada | detectada | `test_serie_repetida_com_conteudo_diferente` |
| MV8 | formato do checkpoint não é validado | detectada | `test_formato_invalido` |
| MV9 | armazenamento atual não é comparado ao último checkpoint | detectada | `test_adulteracao_de_versao_e_lacuna_no_armazenamento`, `test_premissa_inteira_removida_do_armazenamento`, `test_remocao_da_aprovacao_no_armazenamento_e_detecta |
| MV10 | série mínima exigida não é conferida | detectada | `test_serie_minima_exigida` |
| MV11 | seq duplicado com conteúdo diferente é aceito | detectada | `test_seq_duplicado_identico_e_aceito_mas_diferente_e_violacao` |
| MV12 | ferramenta passa a importar módulo do projeto | detectada | `test_arquivos_diretos_e_ultimo_json_e_ignorado`, `test_chave_informada_invalida_e_erro_de_uso`, `test_ferramenta_nao_importa_modulos_do_projeto`, `test_funcion |

### Falhas e lacunas encontradas durante o desenvolvimento

Defeitos reais do código, encontrados pelos próprios testes e corrigidos:

1. **`importlib.metadata.Distribution.files` omite arquivos apagados (Python ≥ 3.12).** O verificador de
   ambiente usava essa lista; apagar um arquivo de uma dependência travada não era detectado. Achado pelo
   teste `test_arquivo_removido_do_pacote`; corrigido lendo o `RECORD` diretamente (mutação MA10 cobre).
2. **`.pyc` fora do RECORD abre uma via de injeção.** Demonstrado: com a fonte intacta, um `.pyc` adulterado
   é executado. Mitigado exigindo `-X pycache_prefix` (o bytecode em disco deixa de ser carregado); a
   ausência de hash para `.pyc` listados no RECORD permanece como limite (R21).
3. **Janela de queda do GOV-03 na ancoragem.** Gravar `seq-N.json` e atualizar `ultimo.json` não eram
   atômicos em conjunto; uma queda entre os dois travaria a ancoragem para sempre (`FileExistsError`).
   Corrigido com recuperação na inicialização, que **nunca** rebaixa a cadeia (`ultimo.json` à frente dos
   arquivos, adulterado ou ilegível é recusado).
4. **Pastas de premissa vazias após `kill -9`** consumiam o limite `max_premissas`. A criação da pasta não
   pôde ser evitada (um teste do GOV-01 depende de ela persistir); a recuperação passou a removê-las.
5. **Servidor de thread única + limites só de contagem** permitiam que um cliente lento (ou um uid sem
   papel) prendesse o guardião. Corrigido: threads com escrita serializada, prazo total de leitura, tetos
   de conexão por identidade e global, e recusa de uid sem papel sem ler a requisição.
6. **Lacuna no próprio R12:** `max_bytes_total` não cobria o diretório de checkpoints, cujo tamanho cresce
   com o estado. Adicionado `max_bytes_checkpoints`.
7. **Lacunas de cobertura reveladas pelos controles negativos:** a verificação "mesma série da marca d'água com
   outro conteúdo" (MS3) e a borda do prazo de leitura (ML6) passavam sem teste. Testes adicionados.

Defeitos **dos testes** (registrados por honestidade): um teste do R9 supunha que `estado()` consulta o
cadastro mesmo sem aprovação gravada (reescrito para o cenário real, com aprovação já gravada); dois testes do
verificador esperavam detectar a remoção de algo nunca ancorado antes (isso é impossível e agora é um teste
que documenta o limite); o teste de `kill -9` era estrito demais com a pasta vazia; um nome de cenário
duplicado; mensagens com caixa diferente.

## 10. Riscos residuais

| # | Risco | Situação |
|---|---|---|
| R9 | Replay de cadastro antigo assinado | **Mitigado** contra agente sem privilégio e, se a referência estiver em mídia independente, também contra o host do guardião (que só poderia reverter tudo junto). Se o atacante controla a referência **e** a marca d'água, o controle some; resta a detecção posterior pela série nos checkpoints ancorados |
| R10 | Dependências fora da verificação | **Mitigado** para as 9 distribuições travadas (versão, hash do RECORD, arquivos injetados, permissões, `-I`, `pycache_prefix`). Não cobre: interpretador e biblioteca padrão, bibliotecas de sistema (libffi), `.pyc` listados no RECORD sem hash (R21) |
| R12 | Consumo de recursos | **Mitigado na aplicação**; o limite real de disco é a **cota do SO** (infraestrutura, não implementada). Uids em quantidade e agentes que dividem um uid não são cobertos (R22) |
| R16 | Referência externa no mesmo host/disco que o guardião | Aberto (infraestrutura): sem mídia independente, `root` do host restaura referência, cadastro e marca d'água |
| R17 | Defasagem entre cadastro e referência | Aceito: publica-se o cadastro primeiro; referência à frente do cadastro bloqueia o guardião até o cadastro chegar |
| R18 | Série emitida por engano, alta demais, não pode ser reduzida | Aceito: corrige-se emitindo série ainda maior (custo operacional) |
| R19 | Raiz de governança comprometida | Fora do escopo: assinaria qualquer cadastro, referência ou série |
| R20 | Limites do verificador independente | Só cobre o já ancorado; chave de guardião comprometida forja checkpoints; aprovações conferidas por hash, sem revalidar assinatura; reset total da cadeia local só é denunciado pela cópia externa |
| R21 | RECORD não assinado; `.pyc` no RECORD sem hash; stdlib/libs de sistema | Aberto; depende da proteção do SO sobre os diretórios |
| R22 | Cota por uid; trava global serializa operações | Aberto: uma operação lenta atrasa as demais (limitada pelos limites); muitos uids contornam a cota por identidade |
| R23 | `max_checkpoints`/`max_bytes_checkpoints` atingidos bloqueiam a ancoragem | Aceito: exige arquivamento humano (disponibilidade, falha fechada) |
| R24 | Suporte e teste restritos a CPython 3.13 | Aberto: 3.11/3.12 previstos no lock (marcador de `typing-extensions`), mas não testados |
| R25 | Unidade systemd, cotas e permissões propostas | Não testadas (herda R15) |
| R26 | Suíte de integração exige Linux, root e o Python do lock | Fora disso é **pulada**: a validação não ocorre. A integração contínua deve rodar em contêiner root com o venv do lock |
| R27 | Ferramenta do humano: terminal e confirmação são atrito, não segurança | Herdado (R14): a barreira é a chave estar fora do host |
| R28 | Sincronizar a mídia externa com o caminho local lido pelo guardião | Administrativo: falha ou atraso resulta em indisponibilidade (falha fechada), não em aceitação indevida |

## 11. Implantação supervisionada (nada abaixo foi executado)

Cada etapa exige autorização humana específica; o agente não executa nenhuma delas. Complementa a seção 10
do GOV-03.

1. **Lock (mantenedor, com rede).** `python3 -I scripts/gerar_lock.py --saida requirements.lock <pins>`,
   revisar o diff contra o lock anterior e versionar.
2. **Venv de `root`.** `python3 -m venv /opt/ppp-betim/venv` e
   `pip install --require-hashes --only-binary=:all: --no-deps -r requirements.lock`; conferir com
   `python3 -I -X pycache_prefix=/nonexistent scripts/ambiente.py --exigir-isolado --exigir-sem-pyc`.
3. **Cerimônia da raiz (offline, duas pessoas).** Cadastro com `serie = 1`; `assinar-registro --primeiro`;
   depois `assinar-referencia --primeira`. Guardar a chave da raiz offline.
4. **Mídia externa da referência.** Disponibilizar o arquivo em meio que o agente **e** o host do guardião não
   reescrevam (somente leitura, WORM ou equivalente), montado em caminho de `root` fora de `registros/`.
5. **Configuração de formato 2 e unidade.** Seção 7, com `--estrito`; **cota de disco** (volume dedicado) para
   `/var/lib/ppp-betim`.
6. **Aceitação com as contas reais.** Executar `test_robustez.py` e `test_fronteira.py` (ajustando os uids)
   contra o runtime real do agente; anexar a saída. Qualquer falha crítica impede a homologação.
7. **Ancoragem.** Tarefa do ancorador (intervalo ≥ o mínimo configurado; sugerido 5–15 min) → cópia para o meio
   externo por processo sem acesso do agente → rotina do auditor com `verificar_ancora.py` (chave do
   guardião por outro canal). Simulado: apagar uma versão em homologação e confirmar a detecção.
8. **Operação.** Nova série (adicionar/revogar aprovador, reversão legítima, série emitida por engano),
   marca d'água perdida, referência perdida, arquivamento de checkpoints ao atingir o limite, atualização de
   dependências e rotação de chaves — procedimentos das seções 3 e 4.

Critérios de aceite: o log do serviço mostra `PRONTO` **sem** `AVISO: perfil legado`; o guardião recusa iniciar
sem a referência, com a referência adulterada, com cadastro de série menor e fora do lock; o verificador
independente retorna `0` sobre as cópias externas; as nove verificações adversariais do GOV-03 passam com as
contas reais.

## 12. Encaminhamento para revisão independente

A revisão deve ser feita por pessoa **independente de quem implementou**; o autor (um agente de IA) não pode
atestar o próprio trabalho, e o ambiente de desenvolvimento executa como `root`.

- **Escopo do diff:** `git diff afe7eff..HEAD` no ramo `claude/ppp-centro-scaffold-rybowl`. Fontes em
  `scripts/ppp-betim/pacote/`; o pacote gerado em `projects/` é derivado e deve ser idêntico à saída do gerador.
- **Onde olhar com mais rigor:** `serie.py` (regras do piso e da marca d'água), `ambiente.py` (leitura do RECORD,
  marcadores, proteção), `guardiao.py` (tratador de conexões, trava, recuperação, ordem "verificar antes de
  importar"), `verificar_ancora.py` (independência e monotonicidade), `limites.py`.
- **Perguntas para o revisor:** (1) a ordem das verificações em `carregar_configuracao` elimina de fato a janela
  entre verificar e importar? (2) há condição de corrida entre o servidor em threads e a marca d'água/`ultimo.json`?
  (3) o piso `max(referência, marca d'água)` cobre algum cenário de DR sem abrir brecha de replay? (4) o `RECORD`
  e a checagem de arquivos não listados cobrem as vias de injeção relevantes na plataforma-alvo? (5) os
  limites estritos são adequados ao volume real?
- **Reprodução:** instalar o lock num venv, `python3 gerar_projeto.py` (ou `python3 -m unittest discover -s testes`
  no pacote); como `root` em Linux roda a integração, sem isso ela é pulada.
- **O autor não verificou:** comportamento em outros sistemas operacionais ou versões de Python; a unidade
  systemd; cotas de disco; a mídia externa real; desempenho sob carga; o código de terceiros (apenas hashes e
  versões foram conferidos).
