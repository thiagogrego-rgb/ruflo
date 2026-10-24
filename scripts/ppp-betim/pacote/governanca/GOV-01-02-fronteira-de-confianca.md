# GOV-01 e GOV-02 — Integridade de premissas e aprovação humana

**Estado:** implementado e testado com dados sintéticos. **Não homologado.**
A proteção só é efetiva com os controles externos da seção 4 configurados.

> **Atualização (GOV-03):** o serviço guardião, o papel `ancoradores`, a âncora de
> checkpoints e a revisão dos riscos R1–R5 estão em `GOV-03-fronteira-efetiva.md`.
> Este documento descreve a base (GOV-01/02) e permanece válido.

## 1. Componentes

| Arquivo | Função |
|---|---|
| `governanca/schemas/premissa.schema.json` | Contrato da premissa proposta (Draft 2020-12) |
| `governanca/schemas/aprovacao.schema.json` | Formato da aprovação assinada |
| `governanca/schemas/aprovadores.schema.json` | Formato do registro de aprovadores |
| `governanca/aprovadores.json` | Âncora de confiança: aprovadores humanos e chaves públicas (distribuído vazio) |
| `scripts/governanca.py` | Validação pelo schema e regras complementares |
| `scripts/premissas_repositorio.py` | Armazenamento append-only com cadeia de hashes |
| `scripts/aprovacao.py` | Verificação de aprovações Ed25519 |
| `scripts/assinar_aprovacao.py` | Ferramenta do aprovador humano (gerar chave, assinar) |
| `testes/test_premissas.py`, `testes/test_aprovacao.py` | Testes de GOV-01 e GOV-02 |

Dependências: `requirements.txt` (`jsonschema`, `cryptography`). Sem elas a
validação e a autorização falham fechadas: nada é registrado nem aprovado.

## 2. Regras implementadas

**GOV-01 — premissas**

- Toda premissa é validada pelo JSON Schema. Uma única fonte de regras de formato.
- `versao` é inteiro ≥ 1; booleanos, textos, decimais e nulos são rejeitados.
- `OBSERVADO`/`CALCULADO` exigem `fonte_id`, e a fonte precisa existir em
  `registros/fontes/<fonte_id>.json`. `HIPOTESE` exige justificativa não vazia.
- Identificadores têm padrão fixo (`PREM-NNN`, `FONTE-NNN`), o que impede
  travessia de diretórios ao montar caminhos.
- O único status registrável é `PROPOSTA`. `APROVADA` nunca é declarado no
  conteúdo; é derivado de uma aprovação assinada válida. Os estados
  intermediários da política (EM_VERIFICACAO, VERIFICADA, REJEITADA,
  SUBSTITUIDA) ainda não têm evento próprio — pendência.
- Cada versão é um arquivo imutável `v<N>.json`, gravado por link atômico que
  falha se o destino existir: não há sobrescrita pelo código, nem de versão nem
  de aprovação. A versão N+1 só é aceita sobre a N; escritores concorrentes
  recebem `ConflitoVersao`.
- Cada versão guarda o SHA-256 da anterior. A cadeia é reverificada em toda
  leitura; alteração, corrupção ou lacuna resulta em `IntegridadeViolada`.
- Gravação interrompida nunca deixa arquivo final parcial; restam apenas
  temporários `.*.tmp`, removidos por `recuperar()`.

**GOV-02 — aprovação**

- A aprovação é um payload `{premissa_id, versao, sha256_versao, aprovador_id,
  emitida_em, decisao}` assinado com Ed25519 pela chave privada do aprovador.
- É aceita somente se: o formato confere com o schema; o payload aponta para
  exatamente aquela versão e aquele conteúdo; o aprovador consta como humano
  ativo no registro, com papel `aprovador-premissas` e o produto da premissa;
  o aprovador não é o proponente da versão; e a assinatura confere.
- A verificação é refeita a cada leitura (`estado`, `ler_aprovada`). Desativar
  um aprovador invalida, a partir daí, as aprovações dele.
- Falha do mecanismo (registro ausente, corrompido ou inválido, dependência
  ausente) levanta `AutorizacaoIndisponivel`; nenhuma versão é tratada como
  aprovada.
- Decisões gerais (`aprovar_decisao`) e publicação (`autorizar_publicacao`)
  continuam bloqueadas.

## 3. Fronteira de confiança

```
 CONFIÁVEL (fora do alcance do agente)         NÃO CONFIÁVEL (agente)
 ─────────────────────────────────────         ──────────────────────────
 chave privada do aprovador                    propor versões
 terminal do aprovador                         ler registros
 governanca/aprovadores.json (revisado)        copiar aprovações assinadas
 código de verificação (revisado)              tudo que o usuário do SO permitir
```

Separação de direitos, tecnicamente:

- **Propor** = escrever em `registros/premissas/` pelo repositório. Qualquer
  processo com escrita no diretório pode fazê-lo; o campo `proponente` é
  declarado, não autenticado.
- **Aprovar** = possuir a chave privada correspondente a uma chave pública do
  registro. Sem a chave, produzir uma aprovação aceita exige quebrar Ed25519.

A segunda afirmação só vale se o agente **não puder alterar** o registro de
aprovadores, o código verificador nem o ambiente Python. Um agente com
escrita nesses arquivos pode incluir a própria chave ou desativar a
verificação. Hooks, prompts e a lista `tools:` dos agentes **não** garantem
esse isolamento: a sessão principal do Claude Code executa `Bash` com os
direitos do usuário.

## 4. Permissões necessárias para proteção efetiva

1. Chave privada fora do projeto e da máquina do agente (preferencialmente em
   token de hardware), protegida por frase-senha. `assinar_aprovacao.py`
   recusa chaves dentro do projeto e exige terminal interativo — atrito, não
   segurança.
2. `governanca/`, `scripts/` e o interpretador Python sem permissão de escrita
   para o usuário do SO que executa o agente (outro dono, montagem somente
   leitura ou contêiner com volume `:ro`).
3. `registros/premissas/` gravável pelo agente apenas por meio do repositório;
   alterações diretas são detectadas, não impedidas.
4. Toda mudança em `governanca/aprovadores.json` revisada por humano em
   branch protegida do git (âncora externa).
5. Âncora externa para o histórico — ver risco R1.

## 5. Riscos residuais

| # | Risco | Situação |
|---|---|---|
| R1 | Remover a última versão e sua aprovação (rollback) não deixa rastro local | Aberto. `registros/` está fora do git (`.gitignore`); requer checkpoint assinado ou cópia em local somente-anexação |
| R2 | Versões não aprovadas podem ser reescritas com a cadeia recalculada | Aceito: hash sem assinatura não prova autoria; só a aprovação assinada protege conteúdo |
| R3 | `proponente` é declarado; a segregação proponente ≠ aprovador depende dessa declaração | Aberto. Requer identidade autenticada do proponente |
| R4 | Agente com escrita em `governanca/aprovadores.json` ou no código anula GOV-02 | Mitigado apenas pelos controles externos da seção 4 |
| R5 | Neste ambiente de teste o processo roda como root; `chmod 0444` não impede escrita | Os testes verificam detecção, não bloqueio |
| R6 | `recuperar()` concorrente a uma gravação pode abortá-la (sem corromper) | Executar sem gravações em curso |
| R7 | Sistemas de arquivos sem hard link (ex.: FAT) não suportam a gravação atômica | Usar NTFS, ext4, APFS ou equivalente |
| R8 | Aprovação continua válida se a fonte citada for removida depois | Aberto |

## 6. Pendências de homologação

- Configurar e testar os controles externos da seção 4 no ambiente real.
- Cadastrar aprovadores reais e testar `assinar_aprovacao.py` em terminal.
- Âncora externa para o histórico (R1) e identidade do proponente (R3).
- Eventos para os estados intermediários e registro formal de fontes.
- Revisão independente deste código antes do uso com dados reais.
