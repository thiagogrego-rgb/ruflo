# Parecer das revisões independentes (GOV-09)

Natureza: duas revisões **estáticas** (leitura de código e de evidência) por agentes de contexto limpo, somente leitura, sem acesso ao ambiente instalado.
**Não é** revisão dinâmica nem pentest, e foi encomendada pela mesma sessão que produziu o código (independência limitada: sem separação humana).

## A. Segurança do código novo (agente `security-auditor`)
Achados confirmados e corrigidos: revogação não derrubava o gateway; config de laboratório podia chegar ao modo real; `shell=True` como root; `instalar` seguindo links/apagando logs/trocando código com serviços no ar.
Parcialmente corrigidos ou declarados: DoS por gotejamento de cabeçalho (R-05), âncoras no mesmo host e cauda não ancorada (R-02/R-03), proxy `http` e CA corporativa (R-04), cabeçalhos por prefixo (R-07).
Verificado sem achado: gravação atômica da credencial (`O_EXCL|O_NOFOLLOW`, `fchown` antes do `replace`), chave fora de argv/ambiente, leitura de chave/proxy por fd, evidências sem `sk-ant`/canário completo.

## B. Validade das evidências (agente `reviewer`)
Veredito inicial: os JSON sustentavam "controles funcionam em laboratório com modelo simulado", **não** nada sobre homologação ou chamada real; vários testes aceitavam "qualquer erro" como bloqueio.
Corrigido: S08 passou a ler as decisões do guardião (log encadeado) e casar resultados por `tool_use_id`; S03 exige a mensagem esperada (e o caso `sem_root` passou a ser realmente lido pelo lançador); S05 ganhou controle positivo; S02 verifica contagens;
S10 exige rótulo/início distintos, mesmo modo e mesmo código instalado e não conta NÃO EXECUTADO como reproduzido; relatório traz a linha fixa "Escopo: LABORATÓRIO; homologação: NÃO realizada".
Mantido como limite declarado: S01 só p3; F5 adultera cópia; F6 tolerante; S08 não prova julgamento dos agentes; verificação "revisor mecânico" do cenário integrado **recalcula a mesma função** (fraca) — o cálculo é conferido de forma independente nos testes unitários.

## C. O que este parecer NÃO cobre
Execução com modelo real, rede/proxy reais, systemd/firewall, volume, injeção de prompt adversarial e o Claude Chat. Recomenda-se revisão dinâmica por pessoa independente na homologação.
