# Piloto GOV-09 — rodada `r1`

- Modo: **laboratorio-modelo-simulado**
- Início: 2026-10-25T02:45:50+0000 — duração 58.0 s
- Credencial: canário sintético (laboratório)

| Cenário | Resultado | O que prova |
|---|---|---|
| S01 | **PASSOU** | Claude Code como usuário sem privilégios |
| S02 | **PASSOU** | Contas e permissões por papel (sistema real) |
| S03 | **PASSOU** | Inicialização segura por mecanismo controlado |
| S04 | **NAO_EXECUTADO** | Comunicação real com a API pelo gateway |
| S05 | **PASSOU** | Proteção da credencial |
| S05b | **PASSOU** | Credencial rotacionada ausente de argv/ambiente/arquivos após o piloto |
| S06 | **PASSOU** | Restrições de rede (namespace vazio + gateway) |
| S07 | **PASSOU** | Integridade e armazenamento protegido dos logs |
| S07b | **PASSOU** | Integridade dos logs após os testes de falha |
| S08 | **PASSOU** | Dez agentes e dezenove skills em execução real (modelo simulado) |
| S09 | **PASSOU** | Falha e recuperação (F1–F6) |

Chamada real ao provedor (S04): **NAO_EXECUTADO**

## S04 — NAO_EXECUTADO
```json
{
 "motivo": "execução em modo laboratório com modelo simulado: nenhuma chamada real foi feita",
 "credencial_provisionada": true
}
```
