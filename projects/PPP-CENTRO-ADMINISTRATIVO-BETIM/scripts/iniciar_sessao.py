#!/usr/bin/env python3
"""Lançador de sessão do Claude Code com os controles de GOV-05/06 blindados contra deriva de configuração.

1. Recusa iniciar se `verificar_configuracao.py` encontrar qualquer problema.
2. Passa os controles por `--settings` (precedência acima de projeto e local) e ignora a fonte `local`
   (`--setting-sources user,project`), de modo que `settings.json` do projeto corrompido ou
   `settings.local.json` com `disableAllHooks` não desliguem o guarda (medido em GOV-06).

Uso:  python3 scripts/iniciar_sessao.py [--dry-run] [--sandbox] [opções do claude, ex.: --agent c-orquestrador]

--sandbox  soma o bloco de governanca/sandbox-recomendado.json (barreira de SO para o terminal) num arquivo
           temporário de settings; exige bubblewrap+socat (Linux/WSL2) ou macOS e FALHA se faltarem.

Não substitui o isolamento de SO nem autentica o usuário. Settings gerenciados (da organização), se
existirem, continuam com precedência sobre estes.
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verificar_configuracao as V  # noqa: E402


def settings_com_sandbox():
    base = json.loads((V.RAIZ / ".claude/settings.json").read_text(encoding="utf-8"))
    base.update(json.loads((V.RAIZ / "governanca/sandbox-recomendado.json").read_text(encoding="utf-8")))
    fd, caminho = tempfile.mkstemp(prefix="ppp-settings-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(base, f, ensure_ascii=False)
    return caminho


def montar(argumentos, claude=None, sandbox=False):
    problemas = V.verificar()
    if problemas:
        raise SystemExit("Sessão NÃO iniciada:\n  - " + "\n  - ".join(problemas))
    claude = claude or shutil.which("claude")
    if not claude:
        raise SystemExit("executável 'claude' não encontrado no PATH")
    settings = settings_com_sandbox() if sandbox else str(V.RAIZ / ".claude/settings.json")
    return [claude, "--settings", settings,
            "--setting-sources", "user,project", *argumentos]


def main(argv):
    seco = "--dry-run" in argv
    comando = montar([a for a in argv if a not in ("--dry-run", "--sandbox")], sandbox="--sandbox" in argv)
    if seco:
        print(" ".join(comando))
        return 0
    os.chdir(V.RAIZ)
    os.execv(comando[0], comando)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
