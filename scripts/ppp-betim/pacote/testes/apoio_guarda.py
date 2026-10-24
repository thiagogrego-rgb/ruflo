"""Apoio dos testes do guarda (GOV-05/06): projeto falso em diretório temporário com o guarda e a matriz reais."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS_ORIGEM = ROOT / ".claude" / "hooks"
MATRIZ_ORIGEM = ROOT / "governanca" / "matriz-agentes.json"
AREAS = ("dados", "registros", "governanca", ".claude", "scripts", "testes",
         "arquitetura", "referencias", "logs", "projects")


class ProjetoFalso:
    """Cópia mínima do esqueleto do projeto com o guarda e a matriz reais."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="guarda-"))
        self.raiz = self.dir / "proj"
        (self.raiz / ".claude" / "hooks").mkdir(parents=True)
        (self.raiz / "governanca").mkdir()
        for modulo in sorted(HOOKS_ORIGEM.glob("*.py")):
            shutil.copy(modulo, self.raiz / ".claude" / "hooks" / modulo.name)
        shutil.copy(MATRIZ_ORIGEM, self.raiz / "governanca" / "matriz-agentes.json")
        for d in ("produtos/P3", "produtos/P4", "produtos/C", "registros/decisoes",
                  "dados/restritos", "dados/entrada", "scripts", "testes", "referencias"):
            (self.raiz / d).mkdir(parents=True)
        (self.raiz / "registros/decisoes/DEC-001.json").write_text("{}", encoding="utf-8")
        (self.raiz / "CLAUDE.md").write_text("x", encoding="utf-8")
        (self.raiz / "scripts/ok.py").write_text("print(1)", encoding="utf-8")
        (self.raiz / "logs").mkdir()
        for arq in ("dados/restritos/r.txt", "dados/entrada/e.txt", "logs/l.log", "registros/decisoes/d.json"):
            (self.raiz / arq).write_text("x", encoding="utf-8")
        self.hook = self.raiz / ".claude" / "hooks" / "guarda_ferramentas.py"

    def chama(self, evento, bruto=None):
        entrada = bruto if bruto is not None else json.dumps(evento)
        r = subprocess.run([sys.executable, "-I", str(self.hook)], input=entrada, text=True,
                           capture_output=True, cwd=self.raiz, timeout=30)
        return r.returncode, r.stdout, r.stderr

    def escrita(self, caminho, agente=None, ferramenta="Write", campo="file_path"):
        ev = {"hook_event_name": "PreToolUse", "tool_name": ferramenta, "cwd": str(self.raiz),
              "tool_input": {campo: str(caminho)}}
        if agente:
            ev["agent_type"] = agente
        return self.chama(ev)[0]

    def leitura(self, ferramenta, agente=None, **entrada):
        ev = {"tool_name": ferramenta, "cwd": str(self.raiz), "tool_input": entrada}
        if agente:
            ev["agent_type"] = agente
        return self.chama(ev)[0]

    def skill(self, nome, agente=None):
        ev = {"tool_name": "Skill", "cwd": str(self.raiz), "tool_input": {"skill": nome}}
        if agente:
            ev["agent_type"] = agente
        return self.chama(ev)[0]

    def bash(self, comando, agente=None):
        ev = {"tool_name": "Bash", "cwd": str(self.raiz), "tool_input": {"command": comando}}
        if agente:
            ev["agent_type"] = agente
        return self.chama(ev)

    def limpa(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class Base(unittest.TestCase):
    def setUp(self):
        self.p = ProjetoFalso()
        self.addCleanup(self.p.limpa)
