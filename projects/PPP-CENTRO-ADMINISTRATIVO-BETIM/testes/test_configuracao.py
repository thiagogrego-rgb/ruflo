"""GOV-06: integridade da configuração e lançador de sessão (falha fechada contra deriva de configuração)."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COPIAR = (".claude", "governanca", "scripts")


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cfg-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.raiz = self.dir / "proj"
        for pasta in COPIAR:
            shutil.copytree(ROOT / pasta, self.raiz / pasta, ignore=shutil.ignore_patterns("__pycache__"))

    def verificar(self):
        r = subprocess.run([sys.executable, "-I", str(self.raiz / "scripts/verificar_configuracao.py")],
                           capture_output=True, text=True, timeout=60)
        return r.returncode, r.stderr

    def cfg(self):
        return json.loads((self.raiz / ".claude/settings.json").read_text(encoding="utf-8"))

    def grava_cfg(self, cfg):
        (self.raiz / ".claude/settings.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")


class TestVerificador(Base):
    def test_pacote_integro_passa(self):
        self.assertEqual(self.verificar(), (0, ""))

    def test_settings_invalido_ou_ilegivel(self):
        for conteudo in ('{"permissions": {', "", "[]", "null"):
            (self.raiz / ".claude/settings.json").write_text(conteudo, encoding="utf-8")
            with self.subTest(conteudo=conteudo):
                self.assertEqual(self.verificar()[0], 1)
        (self.raiz / ".claude/settings.json").unlink()
        self.assertEqual(self.verificar()[0], 1)

    def test_regra_deny_removida(self):
        cfg = self.cfg()
        cfg["permissions"]["deny"].remove("Edit(/registros/**)")
        self.grava_cfg(cfg)
        codigo, erro = self.verificar()
        self.assertEqual(codigo, 1)
        self.assertIn("Edit(/registros/**)", erro)

    def test_hook_removido_ou_sem_falha_fechada(self):
        cfg = self.cfg()
        cfg["hooks"] = {}
        self.grava_cfg(cfg)
        self.assertEqual(self.verificar()[0], 1)
        cfg = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
        cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = 'python3 "$CLAUDE_PROJECT_DIR/.claude/hooks/guarda_ferramentas.py"'
        self.grava_cfg(cfg)
        self.assertIn("exit 2", self.verificar()[1])

    def test_hook_sem_timeout_ou_matcher_estreito(self):
        base = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
        cfg = json.loads(json.dumps(base))
        del cfg["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"]
        self.grava_cfg(cfg)
        self.assertIn("timeout", self.verificar()[1])
        cfg = json.loads(json.dumps(base))
        cfg["hooks"]["PreToolUse"][0]["matcher"] = "Write|Edit"
        self.grava_cfg(cfg)
        self.assertIn("matcher", self.verificar()[1])

    def test_modo_permissivo_e_disable_all_hooks(self):
        for chave, valor in (("defaultMode", "bypassPermissions"), ("defaultMode", "acceptEdits")):
            cfg = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
            cfg["permissions"][chave] = valor
            self.grava_cfg(cfg)
            self.assertEqual(self.verificar()[0], 1)
        cfg = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
        cfg["disableAllHooks"] = True
        self.grava_cfg(cfg)
        self.assertEqual(self.verificar()[0], 1)

    def test_settings_local_e_recusado(self):
        (self.raiz / ".claude/settings.local.json").write_text('{"disableAllHooks": true}', encoding="utf-8")
        self.assertIn("settings.local.json", self.verificar()[1])

    def test_arquivos_alterados_ou_novos(self):
        alvos = [".claude/hooks/guarda_ferramentas.py", "governanca/matriz-agentes.json",
                 ".claude/agents/c-orquestrador.md", ".claude/skills/minutas-ppp/SKILL.md",
                 "scripts/iniciar_sessao.py"]
        for alvo in alvos:
            caminho = self.raiz / alvo
            original = caminho.read_bytes()
            caminho.write_bytes(original + b"\n# alterado\n")
            with self.subTest(alvo=alvo):
                codigo, erro = self.verificar()
                self.assertEqual(codigo, 1)
                self.assertIn(alvo, erro)
            caminho.write_bytes(original)
        (self.raiz / ".claude/agents/intruso.md").write_text("---\nname: intruso\n---\n", encoding="utf-8")
        self.assertIn("fora do manifesto", self.verificar()[1])

    def test_manifesto_ausente_ou_corrompido(self):
        manifesto = self.raiz / "governanca/manifesto-controles.json"
        manifesto.write_text("{", encoding="utf-8")
        self.assertEqual(self.verificar()[0], 1)
        manifesto.unlink()
        self.assertEqual(self.verificar()[0], 1)

    def test_gerar_aceita_mudanca_revisada(self):
        alvo = self.raiz / "governanca/matriz-agentes.json"
        alvo.write_bytes(alvo.read_bytes() + b"\n")
        self.assertEqual(self.verificar()[0], 1)
        r = subprocess.run([sys.executable, "-I", str(self.raiz / "scripts/verificar_configuracao.py"), "--gerar"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.verificar()[0], 0)


class TestLancador(Base):
    def lancar(self, *args):
        return subprocess.run([sys.executable, "-I", str(self.raiz / "scripts/iniciar_sessao.py"), *args],
                              capture_output=True, text=True, timeout=60)

    def test_comando_montado_com_controles_blindados(self):
        falso = self.dir / "bin"
        falso.mkdir()
        (falso / "claude").write_text("#!/bin/sh\n", encoding="utf-8")
        (falso / "claude").chmod(0o755)
        import os
        env = dict(os.environ, PATH=f"{falso}:{os.environ['PATH']}")
        r = subprocess.run([sys.executable, "-I", str(self.raiz / "scripts/iniciar_sessao.py"), "--dry-run",
                            "--agent", "c-orquestrador"], capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        partes = r.stdout.split()
        self.assertIn("--settings", partes)
        self.assertEqual(partes[partes.index("--setting-sources") + 1], "user,project")   # sem a fonte `local`
        self.assertEqual(partes[partes.index("--agent") + 1], "c-orquestrador")
        self.assertTrue(partes[0].endswith("/claude"))

    def test_opcao_sandbox_soma_o_bloco_testado_sem_tocar_no_settings_entregue(self):
        falso = self.dir / "bin2"
        falso.mkdir()
        (falso / "claude").write_text("#!/bin/sh\n", encoding="utf-8")
        (falso / "claude").chmod(0o755)
        import os
        env = dict(os.environ, PATH=f"{falso}:{os.environ['PATH']}")
        antes = (self.raiz / ".claude/settings.json").read_bytes()
        r = subprocess.run([sys.executable, "-I", str(self.raiz / "scripts/iniciar_sessao.py"), "--dry-run", "--sandbox"],
                           capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        partes = r.stdout.split()
        temporario = Path(partes[partes.index("--settings") + 1])
        try:
            cfg = json.loads(temporario.read_text(encoding="utf-8"))
        finally:
            temporario.unlink()
        self.assertTrue(cfg["sandbox"]["enabled"])
        self.assertTrue(cfg["sandbox"]["failIfUnavailable"])
        self.assertIn("PreToolUse", cfg["hooks"])                       # os controles continuam presentes
        self.assertEqual((self.raiz / ".claude/settings.json").read_bytes(), antes)

    def test_recusa_iniciar_com_configuracao_comprometida(self):
        (self.raiz / ".claude/settings.json").write_text("{", encoding="utf-8")
        r = self.lancar("--dry-run")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("NÃO iniciada", r.stderr)
        self.assertEqual(r.stdout, "")


if __name__ == "__main__":
    unittest.main()
