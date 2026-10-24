"""GOV-05: permissões de escrita, escopo por agente, skills e guarda de ferramentas.

O guarda é exercitado como subprocesso (exatamente como o Claude Code o chama) dentro de um
projeto falso em diretório temporário, para que nenhum teste toque no pacote real.
Cobre a camada de ferramentas; o comportamento no runtime real é verificado à parte
(`governanca/GOV-05-permissoes-e-skills.md`) e NÃO é provado por estes testes.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK_ORIGEM = ROOT / ".claude" / "hooks" / "guarda_ferramentas.py"
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
        shutil.copy(HOOK_ORIGEM, self.raiz / ".claude" / "hooks" / HOOK_ORIGEM.name)
        shutil.copy(MATRIZ_ORIGEM, self.raiz / "governanca" / "matriz-agentes.json")
        for d in ("produtos/P3", "produtos/P4", "produtos/C", "registros/decisoes",
                  "dados/restritos", "dados/entrada", "scripts", "testes", "referencias"):
            (self.raiz / d).mkdir(parents=True)
        (self.raiz / "registros/decisoes/DEC-001.json").write_text("{}", encoding="utf-8")
        (self.raiz / "CLAUDE.md").write_text("x", encoding="utf-8")
        (self.raiz / "scripts/ok.py").write_text("print(1)", encoding="utf-8")
        self.hook = self.raiz / ".claude" / "hooks" / HOOK_ORIGEM.name

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


class TestEscrita(Base):
    def test_escrita_legitima_na_area_do_proprio_agente(self):
        self.assertEqual(self.p.escrita(self.p.raiz / "produtos/P3/minuta.md", "p3-mercado"), 0)
        self.assertEqual(self.p.escrita("produtos/P3/novo/sub/arquivo.md", "p3-mercado"), 0)
        self.assertEqual(self.p.escrita(self.p.raiz / "produtos/C/plano.md", "c-orquestrador"), 0)
        self.assertEqual(self.p.escrita(self.p.raiz / "produtos/C/dr.md", "controlador-dr"), 0)

    def test_sessao_principal_grava_em_qualquer_produto(self):
        self.assertEqual(self.p.escrita("produtos/P4/x.md"), 0)

    def test_agente_nao_grava_na_area_de_outro(self):
        self.assertEqual(self.p.escrita("produtos/P4/x.md", "p3-mercado"), 2)
        self.assertEqual(self.p.escrita("produtos/P3/../P4/x.md", "p3-mercado"), 2)

    def test_areas_protegidas_por_caminho_relativo_e_absoluto(self):
        for destino in ("registros/decisoes/DEC-002.json", "dados/restritos/x.txt",
                        "dados/entrada/x.txt", "governanca/aprovadores.json",
                        ".claude/settings.json", ".claude/agents/c-orquestrador.md",
                        ".claude/hooks/guarda_ferramentas.py", "scripts/ok.py", "testes/t.py",
                        "referencias/r.md", "CLAUDE.md", "logs/guarda.jsonl", "novo-no-raiz.md"):
            for forma in (destino, str(self.p.raiz / destino), "./" + destino):
                with self.subTest(destino=forma):
                    self.assertEqual(self.p.escrita(forma), 2)
                    self.assertEqual(self.p.escrita(forma, "p3-mercado"), 2)

    def test_sobrescrever_registro_existente_e_recusado(self):
        self.assertEqual(self.p.escrita("registros/decisoes/DEC-001.json", "c-orquestrador"), 2)

    def test_variantes_de_caminho(self):
        for destino in ("produtos/../registros/x.json", "produtos/P3/../../dados/restritos/x",
                        "./produtos/./P3/../../registros/x", "Registros/x.json",
                        "REGISTROS/decisoes/x.json", "Dados/Restritos/x", "Produtos/P3/x.md",
                        "produtos/p3/x.md", "produtos//../registros//x"):
            with self.subTest(destino=destino):
                self.assertEqual(self.p.escrita(destino, "p3-mercado"), 2)

    def test_symlink_para_area_protegida(self):
        os.symlink(self.p.raiz / "registros", self.p.raiz / "produtos/P3/atalho")
        os.symlink(self.p.raiz / "registros/decisoes/DEC-001.json",
                   self.p.raiz / "produtos/P3/dec.json")
        self.assertEqual(self.p.escrita("produtos/P3/atalho/decisoes/DEC-009.json", "p3-mercado"), 2)
        self.assertEqual(self.p.escrita("produtos/P3/dec.json", "p3-mercado"), 2)
        self.assertEqual(self.p.escrita("produtos/P3/atalho/novo.json"), 2)

    def test_fora_do_projeto_e_formas_invalidas(self):
        for destino in ("/tmp/fora.txt", "~/fora.txt", "../fora.txt", "", "   ", "a\0b"):
            with self.subTest(destino=destino):
                self.assertEqual(self.p.escrita(destino, "p3-mercado"), 2)
        self.assertEqual(self.p.chama({"tool_name": "Write", "tool_input": {}})[0], 2)
        self.assertEqual(self.p.chama({"tool_name": "Write", "tool_input": {"file_path": 7}})[0], 2)

    def test_arquivo_direto_em_produtos_sem_area_e_recusado(self):
        self.assertEqual(self.p.escrita("produtos/README.md", "p3-mercado"), 2)
        self.assertEqual(self.p.escrita("produtos/P3", "p3-mercado"), 2)

    def test_revisor_e_agente_desconhecido_nao_gravam(self):
        self.assertEqual(self.p.escrita("produtos/C/x.md", "revisor-independente"), 2)
        self.assertEqual(self.p.escrita("produtos/P3/x.md", "general-purpose"), 2)

    def test_demais_ferramentas_de_edicao(self):
        self.assertEqual(self.p.escrita("registros/x.json", "p3-mercado", "Edit"), 2)
        self.assertEqual(self.p.escrita("registros/x.json", "p3-mercado", "MultiEdit"), 2)
        self.assertEqual(self.p.escrita("registros/n.ipynb", "p3-mercado", "NotebookEdit",
                                        "notebook_path"), 2)
        self.assertEqual(self.p.escrita("produtos/P3/n.ipynb", "p3-mercado", "NotebookEdit",
                                        "notebook_path"), 0)
        self.assertEqual(self.p.escrita("produtos/P3/e.md", "p3-mercado", "Edit"), 0)

    def test_leitura_nao_e_guardada(self):
        for ferramenta in ("Read", "Grep", "Glob"):
            ev = {"tool_name": ferramenta, "agent_type": "p3-mercado", "cwd": str(self.p.raiz),
                  "tool_input": {"file_path": str(self.p.raiz / "registros/decisoes/DEC-001.json")}}
            self.assertEqual(self.p.chama(ev)[0], 0, ferramenta)


class TestFalhaFechada(Base):
    def test_entrada_invalida_recusa(self):
        for bruto in ("", "não é json", "[]", "null", '{"tool_name": 3}', "{}"):
            with self.subTest(bruto=bruto):
                self.assertEqual(self.p.chama(None, bruto)[0], 2)

    def test_matriz_ausente_ou_corrompida_recusa(self):
        matriz = self.p.raiz / "governanca/matriz-agentes.json"
        for conteudo in (None, "{", "[]", '{"agentes": {}}', '{"agentes": 3}'):
            if conteudo is None:
                matriz.unlink()
            else:
                matriz.write_text(conteudo, encoding="utf-8")
            with self.subTest(conteudo=conteudo):
                self.assertEqual(self.p.escrita("produtos/P3/x.md", "p3-mercado"), 2)
                self.assertEqual(self.p.skill("value-for-money", "p4-modelagem"), 2)

    def test_recusa_gera_log_rastreavel(self):
        self.p.escrita("registros/decisoes/DEC-003.json", "p3-mercado")
        self.p.escrita("produtos/P3/ok.md", "p3-mercado")
        linhas = [json.loads(x) for x in
                  (self.p.raiz / "logs/guarda.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([x["decisao"] for x in linhas], ["recusado", "permitido"])
        self.assertEqual(linhas[0]["agente"], "p3-mercado")
        self.assertEqual(linhas[0]["ferramenta"], "Write")
        self.assertIn("protegida", linhas[0]["motivo"])

    def test_falha_ao_gravar_log_nao_libera(self):
        (self.p.raiz / "logs").write_text("arquivo no lugar da pasta", encoding="utf-8")
        self.assertEqual(self.p.escrita("registros/x", "p3-mercado"), 2)
        self.assertEqual(self.p.escrita("produtos/P3/x.md", "p3-mercado"), 0)


class TestSkills(Base):
    def test_skill_autorizada_e_nao_autorizada(self):
        self.assertEqual(self.p.skill("value-for-money", "p4-modelagem"), 0)
        self.assertEqual(self.p.skill("/value-for-money", "p4-modelagem"), 0)
        self.assertEqual(self.p.skill("minutas-ppp", "p4-modelagem"), 2)
        self.assertEqual(self.p.skill("minutas-ppp", "p5-juridico"), 0)
        self.assertEqual(self.p.skill("apresentacao-padrao-ceabe", "c-orquestrador"), 0)
        self.assertEqual(self.p.skill("apresentacao-padrao-ceabe", "p4-modelagem"), 2)

    def test_skills_comuns_a_todos(self):
        for agente in json.loads(MATRIZ_ORIGEM.read_text(encoding="utf-8"))["agentes"]:
            for skill in ("ingestao-data-request", "base-premissas", "verificacao-independente"):
                with self.subTest(agente=agente, skill=skill):
                    self.assertEqual(self.p.skill(skill, agente), 0)

    def test_skills_externas_ou_de_configuracao_sao_recusadas(self):
        for nome in ("update-config", "anthropic-skills:pdf", "anthropic-skills:docx", "run",
                     "VALUE-FOR-MONEY", "value-for-money:x", "", None):
            with self.subTest(nome=nome):
                self.assertEqual(self.p.skill(nome, "p4-modelagem"), 2)

    def test_agente_fora_da_matriz_nao_invoca_skills(self):
        self.assertEqual(self.p.skill("base-premissas", "general-purpose"), 2)
        self.assertEqual(self.p.skill("base-premissas", "Explore"), 2)

    def test_sessao_principal_nao_e_restringida(self):
        self.assertEqual(self.p.skill("value-for-money"), 0)


class TestTerminalEConectores(Base):
    def test_subagente_nunca_executa_comando(self):
        for agente in ("p3-mercado", "general-purpose", "revisor-independente"):
            self.assertEqual(self.p.bash("ls", agente)[0], 2)

    def test_leituras_e_comandos_comuns_continuam_permitidos(self):
        for cmd in ("ls registros", "cat governanca/matriz-agentes.json", "grep -r x registros",
                    "git status", "git log --oneline", "touch produtos/P3/novo.md",
                    "cp registros/decisoes/DEC-001.json produtos/P3/copia.json",
                    "ls registros > produtos/P3/lista.txt", "echo ok 2>&1",
                    "python3 scripts/ok.py registros", "python3 -I -X utf8 scripts/ok.py",
                    "python3 -m unittest discover testes", "head -3 dados/restritos/x",
                    "find registros -name '*.json'", "sed -n 1,5p governanca/matriz-agentes.json",
                    "timeout 5 ls registros"):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.p.bash(cmd)[0], 0, self.p.bash(cmd)[2])

    def test_escrita_em_area_protegida_por_terminal_e_recusada(self):
        for cmd in ("echo x > registros/decisoes/DEC-002.json", "echo x >> dados/restritos/a",
                    "cp produtos/P3/a registros/b", "mv produtos/P3/a dados/restritos/",
                    "tee dados/restritos/z < /dev/null", "rm -rf registros", "rm registros/decisoes/*",
                    "sed -i s/a/b/ governanca/matriz-agentes.json", "touch ./Registros/x",
                    "cd registros && touch x", "cd registros/decisoes; echo x > y",
                    "ln -s /etc/passwd registros/p", "install -m 0644 a dados/restritos/",
                    "sh -c 'echo x > registros/a'", "bash -c \"cp a dados/restritos/b\"",
                    "python3 -c \"open('registros/x','w').write('1')\"",
                    "git checkout -- registros", "chmod 777 .claude/settings.json",
                    "echo x > .claude/settings.json", "echo '{}' > CLAUDE.md",
                    "cp a b && echo y > produtos/P3/k && rm -f dados/entrada/*",
                    "ln -s ../../registros produtos/P3/atalho",
                    "ln -s ../../registros produtos/P3/atalho && echo x > produtos/P3/atalho/decisoes/y",
                    "ln -sf /etc/passwd produtos/P3/p", "ln -s ../../dados/restritos produtos/P3/d",
                    "nohup touch registros/x", "timeout 5 touch dados/restritos/q",
                    "env X=1 cp produtos/P3/a registros/b", "sudo -n rm -rf registros",
                    "cp -t registros/decisoes produtos/P3/a", "rsync -a produtos/P3/ dados/restritos/",
                    "cp --target-directory=governanca produtos/P3/a"):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.p.bash(cmd)[0], 2)

    def test_construcao_dinamica_vai_ao_humano(self):
        (self.p.raiz / "produtos/P3/x.py").write_text("print(1)", encoding="utf-8")
        (self.p.raiz / "produtos/P3/x.sh").write_text("echo 1", encoding="utf-8")
        for cmd in ("python3 produtos/P3/x.py", "bash produtos/P3/x.sh", "./produtos/P3/x.sh",
                    "git reset --hard", "git clean -fd", "echo registros/decisoes/b12 | xargs touch",
                    "find registros -name '*.json' -delete", "find dados -exec rm {} ;",
                    "ls registros | parallel rm {}", 'eval "touch $(echo regis)tros/x"',
                    "d=regis; echo x > ${d}tros/decisoes/y", "printf x > $(echo registros)/z",
                    "python3 -c \"import os; os.remove('a'+'b')\""):
            with self.subTest(cmd=cmd):
                codigo, saida, _ = self.p.bash(cmd)
                self.assertEqual(codigo, 0)
                self.assertEqual(json.loads(saida)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_limite_conhecido_ofuscacao_total_nao_e_detectada(self):
        """Registrado de propósito: a análise é heurística, não barreira (ver GOV-05, seção 6)."""
        codigo = self.p.bash("cat registros/x | python3 scripts/ok.py")[0]
        self.assertIn(codigo, (0, 2))        # não afirma proteção; só documenta o alcance da análise

    def test_conectores_nao_sao_usados_por_subagentes(self):
        ev = {"tool_name": "mcp__google_drive__create_file", "agent_type": "p5-juridico"}
        self.assertEqual(self.p.chama(ev)[0], 2)
        ev.pop("agent_type")
        self.assertEqual(self.p.chama(ev)[0], 0)


class TestConfiguracaoDoPacote(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
        self.matriz = json.loads(MATRIZ_ORIGEM.read_text(encoding="utf-8"))["agentes"]

    def test_deny_cobre_todas_as_areas_protegidas(self):
        deny = set(self.cfg["permissions"]["deny"])
        for area in AREAS:
            self.assertIn(f"Edit(/{area}/**)", deny)
            self.assertTrue((ROOT / area).is_dir() or area == "projects" or area == "logs", area)
        for padrao in ("Edit(/*.md)", "Edit(/*.txt)", "Edit(/*.lock)", "Edit(/.gitignore)"):
            self.assertIn(padrao, deny)

    def test_sem_acesso_irrestrito_e_sem_regras_ineficazes(self):
        permissoes = self.cfg["permissions"]
        self.assertNotIn(permissoes.get("defaultMode"), ("bypassPermissions", "acceptEdits"))
        for regra in permissoes["allow"] + permissoes["deny"]:
            self.assertNotRegex(regra, r"^(Bash|Write|MultiEdit|NotebookEdit)\b",
                                f"{regra}: Bash liberado ou regra que nunca casa")
        for regra in permissoes["allow"]:
            self.assertRegex(regra, r"^(Read\(/(registros|governanca)/\*\*\)|Edit\(/produtos/\*\*\))$")

    def test_hook_registrado_com_falha_fechada(self):
        grupos = self.cfg["hooks"]["PreToolUse"]
        self.assertEqual(len(grupos), 1)
        for ferramenta in ("Write", "Edit", "MultiEdit", "NotebookEdit", "Skill", "Bash", "mcp__"):
            self.assertRegex(ferramenta, grupos[0]["matcher"])
        comando = grupos[0]["hooks"][0]["command"]
        self.assertIn("guarda_ferramentas.py", comando)
        self.assertTrue(comando.rstrip().endswith("|| exit 2"))      # hook ausente/quebrado bloqueia

    def test_agentes_tem_skill_e_nada_alem_do_necessario(self):
        arquivos = sorted((ROOT / ".claude/agents").glob("*.md"))
        self.assertEqual(len(arquivos), 10)
        for arq in arquivos:
            texto = arq.read_text(encoding="utf-8")
            front = texto.split("---")[1]
            chaves = set(re.findall(r"^([a-zA-Z-]+):", front, re.M))
            self.assertEqual(chaves, {"name", "description", "tools"}, arq.name)
            ferramentas = [t.strip() for t in re.search(r"^tools: (.+)$", front, re.M).group(1).split(",")]
            self.assertIn("Skill", ferramentas, arq.name)
            self.assertFalse({"Bash", "Agent", "Task", "WebFetch", "WebSearch", "Edit", "MultiEdit",
                              "NotebookEdit"} & set(ferramentas), arq.name)
            self.assertEqual("Write" in ferramentas, arq.stem != "revisor-independente", arq.name)

    def test_agentes_listam_exatamente_as_skills_da_matriz(self):
        self.assertEqual(set(self.matriz), {a.stem for a in (ROOT / ".claude/agents").glob("*.md")})
        for agente, dados in self.matriz.items():
            texto = (ROOT / f".claude/agents/{agente}.md").read_text(encoding="utf-8")
            secao = texto.split("## Skills e áreas de escrita autorizadas")[1].split("## O — Validação")[0]
            self.assertEqual(sorted(re.findall(r"^- `([^`]+)`$", secao, re.M)), dados["skills"], agente)
            for destino in dados["escrita"]:
                self.assertIn(f"`{destino}/`", secao)

    def test_matriz_confere_com_consumidores_declarados_nas_skills(self):
        skills = {}
        for arq in (ROOT / ".claude/skills").glob("*/SKILL.md"):
            texto = arq.read_text(encoding="utf-8")
            skills[arq.parent.name] = re.search(r"Especialista metodológico para (.+)\.", texto).group(1)
        self.assertEqual(len(skills), 19)
        for skill, consumidores in skills.items():
            donos = {a for a, d in self.matriz.items() if skill in d["skills"]}
            if consumidores.strip() == "Todas":
                self.assertEqual(donos, set(self.matriz), skill)
            else:
                codigos = set(re.findall(r"\b(C|P[1-7])\b", consumidores))
                esperado = {a for a in self.matriz
                            if (a == "c-orquestrador" and "C" in codigos)
                            or (re.fullmatch(r"p[1-7]-.+", a) and a[1] and f"P{a[1]}" in codigos)}
                self.assertEqual(donos, esperado, skill)

    def test_escopo_de_escrita_por_agente(self):
        for agente, dados in self.matriz.items():
            if agente == "revisor-independente":
                self.assertEqual(dados["escrita"], [])
            elif agente in ("c-orquestrador", "controlador-dr"):
                self.assertEqual(dados["escrita"], ["produtos/C"])
            else:
                self.assertEqual(dados["escrita"], [f"produtos/P{agente[1]}"])

    def test_skills_nao_concedem_privilegios(self):
        proibidos = {"allowed-tools", "disallowed-tools", "hooks", "context", "agent", "model",
                     "tools", "permissionMode", "disable-model-invocation", "user-invocable"}
        for arq in (ROOT / ".claude/skills").glob("*/SKILL.md"):
            texto = arq.read_text(encoding="utf-8")
            chaves = set(re.findall(r"^([a-zA-Z-]+):", texto.split("---")[1], re.M))
            self.assertEqual(chaves, {"name", "description"}, arq.parent.name)
            self.assertFalse(chaves & proibidos)
            self.assertIn("## Limites de autoridade", texto)
            self.assertIn("Não concede ferramentas, permissões nem", texto)

    def test_sandbox_recomendado_cobre_as_mesmas_areas(self):
        cfg = json.loads((ROOT / "governanca/sandbox-recomendado.json").read_text(encoding="utf-8"))["sandbox"]
        proibidos = set(cfg["filesystem"]["denyWrite"])
        for area in AREAS:
            self.assertIn(f"./{area}", proibidos)
        self.assertFalse(cfg["autoAllowBashIfSandboxed"])
        self.assertFalse(cfg["allowUnsandboxedCommands"])
        self.assertNotIn("sandbox", self.cfg)       # opcional: não vem ativado por padrão

    def test_documento_gov05_confere_com_a_matriz(self):
        doc = (ROOT / "governanca/GOV-05-permissoes-e-skills.md").read_text(encoding="utf-8")
        linhas = re.findall(r"^\| `([a-z0-9-]+)` \| (.+?) \| (.+?) \|$", doc, re.M)
        por_agente = {a: ({s for s in re.findall(r"`([^`]+)`", sk)}, esc) for a, sk, esc in linhas if a in self.matriz}
        self.assertEqual(set(por_agente), set(self.matriz))
        for agente, dados in self.matriz.items():
            self.assertEqual(por_agente[agente][0], set(dados["skills"]), agente)
        self.assertIn("NÃO HOMOLOGADO", doc)

    def test_gitignore_nao_versiona_logs(self):
        texto = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("logs/*", texto)
        self.assertIn("!logs/.gitkeep", texto)


if __name__ == "__main__":
    unittest.main()
