"""GOV-06: restrição de leitura por agente, conectores e achados da revisão independente do guarda."""
import json
import os
import shutil
import subprocess
import sys
import unittest

from apoio_guarda import Base, MATRIZ_ORIGEM, ROOT  # noqa: F401


class TestLeitura(Base):
    RESTRITO = "dados/restritos/r.txt"

    def test_saida_do_dr_so_e_lida_por_quem_tem_direito(self):
        """GOV-08: produtos/DR é sigilosa para os agentes de produto (também na camada de ferramentas)."""
        for agente in ("controlador-dr", "revisor-independente", "c-orquestrador"):
            self.assertEqual(self.p.leitura("Read", agente, file_path="produtos/DR/saida.txt"), 0, agente)
        for agente in ("p1-diagnostico", "p3-mercado", "p7-licitacao"):
            self.assertEqual(self.p.leitura("Read", agente, file_path="produtos/DR/saida.txt"), 2, agente)
            self.assertEqual(self.p.leitura("Grep", agente, pattern="x", path="produtos/DR"), 2, agente)
        self.assertEqual(self.p.leitura("Read", None, file_path="produtos/DR/saida.txt"), 2)      # sessão principal sem leitura extra

    def test_agente_sem_excecao_nao_le_area_sigilosa(self):
        for destino in (self.RESTRITO, "dados/entrada/e.txt", "logs/l.log",
                        str(self.p.raiz / self.RESTRITO), "./" + self.RESTRITO,
                        "produtos/P3/../../" + self.RESTRITO, "DADOS/Restritos/r.txt", "dados//restritos/r.txt"):
            with self.subTest(destino=destino):
                self.assertEqual(self.p.leitura("Read", "p3-mercado", file_path=destino), 2)

    def test_excecoes_por_agente(self):
        self.assertEqual(self.p.leitura("Read", "controlador-dr", file_path=self.RESTRITO), 0)
        self.assertEqual(self.p.leitura("Read", "controlador-dr", file_path="dados/entrada/e.txt"), 0)
        self.assertEqual(self.p.leitura("Read", "controlador-dr", file_path="logs/l.log"), 2)
        self.assertEqual(self.p.leitura("Read", "revisor-independente", file_path="logs/l.log"), 0)
        self.assertEqual(self.p.leitura("Read", "c-orquestrador", file_path="logs/l.log"), 0)
        self.assertEqual(self.p.leitura("Read", "c-orquestrador", file_path=self.RESTRITO), 2)

    def test_sessao_principal_segue_a_politica_padrao(self):
        self.assertEqual(self.p.leitura("Read", file_path=self.RESTRITO), 2)
        self.assertEqual(self.p.leitura("Read", file_path="registros/decisoes/d.json"), 0)

    def test_leituras_legitimas_preservadas(self):
        for destino in ("registros/decisoes/d.json", "governanca/matriz-agentes.json", "produtos/P3",
                        "scripts/ok.py", "CLAUDE.md", "dados/processados", "referencias"):
            with self.subTest(destino=destino):
                self.assertEqual(self.p.leitura("Read", "p3-mercado", file_path=destino), 0)

    def test_symlink_para_area_sigilosa(self):
        os.symlink(self.p.raiz / self.RESTRITO, self.p.raiz / "produtos/P3/atalho.txt")
        os.symlink(self.p.raiz / "dados/restritos", self.p.raiz / "produtos/P3/atalho-dir")
        self.assertEqual(self.p.leitura("Read", "p3-mercado", file_path="produtos/P3/atalho.txt"), 2)
        self.assertEqual(self.p.leitura("Grep", "p3-mercado", pattern="x", path="produtos/P3/atalho-dir"), 2)
        self.assertEqual(self.p.leitura("Glob", "p3-mercado", pattern="*", path="produtos/P3/atalho-dir"), 2)

    def test_grep_e_glob_exigem_caminho_dentro_de_area_permitida(self):
        for entrada in ({"pattern": "x"}, {"pattern": "x", "path": "."}, {"pattern": "x", "path": "dados"},
                        {"pattern": "x", "path": str(self.p.raiz)}, {"pattern": "x", "path": "dados/restritos"}):
            with self.subTest(entrada=entrada):
                self.assertEqual(self.p.leitura("Grep", "p3-mercado", **entrada), 2)
        for entrada in ({"pattern": "x", "path": "produtos/P3"}, {"pattern": "x", "path": "produtos/C"}, {"pattern": "x", "path": "registros"},
                        {"pattern": "x", "path": ".claude/skills"}, {"pattern": "x", "path": "dados/processados"}):
            with self.subTest(entrada=entrada):
                self.assertEqual(self.p.leitura("Grep", "p3-mercado", **entrada), 0)
        # GOV-08: `produtos` contém a pasta do DR (sigilosa para os agentes de produto); quem não a lê informa a subpasta
        self.assertEqual(self.p.leitura("Grep", "p3-mercado", pattern="x", path="produtos"), 2)
        self.assertEqual(self.p.leitura("Grep", "c-orquestrador", pattern="x", path="produtos"), 0)
        # na raiz sempre há área sigilosa (settings.local.json) que ninguém lê: caminho explícito é obrigatório
        self.assertEqual(self.p.leitura("Grep", "revisor-independente", pattern="x"), 2)
        self.assertEqual(self.p.leitura("Grep", "revisor-independente", pattern="x", path="logs"), 0)
        self.assertEqual(self.p.leitura("Grep", "controlador-dr", pattern="x", path="dados"), 0)
        self.assertEqual(self.p.leitura("Grep", "controlador-dr", pattern="x", path="logs"), 2)

    def test_glob_resolve_o_prefixo_estatico_do_padrao(self):
        for pat in ("dados/**/*", "**/*.txt", "*/restritos/*", str(self.p.raiz / "dados/restritos/*"),
                    "../proj/dados/restritos/*", "dados/{restritos,entrada}/*", "logs/*"):
            with self.subTest(pat=pat):
                self.assertEqual(self.p.leitura("Glob", "p3-mercado", pattern=pat), 2)
        for pat in ("registros/**/*.json", "produtos/P3/*.md", "produtos/C/**/*.md", str(self.p.raiz / "governanca/*.json")):
            with self.subTest(pat=pat):
                self.assertEqual(self.p.leitura("Glob", "p3-mercado", pattern=pat), 0)
        self.assertEqual(self.p.leitura("Glob", "p3-mercado", pattern="produtos/*/README.md"), 2)     # varreria produtos/DR
        self.assertEqual(self.p.leitura("Glob", "c-orquestrador", pattern="produtos/*/README.md"), 0)
        self.assertEqual(self.p.leitura("Glob", "p3-mercado", pattern="*", path="registros"), 0)

    def test_fora_do_projeto(self):
        self.assertEqual(self.p.leitura("Read", "p3-mercado", file_path="/etc/hostname"), 2)
        self.assertEqual(self.p.leitura("Grep", "p3-mercado", pattern="x", path="/etc"), 2)
        self.assertEqual(self.p.leitura("Read", file_path="/etc/hostname"), 0)    # sessão principal: fluxo de permissões

    def test_agente_fora_da_matriz_nao_le(self):
        self.assertEqual(self.p.leitura("Read", "general-purpose", file_path="registros/decisoes/d.json"), 2)

    def test_politica_ausente_ou_corrompida_recusa_leitura(self):
        matriz = self.p.raiz / "governanca/matriz-agentes.json"
        base = json.loads(matriz.read_text(encoding="utf-8"))
        for alteracao in ("remover", "vazia", "tipo", "agente-sem-lista"):
            dados = json.loads(json.dumps(base))
            if alteracao == "remover":
                dados.pop("areas_sigilosas")
            elif alteracao == "vazia":
                dados["areas_sigilosas"] = []
            elif alteracao == "tipo":
                dados["areas_sigilosas"] = [1, 2]
            else:
                dados["agentes"]["p3-mercado"]["leitura_extra"] = "dados"
            matriz.write_text(json.dumps(dados), encoding="utf-8")
            with self.subTest(alteracao=alteracao):
                self.assertEqual(self.p.leitura("Read", "p3-mercado", file_path="registros/decisoes/d.json"), 2)

    def test_conectores_so_por_lista_explicita(self):
        ev = {"tool_name": "mcp__sintetico__publicar", "cwd": str(self.p.raiz), "tool_input": {}}
        self.assertEqual(self.p.chama(ev)[0], 2)
        matriz = self.p.raiz / "governanca/matriz-agentes.json"
        dados = json.loads(matriz.read_text(encoding="utf-8"))
        dados["conectores_permitidos_sessao_principal"] = ["mcp__sintetico__listar"]
        matriz.write_text(json.dumps(dados), encoding="utf-8")
        self.assertEqual(self.p.chama(ev)[0], 2)
        ev["tool_name"] = "mcp__sintetico__listar"
        self.assertEqual(self.p.chama(ev)[0], 0)
        ev["agent_type"] = "p3-mercado"
        self.assertEqual(self.p.chama(ev)[0], 2)


class TestRevisaoIndependente(Base):
    """Achados da revisão independente de GOV-06 (cada teste reproduz um contorno confirmado)."""

    def test_agent_type_falso_nao_vira_sessao_principal(self):
        for valor in ("", "  ", 0, False, None, [], {}, 7):
            ev = {"tool_name": "Write", "cwd": str(self.p.raiz), "agent_type": valor,
                  "tool_input": {"file_path": str(self.p.raiz / "produtos/P2/a")}}
            with self.subTest(valor=valor):
                self.assertEqual(self.p.chama(ev)[0], 2)
        ev = {"tool_name": "Bash", "agent_id": "abc", "cwd": str(self.p.raiz), "tool_input": {"command": "ls"}}
        self.assertEqual(self.p.chama(ev)[0], 2)

    def test_glob_gigante_e_recusado_rapido(self):
        import time
        for i in range(260):
            (self.p.raiz / "produtos/P3" / f"f{i}.txt").write_text("x", encoding="utf-8")
        inicio = time.monotonic()
        self.assertEqual(self.p.bash("touch produtos/P3/f*.txt")[0], 2)
        self.assertIn(self.p.bash("touch /*/*/*/*/*/*")[0], (0, 2))      # fora do projeto: não varre; só não pode demorar
        self.assertLess(time.monotonic() - inicio, 10)

    def test_leitura_fora_do_projeto_com_glob_amplo_nao_e_varrida(self):
        import time
        inicio = time.monotonic()
        self.assertEqual(self.p.bash("ls /usr/lib/*")[0], 0)
        self.assertLess(time.monotonic() - inicio, 5)

    def test_extratores_e_aplicadores_vao_ao_humano(self):
        for cmd in ("tar -xf produtos/P3/a.tar -C .", "tar xzf produtos/P3/a.tgz", "tar --extract -f a.tar",
                    "unzip -o produtos/P3/a.zip", "patch -p1 < produtos/P3/a.diff", "make", "npm run build",
                    "pip install x"):
            with self.subTest(cmd=cmd):
                codigo, saida, _ = self.p.bash(cmd)
                self.assertEqual(codigo, 0)
                self.assertEqual(json.loads(saida)["hookSpecificOutput"]["permissionDecision"], "ask")
        for cmd in ("tar -tf produtos/P3/a.tar", "tar tzf produtos/P3/a.tgz"):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.p.bash(cmd), (0, "", ""))

    def test_copia_para_a_raiz_do_projeto_e_recusada(self):
        for cmd in ("cp -r produtos/P3/. .", "cp produtos/P3/a.txt ./", "rsync -a produtos/P3/ ."):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.p.bash(cmd)[0], 2)

    def test_campos_de_skill_divergentes_sao_recusados(self):
        ev = {"tool_name": "Skill", "agent_type": "p1-diagnostico", "cwd": str(self.p.raiz),
              "tool_input": {"skill": "base-premissas", "name": "minutas-ppp"}}
        self.assertEqual(self.p.chama(ev)[0], 2)

    def test_consulta_humana_vira_recusa_em_bypass_permissions(self):
        ev = {"tool_name": "Bash", "cwd": str(self.p.raiz), "permission_mode": "bypassPermissions",
              "tool_input": {"command": "echo registros/x | xargs touch"}}
        self.assertEqual(self.p.chama(ev)[0], 2)
        ev["permission_mode"] = "acceptEdits"
        self.assertEqual(self.p.chama(ev)[0], 0)

    def test_vigia_interno_recusa_se_o_guarda_travar(self):
        import time
        ambiente = dict(os.environ, GUARDA_TEMPO_MAXIMO="1")
        processo = subprocess.Popen([sys.executable, "-I", str(self.p.hook)], stdin=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=ambiente, cwd=self.p.raiz)
        inicio = time.monotonic()
        try:
            codigo = processo.wait(timeout=8)         # stdin nunca fecha: o guarda ficaria bloqueado
        finally:
            processo.kill()
            processo.stdin.close()
            processo.stderr.close()
        self.assertEqual(codigo, 2)
        self.assertLess(time.monotonic() - inicio, 6)


if __name__ == "__main__":
    unittest.main()
