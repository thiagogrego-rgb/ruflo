"""GOV-07: isolamento por SO dos papéis (especificação, previsão, auditoria, sondagem de kernel e lançador).

As partes de kernel exigem Linux, root e `setpriv`: sem isso são PULADAS e o isolamento permanece NÃO validado.
Elas criam uma árvore temporária, aplicam donos/modos sintéticos e fazem cada papel TENTAR as operações com o uid real.
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import iniciar_sessao as L  # noqa: E402
import isolamento as I  # noqa: E402
import jaula as J  # noqa: E402

KERNEL = sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("setpriv")
PULAR = unittest.skipUnless(KERNEL, "exige Linux, root e setpriv: isolamento de kernel NÃO validado")


def spec_base():
    return I.carregar(ROOT / "governanca" / "papeis.json")


class TestEspecificacao(unittest.TestCase):
    def setUp(self):
        self.spec = spec_base()

    def test_especificacao_entregue_e_consistente(self):
        self.assertEqual(I.validar(self.spec), [])

    def test_detecta_especificacoes_inseguras(self):
        def muda(f):
            s = copy.deepcopy(self.spec)
            f(s)
            return I.validar(s)
        casos = {
            "papel privilegiado": lambda s: s["papeis"]["revisor"].update(conta="ppp-admin"),
            "uid duplicado": lambda s: s["contas"].update({"ppp-rev": s["contas"]["ppp-dr"]}),
            "uid de sistema": lambda s: s["contas"].update({"ppp-rev": 0}),
            "restritos legível por outros": lambda s: next(a for a in s["areas"] if a["caminho"] == "dados/restritos").update(modo_dir="0755"),
            "gravável por outros": lambda s: next(a for a in s["areas"] if a["caminho"] == "registros").update(modo_dir="0752"),
            "leitura declarada além do previsto": lambda s: next(a for a in s["areas"] if a["caminho"] == "dados/restritos")["leitura"].append("agentes"),
            "escrita declarada além do previsto": lambda s: next(a for a in s["areas"] if a["caminho"] == "registros")["escrita"].append("revisor"),
            "grupo inexistente": lambda s: s["papeis"]["agentes"]["grupos"].append("ppp-inexistente"),
            "caminho que escapa": lambda s: s["areas"].append({**s["areas"][1], "caminho": "../fora"}),
            "grupo do papel dá acesso indevido": lambda s: s["papeis"]["agentes"]["grupos"].append("ppp-restrito"),
        }
        for nome, f in casos.items():
            with self.subTest(nome=nome):
                self.assertTrue(muda(f), nome)

    def test_previsao_por_papel(self):
        p = lambda papel, area, op: I.prever(self.spec, papel, area, op)
        for papel in self.spec["papeis"]:
            self.assertTrue(p(papel, "registros", "ler"))
            self.assertFalse(p(papel, "registros", "criar"))
            self.assertFalse(p(papel, "governanca", "criar"))
            self.assertFalse(p(papel, ".claude", "sobrescrever"))
        self.assertFalse(p("agentes", "dados/restritos", "ler"))
        self.assertFalse(p("coordenador", "dados/restritos", "ler"))
        self.assertTrue(p("controlador-dr", "dados/restritos", "ler"))
        self.assertTrue(p("revisor", "dados/entrada", "ler"))
        self.assertFalse(p("controlador-dr", "dados/restritos", "criar"))
        self.assertTrue(p("coordenador", "logs", "ler"))
        self.assertFalse(p("controlador-dr", "logs", "ler"))
        self.assertFalse(p("agentes", "logs", "listar"))
        self.assertTrue(p("coordenador", "produtos/C", "criar"))
        self.assertTrue(p("controlador-dr", "produtos/C", "criar"))
        self.assertFalse(p("agentes", "produtos/C", "criar"))
        self.assertTrue(p("agentes", "produtos/P3", "criar"))
        self.assertFalse(p("coordenador", "produtos/P3", "criar"))
        for area in ("produtos/C", "produtos/P1", "produtos"):
            self.assertFalse(p("revisor", area, "criar"))               # o revisor não grava em lugar nenhum
            self.assertTrue(p("revisor", area, "ler"))

    def test_resolucao_de_area(self):
        casos = {"dados/restritos/x/y": "dados/restritos", "dados/processados/a": ".", "produtos/P3/x/y": "produtos/P3",
                 "produtos": "produtos", "produtos/P9": "produtos", "governanca/schemas": ".", ".": ".", "": "."}
        for rel, esperado in casos.items():
            self.assertEqual(I.area_de(self.spec, rel)["caminho"], esperado, rel)

    def test_matriz_e_contas_sao_apenas_texto(self):
        m = I.matriz_markdown(self.spec)
        self.assertIn("dados/restritos", m)
        self.assertIn("revisor", m)
        c = I.comandos_contas(self.spec)
        self.assertIn("useradd", c)
        self.assertIn("REVISAR", c)


class TestDocumentoGov07(unittest.TestCase):
    def test_documento_nao_declara_homologacao(self):
        texto = (ROOT / "governanca/GOV-07-isolamento-por-so.md").read_text(encoding="utf-8")
        for esperado in ("NÃO LIBERADO", "BLOQUEAR", "NÃO EXECUTADO"):
            self.assertIn(esperado, texto)
        self.assertNotIn("HOMOLOGADO PARA DOCUMENTOS REAIS", texto.replace("NÃO HOMOLOGADO PARA DOCUMENTOS REAIS", ""))


class TestLancadorPorPapel(unittest.TestCase):
    def setUp(self):
        self.spec = spec_base()

    def test_opcoes_que_reabririam_configuracao_ou_permissao_sao_recusadas(self):
        for opcao in ("--settings", "--setting-sources", "--dangerously-skip-permissions", "--permission-mode=bypassPermissions",
                      "--mcp-config"):
            with self.assertRaisesRegex(SystemExit, "opção recusada"):
                L.plano_do_papel(self.spec, "coordenador", [opcao, "x"], "/bin/true", dry_run=True)

    def test_papel_sem_valor_ou_root_sem_papel_e_recusado(self):
        with self.assertRaises(SystemExit):
            L.main(["--dry-run", "--papel"])
        if os.geteuid() == 0:
            with self.assertRaises(SystemExit):
                L.main(["--dry-run"])

    def test_jaula_usa_bwrap_absoluto_e_oculta_por_falta_de_leitura(self):
        if not shutil.which("bwrap"):
            self.skipTest("bwrap ausente")
        a = J.argumentos_jaula(self.spec, "agentes", "/srv/x/p", "/srv/x/h")
        self.assertTrue(os.path.isabs(a[0]))
        self.assertIn("--unshare-uts", a)
        spec = json.loads(json.dumps(self.spec))
        for area in spec["areas"]:
            area.pop("sigilosa", None)                                # rótulo ausente não pode abrir a área
        b = J.argumentos_jaula(spec, "agentes", "/srv/x/p", "/srv/x/h")
        self.assertIn("/srv/x/p/dados/restritos", b)

    def test_ambiente_minimo_sem_vazar_segredos(self):
        origem = {"ANTHROPIC_API_KEY": "chave", "AWS_SECRET_ACCESS_KEY": "x", "GITHUB_TOKEN": "y", "HTTPS_PROXY": "p",
                  "PATH": "/perigoso", "LD_PRELOAD": "/x.so", "PYTHONPATH": "/x", "HOME": "/root", "SEGREDO": "z"}
        env = L.ambiente_do_papel("revisor", "/h/revisor", origem)
        self.assertEqual(env["ANTHROPIC_API_KEY"], "chave")
        self.assertEqual(env["HTTPS_PROXY"], "p")
        self.assertEqual(env["PATH"], L.PATH_FIXO)
        self.assertEqual(env["HOME"], "/h/revisor")
        for proibida in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "LD_PRELOAD", "PYTHONPATH", "SEGREDO"):
            self.assertNotIn(proibida, env)

    def test_chaves_sao_mascaradas_na_saida(self):
        saida = L.mascarar(["env", "ANTHROPIC_API_KEY=segredo", "PPP_PAPEL=x", "CLAUDE_CODE_OAUTH_TOKEN=t"])
        self.assertNotIn("segredo", " ".join(saida))
        self.assertNotIn("=t", " ".join(saida))
        self.assertIn("PPP_PAPEL=x", saida)

    def test_papel_desconhecido_e_agentes_sem_agent(self):
        with self.assertRaises(SystemExit):
            L.plano_do_papel(self.spec, "inexistente", [], "/bin/true")
        if os.geteuid() == 0:
            with self.assertRaises(SystemExit):                          # a árvore do pacote não foi aplicada: auditoria diverge
                L.plano_do_papel(self.spec, "agentes", ["--agent", "p3-mercado"], "/bin/true")

    def test_nao_root_de_outra_conta_e_recusado(self):
        if os.geteuid() == 0:
            self.skipTest("este teste é para execução sem root")
        with self.assertRaises(SystemExit):
            L.plano_do_papel(self.spec, "revisor", [], "/bin/true")


@PULAR
class TestKernel(unittest.TestCase):
    """Árvore real com donos e modos sintéticos; cada papel assume seu uid e tenta de fato as operações."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="iso-"))
        self.addCleanup(self.limpa)
        os.chmod(self.base, 0o755)
        self.raiz = self.base / "proj"
        shutil.copytree(ROOT, self.raiz, ignore=shutil.ignore_patterns("__pycache__", "*.zip", "logs"), symlinks=True)
        (self.raiz / "logs").mkdir()
        (self.raiz / "dados/restritos/doc.txt").write_text("SEGREDO-SINTETICO\n", encoding="utf-8")
        (self.raiz / "dados/entrada/doc.txt").write_text("ENTRADA-SINTETICA\n", encoding="utf-8")
        self.spec = spec_base()
        self.homes = self.base / "homes"
        self.avisos = I.aplicar(self.raiz, self.spec, self.homes)

    def limpa(self):
        for arq in (self.raiz / "logs").glob("guarda-*.jsonl"):
            I._chattr("-a", arq)
        shutil.rmtree(self.base, ignore_errors=True)

    def sem_aviso_de_fs(self, divergencias):
        """Se o filesystem do /tmp não suporta chattr +a, ignora só essa classe de divergência (e a registra)."""
        return [d for d in divergencias if "só-anexar" not in d] if self.avisos else divergencias

    def test_auditoria_da_arvore_aplicada_e_conforme(self):
        self.assertEqual(self.sem_aviso_de_fs(I.auditar(self.raiz, self.spec)), [])

    def test_sondagem_de_kernel_confirma_a_matriz_para_todos_os_papeis(self):
        divergencias, registro = I.sondar(self.raiz, self.spec)
        self.assertEqual(self.sem_aviso_de_fs(divergencias), [])
        for papel, r in registro.items():
            self.assertFalse(r["recuperou_root"], papel)
            self.assertGreater(len(r["areas"]) + len(r["ataques"]) + len(r["logs"]), 70, papel)
        # sanidade: houve operações permitidas E negadas (o teste discrimina)
        todas = [v for r in registro.values() for v in r["areas"].values()]
        self.assertTrue(any(todas) and not all(todas))

    def test_operacoes_legitimas_continuam_possiveis(self):
        _, reg = I.sondar(self.raiz, self.spec)
        self.assertTrue(reg["coordenador"]["areas"]["produtos/C|criar"])
        self.assertTrue(reg["controlador-dr"]["areas"]["produtos/C|criar"])
        self.assertTrue(reg["agentes"]["areas"]["produtos/P3|criar"])
        self.assertTrue(reg["controlador-dr"]["areas"]["dados/restritos|ler"])
        self.assertTrue(reg["revisor"]["areas"]["dados/entrada|ler"])
        self.assertTrue(reg["coordenador"]["areas"]["logs|ler"])
        self.assertTrue(all(reg[p]["areas"]["registros|ler"] for p in reg))

    def test_papeis_sem_direito_nao_leem_restritos_mesmo_sem_hooks(self):
        """Nenhum hook, deny ou sandbox participa daqui: é só o kernel."""
        _, reg = I.sondar(self.raiz, self.spec)
        for papel in ("coordenador", "agentes"):
            for chave, valor in reg[papel]["areas"].items():
                if chave.startswith(("dados/restritos|", "dados/entrada|")):
                    self.assertFalse(valor, f"{papel} {chave}")
        for papel in reg:
            self.assertFalse(reg[papel]["areas"]["registros|criar"], papel)
            self.assertFalse(reg[papel]["areas"][".|sobrescrever"], papel)     # governanca/, scripts/, .claude/ ... caem na área-padrão
            self.assertFalse(reg[papel]["areas"][".|criar"], papel)

    def test_log_so_anexar_e_isolado_por_papel(self):
        if self.avisos:
            self.skipTest("filesystem sem chattr +a")
        _, reg = I.sondar(self.raiz, self.spec)
        for papel, r in reg.items():
            for dono in reg:
                self.assertEqual(r["logs"][f"{dono}|anexar"], dono == papel, f"{papel}->{dono}")
                self.assertFalse(r["logs"][f"{dono}|truncar"])
                self.assertFalse(r["logs"][f"{dono}|apagar"])

    def test_deriva_de_permissao_e_detectada_pela_auditoria_e_pela_sondagem(self):
        os.chmod(self.raiz / "dados/restritos", 0o755)               # alguém abre 'outros'
        div = I.auditar(self.raiz, self.spec)
        self.assertTrue(any("dados/restritos" in d for d in div))
        divs, _ = I.sondar(self.raiz, self.spec)
        self.assertTrue(any("agentes dados/restritos" in d for d in divs))
        I.aplicar(self.raiz, self.spec, self.homes)                  # reaplicar corrige
        self.assertEqual(self.sem_aviso_de_fs(I.auditar(self.raiz, self.spec)), [])

    def test_auditoria_pega_setuid_world_writable_e_symlink_para_fora(self):
        (self.raiz / "scripts/x.sh").write_text("x", encoding="utf-8")
        os.chmod(self.raiz / "scripts/x.sh", 0o4755)
        os.symlink("/etc/passwd", self.raiz / "produtos/P1/link")
        os.chmod(self.raiz / "governanca", 0o757)
        saida = " | ".join(I.auditar(self.raiz, self.spec))
        for esperado in ("setuid", "fora do projeto", "'outros'"):
            self.assertIn(esperado, saida)

    def test_lancador_rebaixa_privilegios_e_aplica_o_isolamento_na_identidade_real(self):
        if self.avisos:
            self.skipTest("filesystem sem chattr +a: o lançador recusaria (fail-closed)")
        stub = self.base / "claude-stub"
        stub.write_text(
            "#!/bin/sh\n"
            "echo UID=$(id -u) GID=$(id -g) GRUPOS=$(id -G)\n"
            "grep -E 'NoNewPrivs|CapEff|CapBnd' /proc/self/status\n"
            "echo HOME=$HOME PAPEL=$PPP_PAPEL CWD=$(pwd) UMASK=$(umask)\n"
            "echo SEGREDO_TESTE=${SEGREDO_TESTE:-ausente} CHAVE=${ANTHROPIC_API_KEY:-ausente} LD=${LD_PRELOAD:-ausente}\n"
            "echo ARGS=\"$@\"\n"
            "cat dados/restritos/doc.txt 2>/dev/null && echo LEU-RESTRITO || echo NEGADO-RESTRITO\n"
            "echo x >> registros/decisoes/hack 2>/dev/null && echo ESCREVEU-REGISTRO || echo NEGADO-REGISTRO\n",
            encoding="utf-8")
        os.chmod(stub, 0o755)
        env = dict(os.environ, SEGREDO_TESTE="vazou", ANTHROPIC_API_KEY="chave-sintetica", LD_PRELOAD="/nao/existe.so")

        def lancar(papel, *extra):
            return subprocess.run([sys.executable, "-B", str(self.raiz / "scripts/iniciar_sessao.py"), "--papel", papel,
                                   "--claude", str(stub), "--home-base", str(self.homes), *extra],
                                  capture_output=True, text=True, timeout=60, env=env)
        r = lancar("revisor")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"UID={self.spec['contas']['ppp-rev']}", r.stdout)
        self.assertNotIn("UID=0", r.stdout)
        grupos = set(r.stdout.split("GRUPOS=")[1].split()[0:6])
        self.assertTrue({"61100", "61101", "61102"} <= grupos and "61103" not in grupos and "61104" not in grupos, grupos)
        self.assertIn("NoNewPrivs:\t1", r.stdout)
        self.assertIn("CapEff:\t0000000000000000", r.stdout)
        self.assertIn("PAPEL=revisor", r.stdout)
        self.assertIn(f"CWD={os.path.realpath(self.raiz)}", r.stdout)
        self.assertIn("UMASK=0027", r.stdout)
        self.assertIn("SEGREDO_TESTE=ausente", r.stdout)
        self.assertIn("LD=ausente", r.stdout)
        self.assertIn("CHAVE=chave-sintetica", r.stdout)
        self.assertIn("--agent revisor-independente", r.stdout)
        self.assertIn("--setting-sources user,project", r.stdout)
        self.assertIn("LEU-RESTRITO", r.stdout)                      # o revisor tem direito...
        self.assertIn("NEGADO-REGISTRO", r.stdout)                   # ...mas não grava registros
        r = lancar("agentes", "--agent", "p3-mercado")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NEGADO-RESTRITO", r.stdout)                   # o kernel nega, sem nenhum hook
        self.assertNotIn("LEU-RESTRITO", r.stdout)
        self.assertNotIn("SEGREDO-SINTETICO", r.stdout)
        r = lancar("agentes")
        self.assertNotEqual(r.returncode, 0)                         # agentes exige --agent explícito
        r = lancar("coordenador", "--agent", "c-orquestrador")
        self.assertIn("NEGADO-RESTRITO", r.stdout)

    def test_lancador_recusa_com_isolamento_adulterado_e_nao_executa_nada(self):
        marcador = self.base / "executou"
        stub = self.base / "claude-stub"
        stub.write_text(f"#!/bin/sh\ntouch {marcador}\n", encoding="utf-8")
        os.chmod(stub, 0o755)
        os.chmod(self.raiz / "dados/restritos", 0o777)
        r = subprocess.run([sys.executable, "-B", str(self.raiz / "scripts/iniciar_sessao.py"), "--papel", "agentes",
                            "--agent", "p3-mercado", "--claude", str(stub), "--home-base", str(self.homes)],
                           capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("divergente", r.stderr)
        self.assertFalse(marcador.exists())

    def test_lancador_recusa_configuracao_comprometida_mesmo_com_papel(self):
        marcador = self.base / "executou"
        stub = self.base / "claude-stub"
        stub.write_text(f"#!/bin/sh\ntouch {marcador}\n", encoding="utf-8")
        os.chmod(stub, 0o755)
        (self.raiz / ".claude/settings.json").write_text("{", encoding="utf-8")
        r = subprocess.run([sys.executable, "-B", str(self.raiz / "scripts/iniciar_sessao.py"), "--papel", "revisor",
                            "--claude", str(stub), "--home-base", str(self.homes)], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(marcador.exists())


def _bwrap_funciona():
    if not shutil.which("bwrap"):
        return False
    return subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-user", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(_bwrap_funciona(), "exige bubblewrap com user namespaces: jaula NÃO validada")
class TestJaula(unittest.TestCase):
    """A jaula contém o processo por montagens, sem hook, sem deny e sem contas de SO."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="jaula-"))
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        os.chmod(self.base, 0o755)
        self.raiz = self.base / "proj"
        shutil.copytree(ROOT, self.raiz, ignore=shutil.ignore_patterns("__pycache__", "*.zip", "logs"), symlinks=True)
        (self.raiz / "logs").mkdir()
        for papel in spec_base()["papeis"]:
            (self.raiz / f"logs/guarda-{papel}.jsonl").touch()
        (self.raiz / "dados/restritos/doc.txt").write_text("SEGREDO-SINTETICO\n", encoding="utf-8")
        (self.raiz / "dados/entrada/doc.txt").write_text("ENTRADA\n", encoding="utf-8")
        self.home = self.base / "home"
        self.home.mkdir()
        self.spec = spec_base()

    def executa(self, papel, codigo):
        vetor = [sys.executable, "-B", str(self.raiz / "scripts/jaula.py"), "--papel", papel, "--raiz", str(self.raiz),
                 "--home", str(self.home), "--", sys.executable, "-B", "-c", codigo]
        return subprocess.run(vetor, capture_output=True, text=True, timeout=60, cwd=self.raiz)

    PROBA = (
        "import os,json\n"
        "def t(f):\n"
        "    try: f(); return True\n"
        "    except OSError: return False\n"
        "def esc(p):\n"
        "    def g():\n"
        "        with open(p,'w') as h: h.write('x')\n"
        "    return g\n"
        "def ler(p):\n"
        "    def g():\n"
        "        with open(p) as h: return h.read().index('SEGREDO')\n"
        "    return g\n"
        "r={'registros':t(esc('registros/decisoes/x')),'governanca':t(esc('governanca/x')),'claude':t(esc('.claude/settings.json')),\n"
        " 'C':t(esc('produtos/C/x')),'P3':t(esc('produtos/P3/x')),'restrito':t(ler('dados/restritos/doc.txt')),\n"
        " 'restrito_lista':os.listdir('dados/restritos'),'entrada':os.path.exists('dados/entrada/doc.txt'),\n"
        " 'etc':t(esc('/etc/ppp-x')),'home':t(esc('@HOME@/ok')),\n"
        " 'remonta':os.system('mount -o remount,rw /srv >/dev/null 2>&1')==0,'uid':os.getuid()}\n"
        "print(json.dumps(r))\n")

    def sonda(self, papel):
        r = self.executa(papel, self.PROBA.replace('@HOME@', str(self.home)))
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_argumentos_refletem_o_perfil_do_papel(self):
        from jaula import argumentos_jaula
        ag = " ".join(argumentos_jaula(self.spec, "agentes", self.raiz, self.home))
        self.assertIn("--cap-drop ALL", ag)
        self.assertIn("--unshare-user", ag)
        self.assertIn(f"--tmpfs {self.raiz}/dados/restritos --remount-ro {self.raiz}/dados/restritos", ag)
        self.assertIn(f"--bind {self.raiz}/produtos/P3 {self.raiz}/produtos/P3", ag)
        self.assertNotIn(f"--bind {self.raiz}/produtos/C ", ag)
        rev = " ".join(argumentos_jaula(self.spec, "revisor", self.raiz, self.home))
        self.assertNotIn(f"--tmpfs {self.raiz}/dados/restritos", rev)       # o revisor tem direito de ler
        self.assertNotIn("--bind " + str(self.raiz) + "/produtos", rev)      # e não grava em produtos
        with self.assertRaises(ValueError):
            argumentos_jaula(self.spec, "inexistente", self.raiz, self.home)

    def test_agentes_so_gravam_em_produtos_p_e_nao_veem_restritos(self):
        r = self.sonda("agentes")
        self.assertFalse(r["registros"] or r["governanca"] or r["claude"] or r["C"] or r["etc"])
        self.assertTrue(r["P3"] and r["home"])
        self.assertFalse(r["restrito"])
        self.assertEqual(r["restrito_lista"], [])
        self.assertFalse(r["entrada"])
        self.assertFalse(r["remonta"])

    def test_cada_papel_tem_o_seu_perfil(self):
        coord, dr, rev = self.sonda("coordenador"), self.sonda("controlador-dr"), self.sonda("revisor")
        self.assertTrue(coord["C"] and not coord["P3"] and not coord["restrito"])
        self.assertTrue(dr["C"] and dr["restrito"] and dr["entrada"])
        self.assertFalse(dr["registros"] or dr["P3"])
        self.assertTrue(rev["restrito"] and rev["entrada"])
        self.assertFalse(rev["C"] or rev["P3"] or rev["registros"])           # o revisor não grava em lugar nenhum

    def test_nenhum_papel_remonta_nem_escreve_fora_do_perfil(self):
        for papel in self.spec["papeis"]:
            r = self.sonda(papel)
            self.assertFalse(r["remonta"], papel)
            self.assertFalse(r["etc"], papel)

    def test_sem_comando_ou_papel_invalido_recusa(self):
        base = [sys.executable, "-B", str(self.raiz / "scripts/jaula.py"), "--raiz", str(self.raiz), "--home", str(self.home)]
        self.assertNotEqual(subprocess.run([*base, "--papel", "revisor"], capture_output=True).returncode, 0)
        self.assertNotEqual(subprocess.run([*base, "--papel", "xx", "--", "true"], capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
