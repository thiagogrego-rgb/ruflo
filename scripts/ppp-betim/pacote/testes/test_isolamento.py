"""GOV-07/08: isolamento por SO dos papéis (especificação, previsão, auditoria, sondagem de kernel, ataques de link e jaula).

As partes de kernel exigem Linux, root e `setpriv`: sem isso são PULADAS e o isolamento permanece NÃO validado.
Elas criam uma árvore temporária, aplicam donos/modos sintéticos e fazem cada papel TENTAR as operações com o uid real.
"""
import copy
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
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


def area(spec, caminho):
    return next(a for a in spec["areas"] if a["caminho"] == caminho)


class TestEspecificacao(unittest.TestCase):
    def setUp(self):
        self.spec = spec_base()

    def test_especificacao_entregue_e_consistente(self):
        self.assertEqual(I.validar(self.spec), [])
        self.assertEqual(len(self.spec["papeis"]), 10)                   # 3 papéis de coordenação/controle + 7 agentes P1-P7

    def test_cada_agente_de_produto_tem_conta_propria(self):
        contas = [p["conta"] for p in self.spec["papeis"].values()]
        self.assertEqual(len(set(contas)), len(contas))
        for i in range(1, 8):
            self.assertEqual(self.spec["papeis"][f"p{i}"]["conta"], f"ppp-p{i}")
            self.assertEqual(area(self.spec, f"produtos/P{i}")["escrita"], [f"p{i}"])
            self.assertEqual(area(self.spec, f"produtos/P{i}")["dono"], f"ppp-p{i}")

    def test_detecta_especificacoes_inseguras(self):
        def muda(f):
            s = copy.deepcopy(self.spec)
            f(s)
            return I.validar(s)
        casos = {
            "papel privilegiado": lambda s: s["papeis"]["revisor"].update(conta="ppp-admin"),
            "papel com a conta de rede": lambda s: s["papeis"]["revisor"].update(conta="ppp-rede"),
            "dois papéis na mesma conta": lambda s: s["papeis"]["p2"].update(conta="ppp-p1"),
            "uid duplicado": lambda s: s["contas"].update({"ppp-rev": s["contas"]["ppp-dr"]}),
            "uid de sistema": lambda s: s["contas"].update({"ppp-rev": 0}),
            "gid colide com uid": lambda s: s["grupos"].update({"ppp-leitura": s["contas"]["ppp-rev"]}),
            "restritos legível por outros": lambda s: area(s, "dados/restritos").update(modo_dir="0755"),
            "gravável por outros": lambda s: area(s, "registros").update(modo_dir="0752"),
            "gravável pelo grupo": lambda s: area(s, "produtos/P1").update(modo_arq="0660"),
            "setuid em arquivo": lambda s: area(s, "produtos/P1").update(modo_arq="4640"),
            "sticky em diretório": lambda s: area(s, "produtos/P1").update(modo_dir="3750"),
            "leitura declarada além do previsto": lambda s: area(s, "dados/restritos")["leitura"].append("p1"),
            "agente lê a área do DR": lambda s: area(s, "produtos/DR")["leitura"].append("p1"),
            "escrita declarada além do previsto": lambda s: area(s, "registros")["escrita"].append("revisor"),
            "escrita que não é do dono": lambda s: area(s, "produtos/C")["escrita"].append("controlador-dr"),
            "dono de papel sem escrita": lambda s: area(s, "produtos/C").update(escrita=[]),
            "área sigilosa com dono de papel": lambda s: area(s, "produtos/DR").update(dono="ppp-dr", escrita=["controlador-dr"]),
            "modo malformado": lambda s: area(s, "produtos/C").update(modo_dir="rwx"),
            "serviço ausente": lambda s: s["servicos"].pop("logd_socket"),
            "rede sem caminhos": lambda s: s["rede"].update(caminhos_permitidos=[]),
            "grupo inexistente": lambda s: s["papeis"]["p1"]["grupos"].append("ppp-inexistente"),
            "papel inexistente na área": lambda s: area(s, "produtos/C")["leitura"].append("fantasma"),
            "chave desconhecida": lambda s: area(s, "produtos/C").update(sigiloso=True),
            "caminho que escapa": lambda s: s["areas"].append({**s["areas"][1], "caminho": "../fora"}),
            "grupo do papel dá acesso indevido": lambda s: s["papeis"]["p1"]["grupos"].append("ppp-restrito"),
            "área duplicada": lambda s: s["areas"].append(copy.deepcopy(area(s, "produtos/P1"))),
        }
        for nome, f in casos.items():
            with self.subTest(nome=nome):
                self.assertTrue(muda(f), nome)

    def test_previsao_por_papel(self):
        p = lambda papel, rel, op: I.prever(self.spec, papel, rel, op)
        for papel in self.spec["papeis"]:
            self.assertTrue(p(papel, "registros", "ler"))
            self.assertFalse(p(papel, "registros", "criar"))
            self.assertFalse(p(papel, "governanca", "criar"))
            self.assertFalse(p(papel, ".claude", "sobrescrever"))
            self.assertFalse(p(papel, "logs", "criar"), papel)               # nenhum papel grava em logs/
            self.assertFalse(p(papel, "logs", "sobrescrever"), papel)
        self.assertFalse(p("p1", "dados/restritos", "ler"))
        self.assertFalse(p("coordenador", "dados/restritos", "ler"))
        self.assertTrue(p("controlador-dr", "dados/restritos", "ler"))
        self.assertTrue(p("revisor", "dados/entrada", "ler"))
        self.assertFalse(p("controlador-dr", "dados/restritos", "criar"))
        self.assertTrue(p("coordenador", "logs", "ler"))
        self.assertFalse(p("controlador-dr", "logs", "ler"))
        self.assertFalse(p("p1", "logs", "listar"))
        self.assertTrue(p("coordenador", "produtos/C", "criar"))
        self.assertFalse(p("controlador-dr", "produtos/C", "criar"))          # o DR só escreve na sua própria pasta
        self.assertTrue(p("controlador-dr", "produtos/DR/saida", "criar"))
        self.assertFalse(p("controlador-dr", "produtos/DR", "criar"))          # a pasta-casca é do administrador
        self.assertFalse(p("coordenador", "produtos/DR/saida", "criar"))
        self.assertTrue(p("coordenador", "produtos/DR/saida", "ler"))
        self.assertTrue(p("revisor", "produtos/DR/saida", "ler"))
        for i in range(1, 8):
            self.assertFalse(p(f"p{i}", "produtos/DR", "ler"), f"p{i} lê a saída do DR")
            self.assertFalse(p(f"p{i}", "produtos/DR/saida", "ler"), f"p{i} lê a saída do DR")
            for j in range(1, 8):
                self.assertEqual(p(f"p{i}", f"produtos/P{j}", "criar"), i == j, f"p{i}->P{j}")
                self.assertTrue(p(f"p{i}", f"produtos/P{j}", "ler"))
            self.assertFalse(p(f"p{i}", "produtos/C", "criar"))
        for rel in ("produtos/C", "produtos/DR", "produtos/DR/saida", "produtos/P1", "produtos"):
            self.assertFalse(p("revisor", rel, "criar"))               # o revisor não grava em lugar nenhum

    def test_resolucao_de_area(self):
        casos = {"dados/restritos/x/y": "dados/restritos", "dados/processados/a": ".", "produtos/P3/x/y": "produtos/P3",
                 "produtos": "produtos", "produtos/P9": "produtos", "governanca/schemas": ".", ".": ".", "": ".",
                 "produtos/DR/a": "produtos/DR", "logs/guarda-p1.jsonl": "logs"}
        for rel, esperado in casos.items():
            self.assertEqual(I.area_de(self.spec, rel)["caminho"], esperado, rel)

    def test_matriz_e_contas_sao_apenas_texto(self):
        m = I.matriz_markdown(self.spec)
        self.assertIn("dados/restritos", m)
        self.assertIn("produtos/DR", m)
        c = I.comandos_contas(self.spec)
        self.assertIn("useradd", c)
        self.assertIn("REVISAR", c)
        self.assertIn("ppp-rede", c)


class TestLancadorPorPapel(unittest.TestCase):
    def setUp(self):
        self.spec = spec_base()

    def test_opcoes_que_reabririam_configuracao_ou_permissao_sao_recusadas(self):
        for opcao in ("--settings", "--setting-sources", "--dangerously-skip-permissions", "--permission-mode=bypassPermissions",
                      "--mcp-config", "--agents", "--allowedTools", "--tools", "--system-prompt", "--append-system-prompt", "--debug-file",
                      "--worktree", "--add-dir", "--plugin-dir", "--dangerously-skip-permissions", "--disallowedTools"):
            with self.assertRaisesRegex(SystemExit, "opção recusada"):
                L.plano_do_papel(self.spec, "coordenador", [opcao, "x"], "/bin/true", dry_run=True)
        for permitida in ("-p", "--output-format", "--agent=p3-mercado", "--model", "--verbose"):
            self.assertIn(permitida.split("=")[0], L.OPCOES_PERMITIDAS)

    def test_papel_sem_valor_ou_root_sem_papel_e_recusado(self):
        with self.assertRaises(SystemExit):
            L.main(["--dry-run", "--papel"])
        if os.geteuid() == 0:
            with self.assertRaises(SystemExit):
                L.main(["--dry-run"])

    def test_jaula_oculta_por_falta_de_leitura_isola_a_rede_e_nao_da_escrita_em_logs(self):
        if not shutil.which("bwrap"):
            self.skipTest("bwrap ausente")
        a = J.argumentos_jaula(self.spec, "p3", "/srv/x/p", "/srv/x/h")
        self.assertTrue(os.path.isabs(a[0]))
        self.assertIn("--unshare-uts", a)
        self.assertIn("--unshare-net", a)                                  # padrão: sem rede nenhuma
        self.assertNotIn("--unshare-net", J.argumentos_jaula(self.spec, "p3", "/srv/x/p", "/srv/x/h", rede="aberta"))
        with self.assertRaises(ValueError):
            J.argumentos_jaula(self.spec, "p3", "/srv/x/p", "/srv/x/h", rede="qualquer")
        juntos = " ".join(a)
        self.assertIn("--tmpfs /srv/x/p/produtos/DR --remount-ro /srv/x/p/produtos/DR", juntos)      # p3 não lê a saída do DR
        self.assertIn("--disable-userns", juntos)
        self.assertIn("--bind /srv/x/p/produtos/P3 /srv/x/p/produtos/P3", juntos)
        self.assertNotIn("--bind /srv/x/p/produtos/P4 ", juntos)
        self.assertNotIn("guarda-p3.jsonl", juntos)                       # o papel não tem ponto de escrita no próprio log
        spec = json.loads(json.dumps(self.spec))
        for ar in spec["areas"]:
            ar.pop("sigilosa", None)                                       # rótulo ausente não pode abrir a área
        self.assertIn("/srv/x/p/dados/restritos", J.argumentos_jaula(spec, "p3", "/srv/x/p", "/srv/x/h"))

    def test_ambiente_do_modo_gateway_nao_recebe_credencial(self):
        origem = {"ANTHROPIC_API_KEY": "chave", "CLAUDE_CODE_OAUTH_TOKEN": "t", "AWS_SECRET_ACCESS_KEY": "x", "GITHUB_TOKEN": "y",
                  "HTTPS_PROXY": "http://u:senha@p", "PATH": "/perigoso", "LD_PRELOAD": "/x.so", "PYTHONPATH": "/x",
                  "HOME": "/root", "SEGREDO": "z", "LANG": "pt_BR.UTF-8"}
        env = L.ambiente_do_papel("revisor", "/h/revisor", origem, rede="gateway", logd_socket="/run/x/logd.sock")
        self.assertEqual(env["PATH"], L.PATH_FIXO)
        self.assertEqual(env["HOME"], "/h/revisor")
        self.assertNotIn("PPP_LOGD_OBRIGATORIO", env)
        self.assertEqual(env["PPP_LOGD_SOCKET"], "/run/x/logd.sock")
        self.assertEqual(env["LANG"], "pt_BR.UTF-8")
        for proibida in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "HTTPS_PROXY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
                         "LD_PRELOAD", "PYTHONPATH", "SEGREDO"):
            self.assertNotIn(proibida, env)
        aberto = L.ambiente_do_papel("revisor", "/h/revisor", origem, rede="aberta")
        self.assertEqual(aberto["ANTHROPIC_API_KEY"], "chave")             # modo explícito, só dados sintéticos
        self.assertNotIn("LD_PRELOAD", aberto)

    def test_segredos_sao_mascarados_na_saida(self):
        saida = L.mascarar(["env", "ANTHROPIC_API_KEY=segredo", "PPP_PAPEL=x", "CLAUDE_CODE_OAUTH_TOKEN=t", "HTTPS_PROXY=http://u:s@p"])
        texto = " ".join(saida)
        for vazado in ("segredo", "=t ", "u:s"):
            self.assertNotIn(vazado, texto + " ")
        self.assertIn("PPP_PAPEL=x", saida)
        env = L.mascarar_ambiente({"ANTHROPIC_API_KEY": "segredo", "HTTPS_PROXY": "http://u:s@p", "PPP_PAPEL": "x"})
        self.assertEqual(env["PPP_PAPEL"], "x")
        self.assertNotIn("segredo", json.dumps(env))
        self.assertNotIn("u:s", json.dumps(env))

    def test_regras_de_leitura_por_papel(self):
        r1 = L.regras_de_leitura(self.spec, "p1", "/proj")
        for esperado in ("dados/restritos", "dados/entrada", "logs", "produtos/DR"):
            self.assertTrue(any(f"/proj/{esperado}/**" in x for x in r1), esperado)
        self.assertFalse(any("registros" in x or "produtos/P" in x for x in r1))
        rev = L.regras_de_leitura(self.spec, "revisor", "/proj")
        self.assertEqual(rev, [])                                          # o revisor lê tudo, por desenho
        self.assertTrue(any("dados/restritos" in x for x in L.regras_de_leitura(self.spec, "coordenador", "/proj")))

    def test_terminal_inseguro_cobre_kernel_com_e_sem_o_sysctl(self):
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="tty-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        um, zero, ausente = d / "um", d / "zero", d / "ausente"
        um.write_text("1\n")
        zero.write_text("0\n")
        casos = [(um, None, True, True), (zero, None, True, False), (um, None, False, False),          # sysctl presente: vale o valor
                 (ausente, "5.15.0-1", True, True), (ausente, "6.1.9", True, True),                     # sem sysctl, kernel < 6.2: sempre permite
                 (ausente, "6.2.0", True, False), (ausente, "6.8.0-45", True, False), (ausente, "x.y", True, True),
                 (ausente, "5.15.0", False, False)]
        for sysctl, release, terminal, esperado in casos:
            self.assertEqual(L._terminal_inseguro(str(sysctl), release, terminal), esperado, (sysctl.name, release, terminal))

    def test_papel_desconhecido_e_agente_sem_nome(self):
        with self.assertRaises(SystemExit):
            L.plano_do_papel(self.spec, "inexistente", [], "/bin/true")
        if os.geteuid() == 0:
            with self.assertRaises(SystemExit):                          # a árvore do pacote não foi aplicada: auditoria diverge
                L.plano_do_papel(self.spec, "p3", [], "/bin/true", dry_run=True)

    def test_nao_root_de_outra_conta_e_recusado(self):
        if os.geteuid() == 0:
            self.skipTest("este teste é para execução sem root")
        with self.assertRaises(SystemExit):
            L.plano_do_papel(self.spec, "revisor", [], "/bin/true")


def _rodar_como(papel, spec, codigo, **kw):
    """Executa Python como a conta do papel (uid, gid e grupos reais)."""
    uid, gid, gids = I.ids_papel(spec, papel)
    return subprocess.run(["setpriv", f"--reuid={uid}", f"--regid={gid}", "--groups=" + ",".join(str(g) for g in gids if g != gid),
                           sys.executable, "-B", "-c", codigo], capture_output=True, text=True, timeout=60, **kw)


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
        self.homes.mkdir()                        # o administrador cria o home_base antes (root, sem escrita para grupo/outros)
        os.chmod(self.homes, 0o755)
        self.avisos = I.aplicar(self.raiz, self.spec, self.homes)

    def limpa(self):
        for arq in (self.raiz / "logs").glob("*.jsonl"):
            I._chattr("-a", arq)
        shutil.rmtree(self.base, ignore_errors=True)

    def sem_aviso_de_fs(self, divergencias):
        """Se o filesystem do /tmp não suporta chattr +a, ignora só essa classe de divergência (e a registra)."""
        return [d for d in divergencias if "só-anexar" not in d] if any("chattr" in a for a in self.avisos) else divergencias

    def audita(self):
        return self.sem_aviso_de_fs(I.auditar(self.raiz, self.spec, self.homes))

    def test_auditoria_da_arvore_aplicada_e_conforme(self):
        self.assertEqual(self.audita(), [])

    def test_sondagem_de_kernel_confirma_a_matriz_para_todos_os_papeis(self):
        divergencias, registro = I.sondar(self.raiz, self.spec)
        self.assertEqual(self.sem_aviso_de_fs(divergencias), [])
        self.assertEqual(len(registro), 10)
        total = 0
        for papel, r in registro.items():
            self.assertFalse(r["recuperou_root"], papel)
            n = len(r["areas"]) + len(r["ataques"]) + len(r["logs"])
            self.assertGreater(n, 80, papel)
            total += n
        self.assertGreater(total, 800)
        todas = [v for r in registro.values() for v in r["areas"].values()]
        self.assertTrue(any(todas) and not all(todas))                    # houve operações permitidas E negadas

    def test_operacoes_legitimas_continuam_possiveis(self):
        _, reg = I.sondar(self.raiz, self.spec)
        self.assertTrue(reg["coordenador"]["areas"]["produtos/C|criar"])
        self.assertTrue(reg["controlador-dr"]["areas"]["produtos/DR/saida|criar"])
        self.assertTrue(reg["controlador-dr"]["areas"]["dados/restritos|ler"])
        self.assertTrue(reg["revisor"]["areas"]["dados/entrada|ler"])
        self.assertTrue(reg["revisor"]["areas"]["produtos/DR|ler"])
        self.assertTrue(reg["coordenador"]["areas"]["produtos/DR|ler"])
        self.assertTrue(reg["coordenador"]["areas"]["logs|ler"])
        for i in range(1, 8):
            self.assertTrue(reg[f"p{i}"]["areas"][f"produtos/P{i}|criar"], f"p{i} grava na própria pasta")
        self.assertTrue(all(reg[p]["areas"]["registros|ler"] for p in reg))

    def test_escrita_segregada_nenhum_papel_grava_fora_da_propria_pasta(self):
        _, reg = I.sondar(self.raiz, self.spec)
        escritas = {p: sorted(k.split("|")[0] for k, v in r["areas"].items() if k.endswith("|criar") and v) for p, r in reg.items()}
        self.assertEqual(escritas["coordenador"], ["produtos/C"])
        self.assertEqual(escritas["controlador-dr"], ["produtos/DR/saida"])
        self.assertEqual(escritas["revisor"], [])
        for i in range(1, 8):
            self.assertEqual(escritas[f"p{i}"], [f"produtos/P{i}"])
        for p, r in reg.items():                                          # a saída do DR não chega aos agentes de produto
            if p.startswith("p"):
                self.assertFalse(r["areas"]["produtos/DR|ler"] or r["areas"]["produtos/DR|listar"], p)

    def test_papeis_sem_direito_nao_leem_restritos_mesmo_sem_hooks(self):
        """Nenhum hook, deny ou sandbox participa daqui: é só o kernel."""
        _, reg = I.sondar(self.raiz, self.spec)
        for papel in ["coordenador"] + [f"p{i}" for i in range(1, 8)]:
            for chave, valor in reg[papel]["areas"].items():
                if chave.startswith(("dados/restritos|", "dados/entrada|")):
                    self.assertFalse(valor, f"{papel} {chave}")
        for papel in reg:
            self.assertFalse(reg[papel]["areas"]["registros|criar"], papel)
            self.assertFalse(reg[papel]["areas"][".|sobrescrever"], papel)
            self.assertFalse(reg[papel]["areas"][".|criar"], papel)

    def test_logs_nao_sao_gravaveis_por_nenhum_papel(self):
        if any("chattr" in a for a in self.avisos):
            self.skipTest("filesystem sem chattr +a")
        _, reg = I.sondar(self.raiz, self.spec)
        for papel, r in reg.items():
            for chave, valor in r["logs"].items():
                self.assertFalse(valor, f"{papel} {chave}")               # nem anexar, nem truncar, nem apagar, nem criar
        for nome in I.nomes_de_log(self.spec):
            self.assertTrue(I._tem_so_anexar(self.raiz / "logs" / nome), nome)
            st = os.stat(self.raiz / "logs" / nome)
            self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode)), (self.spec["contas"]["ppp-guardiao"], 0o640))

    def test_deriva_de_permissao_e_detectada_pela_auditoria_e_pela_sondagem(self):
        os.chmod(self.raiz / "dados/restritos", 0o755)               # alguém abre 'outros'
        div = I.auditar(self.raiz, self.spec, self.homes)
        self.assertTrue(any("dados/restritos" in d for d in div))
        divs, _ = I.sondar(self.raiz, self.spec)
        self.assertTrue(any("p1 dados/restritos" in d for d in divs))
        I.aplicar(self.raiz, self.spec, self.homes)                  # reaplicar corrige
        self.assertEqual(self.audita(), [])

    def test_auditoria_pega_setuid_world_writable_symlink_hardlink_e_arquivo_especial(self):
        (self.raiz / "scripts/x.sh").write_text("x", encoding="utf-8")
        os.chmod(self.raiz / "scripts/x.sh", 0o4755)
        os.symlink("/etc/passwd", self.raiz / "produtos/P1/link")
        os.chmod(self.raiz / "governanca", 0o757)
        os.link(self.raiz / "scripts/isolamento.py", self.raiz / "scripts/duro.py")
        os.mkfifo(self.raiz / "scripts/fifo")
        saida = " | ".join(I.auditar(self.raiz, self.spec, self.homes))
        for esperado in ("setuid", "fora do projeto", "'outros'", "link físico", "especial"):
            self.assertIn(esperado, saida)

    def test_auditoria_pega_arquivo_inesperado_em_logs_e_log_com_dono_errado(self):
        (self.raiz / "logs/intruso.jsonl").write_text("x", encoding="utf-8")
        saida = " | ".join(I.auditar(self.raiz, self.spec, self.homes))
        self.assertIn("inesperado em logs", saida)
        os.unlink(self.raiz / "logs/intruso.jsonl")
        I._chattr("-a", self.raiz / "logs/guarda-p1.jsonl")
        os.chown(self.raiz / "logs/guarda-p1.jsonl", self.spec["contas"]["ppp-p1"], self.spec["contas"]["ppp-p1"])
        self.assertIn("dono, grupo ou modo", " | ".join(I.auditar(self.raiz, self.spec, self.homes)))

    def test_auditoria_tolera_arquivos_legitimos_do_papel_e_recusa_os_perigosos(self):
        """Operação legítima não pode travar o próximo início: arquivo do dono, modo igual ou mais restrito."""
        pasta = self.raiz / "produtos/P3"
        uid = self.spec["contas"]["ppp-p3"]
        gid = self.spec["grupos"]["ppp-leitura"]
        for nome, modo in (("relatorio.md", 0o640), ("rascunho.md", 0o600)):
            (pasta / nome).write_text("x", encoding="utf-8")
            os.chown(pasta / nome, uid, gid)
            os.chmod(pasta / nome, modo)
        os.mkdir(pasta / "sub")
        os.chown(pasta / "sub", uid, gid)
        os.chmod(pasta / "sub", 0o2750)
        self.assertEqual(self.audita(), [])
        os.chmod(pasta / "relatorio.md", 0o644)                           # mais permissivo do que o previsto
        self.assertTrue(any("relatorio.md" in d for d in self.audita()))
        os.chmod(pasta / "relatorio.md", 0o640)
        os.chown(pasta / "relatorio.md", self.spec["contas"]["ppp-p4"], gid)    # arquivo de outro agente dentro de P3
        self.assertTrue(any("relatorio.md" in d for d in self.audita()))

    def test_aplicar_nao_segue_links_plantados_por_um_agente(self):
        """P1 da correção: aplicar roda como root em pastas que o agente controla; link nunca pode virar chown/chmod no alvo."""
        vitima = self.base / "vitima"
        vitima.mkdir()
        (vitima / "alvo.txt").write_text("fora do projeto", encoding="utf-8")
        os.chmod(vitima, 0o700)
        os.chmod(vitima / "alvo.txt", 0o600)
        antes = {c: (os.stat(c).st_uid, os.stat(c).st_gid, stat.S_IMODE(os.stat(c).st_mode)) for c in (vitima, vitima / "alvo.txt")}
        alvo_proj = self.raiz / "registros/decisoes"
        alvo_proj.mkdir(exist_ok=True)
        os.chown(alvo_proj, self.spec["contas"]["ppp-guardiao"], self.spec["grupos"]["ppp-leitura"])
        os.chmod(alvo_proj, 0o750)
        plantar = (
            "import os\n"
            f"p='{self.raiz}/produtos/P3/'\n"
            f"os.symlink('{vitima}', p+'elo-dir')\n"
            f"os.symlink('{vitima}/alvo.txt', p+'elo-arq')\n"
            f"os.symlink('{alvo_proj}', p+'elo-registros')\n"
            "open(p+'meu.txt','w').write('x')\n"
            "os.link(p+'meu.txt', p+'meu-duro.txt')\n")
        r = _rodar_como("p3", self.spec, plantar)
        self.assertEqual(r.returncode, 0, r.stderr)
        avisos = I.aplicar(self.raiz, self.spec, self.homes)
        for c, v in antes.items():
            st = os.stat(c)
            self.assertEqual((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)), v, f"{c} foi alterado através de um link")
        self.assertTrue(any("link físico" in a for a in avisos), avisos)  # hardlink não é tocado
        stp = os.lstat(self.raiz / "produtos/P3/elo-dir")
        self.assertTrue(stat.S_ISLNK(stp.st_mode))
        self.assertEqual(os.stat(alvo_proj).st_mode & 0o7777, 0o750)
        # a auditoria recusa a árvore com links para fora e os hardlinks, então a sessão não inicia
        saida = " | ".join(I.auditar(self.raiz, self.spec, self.homes))
        self.assertIn("fora do projeto", saida)
        self.assertIn("link físico", saida)

    def test_aplicar_resiste_a_troca_de_diretorio_por_link_durante_a_execucao(self):
        """Corrida: o agente alterna uma pasta entre diretório real e link para fora enquanto aplicar roda várias vezes."""
        vitima = self.base / "vitima2"
        (vitima / "sub").mkdir(parents=True)
        (vitima / "sub/arq.txt").write_text("x", encoding="utf-8")
        os.chmod(vitima, 0o700)
        antes = [(c, os.stat(c).st_uid, stat.S_IMODE(os.stat(c).st_mode)) for c in (vitima, vitima / "sub", vitima / "sub/arq.txt")]
        pasta = self.raiz / "produtos/P3"
        for i in range(40):                                               # muitos arquivos alargam a janela de corrida
            (pasta / f"f{i}.txt").write_text("x", encoding="utf-8")
        trocador = (
            "import os,time\n"
            f"p='{pasta}/d'\n"
            f"fim=time.time()+6\n"
            "while time.time()<fim:\n"
            "    try:\n"
            "        os.mkdir(p)\n"
            "    except FileExistsError: pass\n"
            "    try:\n"
            "        os.rmdir(p)\n"
            f"        os.symlink('{vitima}', p)\n"
            "    except OSError: pass\n"
            "    try:\n"
            "        os.unlink(p)\n"
            "    except OSError: pass\n")
        uid, gid, gids = I.ids_papel(self.spec, "p3")
        proc = subprocess.Popen(["setpriv", f"--reuid={uid}", f"--regid={gid}", "--groups=" + ",".join(str(g) for g in gids if g != gid),
                                 sys.executable, "-B", "-c", trocador])
        try:
            fim = time.time() + 5
            execucoes = 0
            while time.time() < fim:
                I.aplicar(self.raiz, self.spec)
                execucoes += 1
        finally:
            proc.wait(timeout=30)
        self.assertGreater(execucoes, 5)
        depois = [(c, os.stat(c).st_uid, stat.S_IMODE(os.stat(c).st_mode)) for c, _, _ in antes]
        self.assertEqual(antes, depois, "um alvo fora do projeto foi alterado por corrida de link")

    def test_home_com_link_plantado_nao_vira_chown_em_diretorio_arbitrario(self):
        vitima = self.base / "vitima3"
        vitima.mkdir()
        os.chmod(vitima, 0o700)
        antes = (os.stat(vitima).st_uid, stat.S_IMODE(os.stat(vitima).st_mode))
        tmp = self.homes / "p2" / "tmp"
        uid = self.spec["contas"]["ppp-p2"]
        r = _rodar_como("p2", self.spec, f"import os,shutil\nshutil.rmtree('{tmp}')\nos.symlink('{vitima}','{tmp}')\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        with self.assertRaises(OSError):                                  # falha fechada: recusa em vez de seguir o link
            I.aplicar(self.raiz, self.spec, self.homes)
        self.assertEqual((os.stat(vitima).st_uid, stat.S_IMODE(os.stat(vitima).st_mode)), antes)
        self.assertNotEqual(uid, os.stat(vitima).st_uid)
        self.assertTrue(any("home do papel p2" in d for d in I.auditar(self.raiz, self.spec, self.homes)))

    def test_dono_da_saida_do_dr_nao_consegue_expor_a_saida_aos_agentes(self):
        """O dono de uma pasta sempre pode mudar modo e grupo; por isso a saída do DR fica sob uma pasta-casca do administrador."""
        (self.raiz / "produtos/DR/saida/relatorio.txt").write_text("SAIDA-DR\n", encoding="utf-8")
        dr = self.spec["contas"]["ppp-dr"]
        os.chown(self.raiz / "produtos/DR/saida/relatorio.txt", dr, self.spec["grupos"]["ppp-dr-leitura"])
        os.chmod(self.raiz / "produtos/DR/saida/relatorio.txt", 0o640)
        r = _rodar_como("controlador-dr", self.spec,
                        f"import os\nd='{self.raiz}/produtos/DR/saida'\nos.chmod(d, 0o777)\nos.chmod(d+'/relatorio.txt', 0o666)\n"
                        f"os.chown(d, -1, {self.spec['grupos']['ppp-leitura']})\nos.chown(d+'/relatorio.txt', -1, {self.spec['grupos']['ppp-leitura']})\n"
                        "print('ADULTEROU')\n")
        self.assertIn("ADULTEROU", r.stdout, r.stderr)             # o dono consegue (é a limitação do DAC)...
        for i in range(1, 8):                                       # ...mas nenhum agente de produto chega lá
            r = _rodar_como(f"p{i}", self.spec, f"print(open('{self.raiz}/produtos/DR/saida/relatorio.txt').read())")
            self.assertNotIn("SAIDA-DR", r.stdout, f"p{i}")
            self.assertNotEqual(r.returncode, 0, f"p{i}")
        self.assertTrue(any("saida" in d for d in I.auditar(self.raiz, self.spec, self.homes)))        # e a auditoria denuncia o excesso

    def test_cli_aplicar_so_confirma_se_a_auditoria_seguinte_estiver_conforme(self):
        cli = [sys.executable, "-B", str(self.raiz / "scripts/isolamento.py"), "aplicar", "--raiz", str(self.raiz), "--home-base", str(self.homes)]
        ok = subprocess.run(cli, capture_output=True, text=True, timeout=60)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("confirmado pela auditoria", ok.stdout)
        os.link(self.raiz / "scripts/isolamento.py", self.raiz / "scripts/duro.py")          # hardlink: aplicar avisa e a auditoria reprova
        ruim = subprocess.run(cli, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(ruim.returncode, 0)
        self.assertIn("NÃO confirmado", ruim.stdout)

    def test_ancestral_de_propriedade_de_conta_de_papel_e_recusado(self):
        os.chown(self.base, self.spec["contas"]["ppp-p3"], self.spec["contas"]["ppp-p3"])      # o dono sempre pode mudar o modo
        try:
            self.assertTrue(any("pertence a uma conta de papel" in d for d in I.auditar(self.raiz, self.spec, self.homes)))
            with self.assertRaises(SystemExit):
                I.aplicar(self.raiz, self.spec)
        finally:
            os.chown(self.base, 0, 0)

    def test_fifo_no_lugar_da_sentinela_nao_trava_aplicar(self):
        os.unlink(self.raiz / "produtos/P5/.sentinela")
        os.mkfifo(self.raiz / "produtos/P5/.sentinela")
        with self.assertRaises(OSError):
            I.aplicar(self.raiz, self.spec, self.homes)            # recusa com erro claro, sem ficar bloqueado
        os.unlink(self.raiz / "produtos/P5/.sentinela")
        I.aplicar(self.raiz, self.spec, self.homes)

    def test_sondagem_distingue_negacao_do_kernel_de_falha_inconclusiva(self):
        os.unlink(self.raiz / "produtos/P6/.sentinela")           # sem a sentinela, "ler" falha por ENOENT, não por permissão
        divs, _ = I.sondar(self.raiz, self.spec)
        self.assertTrue(any("INCONCLUSIVO" in d and "produtos/P6" in d for d in divs), divs[:3])

    def test_ancestral_gravavel_por_papel_bloqueia_aplicar_e_a_auditoria(self):
        pai = self.base / "pai"
        pai.mkdir()
        os.chmod(pai, 0o777)
        movido = pai / "proj"
        shutil.move(str(self.raiz), movido)
        try:
            self.assertTrue(any("gravável pelo papel" in d for d in I.auditar(movido, self.spec, self.homes)))
            with self.assertRaises(SystemExit):
                I.aplicar(movido, self.spec)
        finally:
            shutil.move(str(movido), str(self.raiz))

    def test_diretorio_ilegivel_nao_vira_conforme_em_silencio(self):
        """Quem audita sem poder ler uma pasta (ex.: NFS com root_squash) recebe erro, não 'conforme'."""
        codigo = (f"import sys; sys.path.insert(0, '{self.raiz / 'scripts'}')\n"
                  "import isolamento as I\n"
                  f"I.auditar('{self.raiz}', I.carregar('{self.raiz / 'governanca/papeis.json'}'))\n")
        r = _rodar_como("p3", self.spec, codigo)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("PermissionError", r.stderr)

    def lancar(self, papel, *extra, stub=None, env=None):
        logd = self.base / "logd.sock"
        gw = self.base / "gw.sock"
        logd.touch()
        if not gw.exists():                                              # a ponte exige um SOCKET de verdade, não um arquivo
            self._gw = socket.socket(socket.AF_UNIX)
            self._gw.bind(str(gw))
            self.addCleanup(self._gw.close)
        return subprocess.run([sys.executable, "-B", str(self.raiz / "scripts/iniciar_sessao.py"), "--papel", papel,
                               "--claude", str(stub), "--home-base", str(self.homes), "--logd-socket", str(logd),
                               "--gateway-socket", str(gw), "--permitir-servicos-de-teste", *extra], capture_output=True, text=True, timeout=60, env=env or os.environ)

    def stub(self, corpo):
        s = self.base / "claude-stub"
        s.write_text("#!/bin/sh\n" + corpo, encoding="utf-8")
        os.chmod(s, 0o755)
        return s

    def test_lancador_rebaixa_privilegios_e_aplica_o_isolamento_na_identidade_real_modo_aberto(self):
        if any("chattr" in a for a in self.avisos):
            self.skipTest("filesystem sem chattr +a: o lançador recusaria (fail-closed)")
        stub = self.stub(
            "echo UID=$(id -u) GID=$(id -g) GRUPOS=$(id -G)\n"
            "grep -E 'NoNewPrivs|CapEff|CapBnd' /proc/self/status\n"
            "echo HOME=$HOME PAPEL=$PPP_PAPEL CWD=$(pwd) UMASK=$(umask) LOGD=$PPP_LOGD_SOCKET\n"
            "echo SEGREDO_TESTE=${SEGREDO_TESTE:-ausente} CHAVE=${ANTHROPIC_API_KEY:-ausente} LD=${LD_PRELOAD:-ausente}\n"
            "echo ARGS=\"$@\"\n"
            "echo CMDLINE=$(tr '\\0' ' ' < /proc/self/cmdline)\n"
            "cat dados/restritos/doc.txt 2>/dev/null && echo LEU-RESTRITO || echo NEGADO-RESTRITO\n"
            "echo x >> registros/decisoes/hack 2>/dev/null && echo ESCREVEU-REGISTRO || echo NEGADO-REGISTRO\n"
            "echo x >> logs/guarda-$PPP_PAPEL.jsonl 2>/dev/null && echo ESCREVEU-LOG || echo NEGADO-LOG\n")
        env = dict(os.environ, SEGREDO_TESTE="vazou", ANTHROPIC_API_KEY="chave-sintetica", LD_PRELOAD="/nao/existe.so")
        r = self.lancar("revisor", "--rede", "aberta", stub=stub, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"UID={self.spec['contas']['ppp-rev']}", r.stdout)
        self.assertNotIn("UID=0", r.stdout)
        grupos = set(r.stdout.split("GRUPOS=")[1].split()[0:6])
        self.assertTrue({"61100", "61101", "61102", "61105"} <= grupos, grupos)
        self.assertIn("NoNewPrivs:\t1", r.stdout)
        self.assertIn("CapEff:\t0000000000000000", r.stdout)
        self.assertIn("PAPEL=revisor", r.stdout)
        self.assertIn(f"CWD={os.path.realpath(self.raiz)}", r.stdout)
        self.assertIn("UMASK=0027", r.stdout)
        self.assertIn("SEGREDO_TESTE=ausente", r.stdout)
        self.assertIn("LD=ausente", r.stdout)
        self.assertIn("CHAVE=chave-sintetica", r.stdout)                   # modo aberto: a chave está no AMBIENTE do processo...
        self.assertNotIn("chave-sintetica", r.stdout.split("CMDLINE=")[1].split("\n")[0])      # ...e nunca em argv
        self.assertNotIn("chave-sintetica", r.stderr)
        self.assertIn("--agent revisor-independente", r.stdout)
        self.assertIn("--setting-sources project", r.stdout)               # fonte `user` (HOME gravável pelo papel) ignorada
        self.assertIn("LEU-RESTRITO", r.stdout)                      # o revisor tem direito...
        self.assertIn("NEGADO-REGISTRO", r.stdout)                   # ...mas não grava registros
        self.assertIn("NEGADO-LOG", r.stdout)                        # ...nem o próprio log (só o serviço grava)
        r = self.lancar("p3", "--rede", "aberta", stub=stub, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NEGADO-RESTRITO", r.stdout)                   # o kernel nega, sem nenhum hook
        self.assertNotIn("SEGREDO-SINTETICO", r.stdout)
        self.assertIn("--agent p3-mercado", r.stdout)                # o agente padrão do papel p3 é o seu próprio agente
        r = self.lancar("coordenador", "--rede", "aberta", stub=stub, env=env)
        self.assertIn("NEGADO-RESTRITO", r.stdout)

    def test_lancador_modo_gateway_nao_entrega_credencial_nem_rede(self):
        if any("chattr" in a for a in self.avisos) or not shutil.which("bwrap"):
            self.skipTest("exige chattr +a e bubblewrap")
        stub = self.stub(
            "echo CHAVE=${ANTHROPIC_API_KEY:-ausente} TOKEN=${CLAUDE_CODE_OAUTH_TOKEN:-ausente} PROXY=${HTTPS_PROXY:-ausente}\n"
            "echo BASE=$ANTHROPIC_BASE_URL\n"
            "echo UID=$(id -u)\n"
            "python3 -c \"import socket\ns=socket.socket();s.settimeout(3)\ntry:\n s.connect(('1.1.1.1',443));print('REDE-ABERTA')\nexcept OSError as e:print('SEM-REDE',e.errno)\"\n"
            "ls /run /root /home 2>&1 | tr '\\n' ' '; echo\n")
        env = dict(os.environ, ANTHROPIC_API_KEY="chave-do-operador", CLAUDE_CODE_OAUTH_TOKEN="token-do-operador",
                   HTTPS_PROXY="http://u:senha@proxy:3128")
        r = self.lancar("p3", stub=stub, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        for segredo in ("chave-do-operador", "token-do-operador", "senha"):
            self.assertNotIn(segredo, r.stdout + r.stderr)
        self.assertIn("TOKEN=ausente", r.stdout)
        self.assertIn("PROXY=ausente", r.stdout)
        self.assertIn("CHAVE=gateway-local-sem-valor", r.stdout)          # marcador sem valor, não a chave
        self.assertRegex(r.stdout, r"BASE=http://127\.0\.0\.1:\d+")
        self.assertIn("SEM-REDE", r.stdout)
        self.assertNotIn("REDE-ABERTA", r.stdout)

    def test_lancador_recusa_sem_servico_de_log_ou_sem_gateway(self):
        marcador = self.base / "executou"
        stub = self.stub(f"touch {marcador}\n")
        base = [sys.executable, "-B", str(self.raiz / "scripts/iniciar_sessao.py"), "--papel", "p3", "--claude", str(stub),
                "--home-base", str(self.homes)]
        r = subprocess.run([*base, "--logd-socket", str(self.base / "nao-existe.sock"), "--rede", "aberta"], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("serviço de log indisponível", r.stderr)
        (self.base / "logd.sock").touch()
        r = subprocess.run([*base, "--logd-socket", str(self.base / "logd.sock"), "--gateway-socket", str(self.base / "nao-existe.sock")],
                           capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("gateway de rede indisponível", r.stderr)
        self.assertFalse(marcador.exists())

    def test_dry_run_nao_mostra_credencial_nem_em_argv_nem_na_saida(self):
        env = dict(os.environ, ANTHROPIC_API_KEY="chave-do-operador", HTTPS_PROXY="http://u:senha@proxy:3128")
        for rede in ("gateway", "aberta"):
            r = subprocess.run([sys.executable, "-B", str(self.raiz / "scripts/iniciar_sessao.py"), "--papel", "p3", "--rede", rede,
                                "--dry-run", "--home-base", str(self.homes), "--claude", "/bin/true"],
                               capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("chave-do-operador", r.stdout + r.stderr)
            self.assertNotIn("senha", r.stdout + r.stderr)
            plano = json.loads(r.stdout)
            self.assertEqual(plano["rede"], rede)
            self.assertEqual("--unshare-net" in plano["comando"], rede == "gateway")
            self.assertEqual(any("entrada_jaula.py" in c for c in plano["comando"]), rede == "gateway")
            for fixa in ("--strict-mcp-config", "--setting-sources", "project"):         # nada de MCP ou settings do HOME gravável
                self.assertIn(fixa, plano["comando"])

    def test_lancador_recusa_socket_de_servico_que_nao_e_da_conta_esperada(self):
        marcador = self.base / "executou"
        stub = self.stub(f"touch {marcador}\n")
        logd, gw = self.base / "logd.sock", self.base / "gw.sock"
        for s in (logd, gw):                                             # sockets de verdade, mas do root (não do guardião/rede)
            sk = socket.socket(socket.AF_UNIX)
            sk.bind(str(s))
            self.addCleanup(sk.close)
        r = subprocess.run([sys.executable, "-B", str(self.raiz / "scripts/iniciar_sessao.py"), "--papel", "p3", "--claude", str(stub),
                            "--home-base", str(self.homes), "--logd-socket", str(logd), "--gateway-socket", str(gw)],
                           capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("não é um socket da conta esperada", r.stderr)
        self.assertFalse(marcador.exists())

    def test_lancador_recusa_com_isolamento_adulterado_e_nao_executa_nada(self):
        marcador = self.base / "executou"
        stub = self.stub(f"touch {marcador}\n")
        os.chmod(self.raiz / "dados/restritos", 0o777)
        r = self.lancar("p3", "--rede", "aberta", stub=stub)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("divergente", r.stderr)
        self.assertFalse(marcador.exists())

    def test_lancador_recusa_configuracao_comprometida_mesmo_com_papel(self):
        marcador = self.base / "executou"
        stub = self.stub(f"touch {marcador}\n")
        (self.raiz / ".claude/settings.json").write_text("{", encoding="utf-8")
        r = self.lancar("revisor", "--rede", "aberta", stub=stub)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(marcador.exists())


def _bwrap_funciona():
    if not shutil.which("bwrap"):
        return False
    return subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-user", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(_bwrap_funciona(), "exige bubblewrap com user namespaces: jaula NÃO validada")
class TestJaula(unittest.TestCase):
    """A jaula contém o processo por montagens e por rede, sem hook, sem deny e sem contas de SO."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="jaula-"))
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        os.chmod(self.base, 0o755)
        self.raiz = self.base / "proj"
        shutil.copytree(ROOT, self.raiz, ignore=shutil.ignore_patterns("__pycache__", "*.zip", "logs"), symlinks=True)
        for ar in spec_base()["areas"]:
            (self.raiz / ar["caminho"]).mkdir(parents=True, exist_ok=True)
        for nome in I.nomes_de_log(spec_base()):
            (self.raiz / f"logs/{nome}").touch()
        (self.raiz / "dados/restritos/doc.txt").write_text("SEGREDO-SINTETICO\n", encoding="utf-8")
        (self.raiz / "dados/entrada/doc.txt").write_text("ENTRADA\n", encoding="utf-8")
        self.home = self.base / "home"
        self.home.mkdir()
        self.spec = spec_base()
        self.escuta = socket.socket()
        self.escuta.bind(("127.0.0.1", 0))
        self.escuta.listen(4)
        self.addCleanup(self.escuta.close)
        self.porta = self.escuta.getsockname()[1]

    def executa(self, papel, codigo, rede="gateway"):
        vetor = [sys.executable, "-B", str(self.raiz / "scripts/jaula.py"), "--papel", papel, "--raiz", str(self.raiz),
                 "--home", str(self.home), "--rede", rede, "--", sys.executable, "-B", "-c", codigo]
        return subprocess.run(vetor, capture_output=True, text=True, timeout=60, cwd=self.raiz)

    PROBA = (
        "import os,json,socket\n"
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
        "def conecta():\n"
        "    s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1',@PORTA@)); s.close()\n"
        "r={'registros':t(esc('registros/decisoes/x')),'governanca':t(esc('governanca/x')),'claude':t(esc('.claude/settings.json')),\n"
        " 'C':t(esc('produtos/C/x')),'DR':t(esc('produtos/DR/saida/x')),'P3':t(esc('produtos/P3/x')),'P4':t(esc('produtos/P4/x')),\n"
        " 'restrito':t(ler('dados/restritos/doc.txt')),\n"
        " 'restrito_lista':os.listdir('dados/restritos'),'entrada':os.path.exists('dados/entrada/doc.txt'),\n"
        " 'dr_lista':t(lambda: os.listdir('produtos/DR')) and len(os.listdir('produtos/DR')),\n"
        " 'log':t(esc('logs/guarda-p3.jsonl')),'log_lista':t(lambda: os.listdir('logs')) and len(os.listdir('logs')),\n"
        " 'etc':t(esc('/etc/ppp-x')),'home':t(esc('@HOME@/ok')),'rede':t(conecta),\n"
        " 'run':os.listdir('/run'),'root':os.listdir('/root'),'home_dir':os.listdir('/home'),'irmaos':os.listdir(os.path.dirname('@HOME@')),\n"
        " 'remonta':os.system('mount -o remount,rw /srv >/dev/null 2>&1')==0,'uid':os.getuid()}\n"
        "print(json.dumps(r))\n")

    def sonda(self, papel, rede="gateway"):
        r = self.executa(papel, self.PROBA.replace('@HOME@', str(self.home)).replace('@PORTA@', str(self.porta)), rede)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_argumentos_refletem_o_perfil_do_papel(self):
        ag = " ".join(J.argumentos_jaula(self.spec, "p3", self.raiz, self.home))
        self.assertIn("--cap-drop ALL", ag)
        self.assertIn("--unshare-user", ag)
        self.assertIn("--unshare-net", ag)
        self.assertIn(f"--tmpfs {self.raiz}/dados/restritos --remount-ro {self.raiz}/dados/restritos", ag)
        self.assertIn(f"--bind {self.raiz}/produtos/P3 {self.raiz}/produtos/P3", ag)
        self.assertNotIn(f"--bind {self.raiz}/produtos/C ", ag)
        rev = " ".join(J.argumentos_jaula(self.spec, "revisor", self.raiz, self.home))
        self.assertNotIn(f"--tmpfs {self.raiz}/dados/restritos", rev)       # o revisor tem direito de ler
        self.assertNotIn("--bind " + str(self.raiz) + "/produtos", rev)      # e não grava em produtos
        with self.assertRaises(ValueError):
            J.argumentos_jaula(self.spec, "inexistente", self.raiz, self.home)

    def test_agente_de_produto_so_grava_na_propria_pasta_e_nao_ve_restritos_nem_dr_nem_logs(self):
        r = self.sonda("p3")
        self.assertFalse(r["registros"] or r["governanca"] or r["claude"] or r["C"] or r["DR"] or r["P4"] or r["etc"])
        self.assertTrue(r["P3"] and r["home"])
        self.assertFalse(r["restrito"])
        self.assertEqual(r["restrito_lista"], [])
        self.assertFalse(r["entrada"])
        self.assertEqual(r["dr_lista"], 0)                                 # a pasta do DR aparece vazia
        self.assertFalse(r["log"])                                         # sem escrita nos logs, nem no próprio
        self.assertEqual(r["log_lista"], 0)                                # e sem ver os registros dos outros
        self.assertFalse(r["remonta"])

    def test_cada_papel_tem_o_seu_perfil(self):
        coord, dr, rev = self.sonda("coordenador"), self.sonda("controlador-dr"), self.sonda("revisor")
        self.assertTrue(coord["C"] and not coord["P3"] and not coord["restrito"] and not coord["DR"])
        self.assertTrue(dr["DR"] and dr["restrito"] and dr["entrada"] and not dr["C"])
        self.assertFalse(dr["registros"] or dr["P3"])
        self.assertTrue(rev["restrito"] and rev["entrada"])
        self.assertFalse(rev["C"] or rev["P3"] or rev["DR"] or rev["registros"] or rev["log"])    # o revisor não grava em lugar nenhum
        self.assertGreater(rev["log_lista"], 0)                            # mas lê os registros de auditoria

    def test_rede_do_host_e_inacessivel_no_modo_gateway_e_acessivel_no_modo_aberto(self):
        self.assertFalse(self.sonda("p3")["rede"], "a jaula deve ter namespace de rede vazio")
        self.assertTrue(self.sonda("p3", rede="aberta")["rede"], "controle positivo: sem isolamento de rede a conexão funciona")

    def test_homes_de_outros_papeis_ficam_ocultos_e_nova_sessao_userns_e_negada(self):
        if not os.path.isdir("/srv") or not os.access("/srv", os.W_OK):
            self.skipTest("sem /srv gravável: o home precisa ficar fora das pastas que a jaula já oculta")
        homes = Path(tempfile.mkdtemp(prefix="homes-", dir="/srv"))
        self.addCleanup(shutil.rmtree, homes, ignore_errors=True)
        (homes / "p3").mkdir()
        (homes / "outro-papel").mkdir()
        (homes / "outro-papel/segredo.txt").write_text("x", encoding="utf-8")
        self.home = homes / "p3"
        r = self.sonda("p3")
        self.assertEqual(r["irmaos"], ["p3"], "só o home do próprio papel pode aparecer ao lado")
        saida = self.executa("p3", "import os\nrc=os.system('unshare -Ur true >/dev/null 2>&1')\nprint('USERNS' if rc==0 else 'SEM-USERNS')")
        self.assertIn("SEM-USERNS", saida.stdout)

    def test_pastas_do_host_ficam_ocultas(self):
        r = self.sonda("p3")
        self.assertEqual(r["run"], [])
        self.assertEqual(r["root"], [])
        self.assertEqual(r["home_dir"], [])

    def test_nenhum_papel_remonta_nem_escreve_fora_do_perfil(self):
        for papel in self.spec["papeis"]:
            r = self.sonda(papel)
            self.assertFalse(r["remonta"], papel)
            self.assertFalse(r["etc"], papel)
            self.assertFalse(r["log"], papel)

    def test_sem_comando_ou_papel_invalido_recusa(self):
        base = [sys.executable, "-B", str(self.raiz / "scripts/jaula.py"), "--raiz", str(self.raiz), "--home", str(self.home)]
        self.assertNotEqual(subprocess.run([*base, "--papel", "revisor"], capture_output=True).returncode, 0)
        self.assertNotEqual(subprocess.run([*base, "--papel", "xx", "--", "true"], capture_output=True).returncode, 0)


class TestDocumentos(unittest.TestCase):
    def test_matriz_do_documento_e_a_gerada_da_especificacao(self):
        texto = (ROOT / "governanca/GOV-08-riscos-criticos.md").read_text(encoding="utf-8")
        self.assertIn(I.matriz_markdown(spec_base()), texto, "a matriz do GOV-08 diverge de papeis.json")

    def test_documentos_nao_declaram_homologacao(self):
        for nome in ("GOV-07-isolamento-por-so.md", "GOV-08-riscos-criticos.md"):
            caminho = ROOT / "governanca" / nome
            if not caminho.exists():
                continue
            texto = caminho.read_text(encoding="utf-8")
            for esperado in ("NÃO EXECUTADO", "BLOQUE"):
                self.assertIn(esperado, texto, nome)
            self.assertNotIn("HOMOLOGADO PARA DOCUMENTOS REAIS", texto.replace("NÃO HOMOLOGADO PARA DOCUMENTOS REAIS", ""), nome)


if __name__ == "__main__":
    unittest.main()
