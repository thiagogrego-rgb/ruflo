"""GOV-03: testes adversariais da fronteira de confiança.

O guardião, o agente, o aprovador humano e a âncora externa executam como
usuários de SO distintos e sem privilégios (uids sintéticos; nenhum usuário é
criado no sistema). Ser root é necessário apenas para PREPARAR a separação.
Sem Linux e root, os testes são pulados — e a fronteira NÃO fica homologada.
Todas as chaves e identidades são sintéticas e descartadas ao final.
"""
import base64
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "scripts"))

UID_GUARDIAO, UID_AGENTE, UID_HUMANO, UID_ANCORA = 52001, 52002, 52003, 52004
APTO = os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0 \
    and hasattr(socket, "SO_PEERCRED")
MOTIVO = "requer Linux e root para preparar uids separados; fronteira NÃO homologada"

PREAMBULO = """
import json, os, sys
sys.path.insert(0, {scripts!r})
def tentar(nome, f):
    try:
        f(); r = "PERMITIDO"
    except Exception as e:
        r = "NEGADO:" + type(e).__name__
    print(json.dumps({{nome: r}}))
"""


def _como(uid):
    def trocar():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return trocar


def _possuir(caminho, uid, modo):
    os.chown(caminho, uid, uid)
    os.chmod(caminho, modo)


@unittest.skipUnless(APTO, MOTIVO)
class TestFronteira(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ancora import chave_hex

        cls.base = Path(tempfile.mkdtemp(prefix="ppp-gov03-"))
        os.chmod(cls.base, 0o755)
        b = cls.base
        # Código e schemas: root, somente leitura para todos.
        cls.codigo = b / "codigo"
        (cls.codigo / "governanca").mkdir(parents=True)
        shutil.copytree(RAIZ / "scripts", cls.codigo / "scripts",
                        ignore=shutil.ignore_patterns("__pycache__", "gerar_projeto.py*"))
        shutil.copytree(RAIZ / "governanca" / "schemas", cls.codigo / "governanca" / "schemas")
        for item in [cls.codigo, *cls.codigo.rglob("*")]:
            os.chmod(item, 0o755 if item.is_dir() else 0o644)
        cls.scripts = str(cls.codigo / "scripts")
        # Raiz de governança: chave sintética mantida só em memória, nunca gravada.
        raiz = Ed25519PrivateKey.generate()
        cls.raiz = raiz                      # sintética, só em memória
        cls.ana = Ed25519PrivateKey.generate()
        guardiao = Ed25519PrivateKey.generate()
        cls.chave_guardiao_hex = chave_hex(guardiao)
        config = b / "config"
        config.mkdir(mode=0o755)
        registro = {"formato": 1, "aprovadores": [{
            "id": "ana.aprovadora", "nome": "Ana (sintética)", "tipo": "humano",
            "papeis": ["aprovador-premissas"], "produtos": ["P3"],
            "chave_publica_ed25519": chave_hex(cls.ana), "ativo": True}]}
        bruto = json.dumps(registro).encode()
        (config / "aprovadores.json").write_bytes(bruto)
        (config / "aprovadores.json.sig").write_text(base64.b64encode(raiz.sign(bruto)).decode())
        # Serviço guardião: dono exclusivo do armazenamento, da chave e do socket.
        servico = b / "servico"
        (servico / "registros" / "fontes").mkdir(parents=True)
        (servico / "registros" / "fontes" / "FONTE-001.json").write_text("{}")
        (servico / "run").mkdir()
        (servico / "guardiao.pem").write_bytes(guardiao.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        for item in [servico, *servico.rglob("*")]:
            _possuir(item, UID_GUARDIAO, 0o700 if item.is_dir() else 0o600)
        os.chmod(servico, 0o711)
        os.chmod(servico / "run", 0o755)
        cls.socket = str(servico / "run" / "g.sock")
        cls.servico = servico
        cls.config = config / "guardiao.json"
        cls.config_dados = {
            "formato": 1, "registros": str(servico / "registros"),
            "aprovadores": str(config / "aprovadores.json"),
            "chave_raiz_governanca": chave_hex(raiz),
            "chave_privada_guardiao": str(servico / "guardiao.pem"),
            "socket": cls.socket, "proponentes": {str(UID_AGENTE): "agente-p3"},
            "ancoradores": [UID_ANCORA]}
        cls.config.write_text(json.dumps(cls.config_dados))
        for item in config.iterdir():
            os.chmod(item, 0o644)
        # Aprovador humano (simula outro dispositivo) e âncora externa.
        cls.humano = b / "humano"
        cls.humano.mkdir()
        (cls.humano / "ana.pem").write_bytes(cls.ana.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        for item in [cls.humano, *cls.humano.iterdir()]:
            _possuir(item, UID_HUMANO, 0o700 if item.is_dir() else 0o600)
        cls.ancora = b / "ancora"
        cls.ancora.mkdir()
        _possuir(cls.ancora, UID_ANCORA, 0o755)
        cls.agente = b / "agente"
        cls.agente.mkdir()
        _possuir(cls.agente, UID_AGENTE, 0o700)
        cls.caixa = b / "caixa"            # meio de troca não confiável
        cls.caixa.mkdir()
        os.chmod(cls.caixa, 0o1777)
        cls.processo = cls.iniciar_guardiao(cls.config, UID_GUARDIAO)
        linha = cls.processo.stdout.readline()
        if linha.strip() != "PRONTO":
            cls.processo.kill()
            raise RuntimeError("Guardião não iniciou: " + linha + cls.processo.stderr.read())

    @classmethod
    def iniciar_guardiao(cls, config, uid, scripts=None):
        return subprocess.Popen(
            [sys.executable, "-I", "-B", f"{scripts or cls.scripts}/guardiao.py", str(config)],
            preexec_fn=_como(uid) if uid else None, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, cwd="/", env={"PATH": "/usr/bin:/bin"})

    @classmethod
    def tearDownClass(cls):
        cls.processo.terminate()
        cls.processo.communicate(timeout=10)
        shutil.rmtree(cls.base)

    def executar(self, uid, codigo, timeout=60):
        resultado = subprocess.run(
            [sys.executable, "-I", "-B", "-c", PREAMBULO.format(scripts=self.scripts) + codigo],
            preexec_fn=_como(uid), capture_output=True, text=True, timeout=timeout,
            cwd=str(self.caixa), env={"PATH": "/usr/bin:/bin", "HOME": str(self.agente)})
        saidas = {}
        for linha in resultado.stdout.splitlines():
            if linha.startswith("{"):
                saidas.update(json.loads(linha))
        if resultado.returncode != 0:
            self.fail(f"Execução falhou: {resultado.stderr[-1500:]}")
        return saidas

    def config_alternativa(self, nome, *, registro=None, assinatura=None, **sobrescritas):
        """Configuração/cadastro alternativos, protegidos como a configuração real.

        `assinatura=False` omite o arquivo .sig; `ancoradores=None` omite a chave.
        """
        pasta = self.base / f"cfg-{nome}"
        pasta.mkdir(mode=0o755)
        origem = self.config.parent
        (pasta / "aprovadores.json").write_bytes(
            registro if registro is not None else (origem / "aprovadores.json").read_bytes())
        if assinatura is not False:
            (pasta / "aprovadores.json.sig").write_text(
                assinatura if assinatura is not None
                else (origem / "aprovadores.json.sig").read_text())
        dados = dict(self.config_dados, aprovadores=str(pasta / "aprovadores.json"),
                     socket=str(self.servico / "run" / f"{nome}.sock"))
        dados.update(sobrescritas)
        if dados.get("ancoradores", 0) is None:
            dados.pop("ancoradores")
        arquivo = pasta / "guardiao.json"
        arquivo.write_text(json.dumps(dados))
        for item in pasta.iterdir():
            os.chmod(item, 0o644)
        return arquivo

    def tentar_iniciar(self, arquivo, uid=UID_GUARDIAO, scripts=None):
        """(código de saída, stderr); código None se o guardião chegou a ficar PRONTO.

        Sempre encerra o processo que chegou a iniciar: um controle enfraquecido
        faria o guardião subir, e o teste não pode deixar serviço órfão. Use
        configurações com socket PRÓPRIO (`config_alternativa`), nunca o principal.
        """
        processo = self.iniciar_guardiao(arquivo, uid, scripts)
        if select.select([processo.stdout], [], [], 15)[0]:
            if processo.stdout.readline().strip() == "PRONTO":
                processo.kill()
                processo.communicate()
                return None, ""
            _, erro = processo.communicate(timeout=30)
            return processo.returncode, erro
        processo.kill()
        processo.communicate()
        return None, "sem resposta em 15 s"

    @contextmanager
    def guardiao_alternativo(self, arquivo):
        processo = self.iniciar_guardiao(arquivo, UID_GUARDIAO)
        try:
            self.assertEqual(processo.stdout.readline().strip(), "PRONTO")
            yield
        finally:
            processo.kill()
            processo.communicate()

    def checkpoints_emitidos(self):
        return len(list((self.servico / "registros" / "ancora").glob("seq-*.json")))

    def como_agente(self, codigo):
        return self.executar(UID_AGENTE, codigo)

    def assertTudoNegado(self, saidas):
        self.assertTrue(saidas)
        permitidos = {k: v for k, v in saidas.items() if not v.startswith("NEGADO")}
        self.assertEqual(permitidos, {}, "FALHA CRÍTICA: o agente conseguiu")

    # -- utilitários do fluxo legítimo ---------------------------------------
    def propor(self, premissa_id, versao=1, valor=42.5):
        return self.como_agente(f"""
import cliente_guardiao as c
p = dict(id={premissa_id!r}, versao={versao}, produto="P3", natureza="OBSERVADO",
         unidade="BRL/m2/mes", status="PROPOSTA", fonte_id="FONTE-001", valor={valor})
print(json.dumps({{"sha": c.propor(p, caminho_socket={self.socket!r})["sha256"]}}))
exp = c.exportar_versao({premissa_id!r}, {versao}, caminho_socket={self.socket!r})
from governanca import canonico
open({str(self.caixa)!r} + "/{premissa_id}-v{versao}.json", "wb").write(canonico(exp["envelope"]))
""")["sha"]

    def humano_assina(self, premissa_id, versao):
        """Aprovador humano lê o envelope exportado, assina com sua chave e devolve."""
        self.executar(UID_HUMANO, f"""
from cryptography.hazmat.primitives import serialization
import aprovacao
from premissas_repositorio import sha256
bruto = open({str(self.caixa)!r} + "/{premissa_id}-v{versao}.json", "rb").read()
chave = serialization.load_pem_private_key(open({str(self.humano)!r} + "/ana.pem", "rb").read(), None)
p = aprovacao.payload_aprovacao({premissa_id!r}, {versao}, sha256(bruto), "ana.aprovadora",
                                "2026-10-24T12:00:00+00:00")
json.dump(aprovacao.assinar(p, chave), open({str(self.caixa)!r} + "/{premissa_id}-v{versao}.aprov", "w"))
os.chmod({str(self.caixa)!r} + "/{premissa_id}-v{versao}.aprov", 0o644)
""")

    def agente_registra(self, premissa_id, versao):
        return self.como_agente(f"""
import cliente_guardiao as c
a = json.load(open({str(self.caixa)!r} + "/{premissa_id}-v{versao}.aprov"))
tentar("registrar", lambda: c.registrar_aprovacao(a, caminho_socket={self.socket!r}))
print(json.dumps({{"estado": c.estado({premissa_id!r}, {versao}, caminho_socket={self.socket!r})}}))
""")

    # -- testes --------------------------------------------------------------
    def test_00_fluxo_legitimo(self):
        self.propor("PREM-100")
        self.humano_assina("PREM-100", 1)
        saidas = self.agente_registra("PREM-100", 1)
        self.assertEqual(saidas, {"registrar": "PERMITIDO", "estado": "APROVADA"})

    def test_agente_nao_modifica_verificador(self):
        alvo = f"{self.scripts}/aprovacao.py"
        self.assertTudoNegado(self.como_agente(f"""
tentar("acrescentar", lambda: open({alvo!r}, "a").write("x"))
open("falso.py", "w").write("pass")
tentar("substituir", lambda: os.replace("falso.py", {alvo!r}))
tentar("criar_sitecustomize", lambda: open({self.scripts!r} + "/sitecustomize.py", "x"))
tentar("criar_modulo_sombra", lambda: open({self.scripts!r} + "/jsonschema.py", "x"))
tentar("alterar_schema", lambda: open({str(self.codigo)!r} + "/governanca/schemas/aprovacao.schema.json", "a"))
tentar("chmod", lambda: os.chmod({alvo!r}, 0o666))
"""))

    def test_agente_nao_altera_cadastro_nem_configuracao(self):
        self.assertTudoNegado(self.como_agente(f"""
for nome in ("aprovadores.json", "aprovadores.json.sig", "guardiao.json"):
    tentar("escrever_" + nome, lambda: open({str(self.config.parent)!r} + "/" + nome, "a").write(" "))
tentar("criar_no_config", lambda: open({str(self.config.parent)!r} + "/novo.json", "x"))
tentar("listar_armazenamento", lambda: os.listdir({str(self.servico)!r} + "/registros"))
"""))

    def test_agente_nao_obtem_chave_privada(self):
        pid = self.processo.pid
        self.assertTudoNegado(self.como_agente(f"""
tentar("chave_humano", lambda: open({str(self.humano)!r} + "/ana.pem", "rb").read())
tentar("chave_guardiao", lambda: open({str(self.servico)!r} + "/guardiao.pem", "rb").read())
tentar("memoria_guardiao", lambda: open("/proc/{pid}/mem", "rb").read(1))
tentar("ambiente_guardiao", lambda: open("/proc/{pid}/environ", "rb").read())
"""))

    def test_agente_nao_cadastra_identidade_propria_nem_autoaprova(self):
        self.propor("PREM-101")
        saidas = self.como_agente(f"""
import aprovacao, cliente_guardiao as c
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from premissas_repositorio import sha256
bruto = open({str(self.caixa)!r} + "/PREM-101-v1.json", "rb").read()
minha = Ed25519PrivateKey.generate()
for ident in ("agente-p3", "ana.aprovadora", "novo.aprovador"):
    a = aprovacao.assinar(aprovacao.payload_aprovacao("PREM-101", 1, sha256(bruto), ident,
                          "2026-10-24T12:00:00+00:00"), minha)
    tentar("aprovar_como_" + ident, lambda: c.registrar_aprovacao(a, caminho_socket={self.socket!r}))
print(json.dumps({{"estado": "NEGADO:" + c.estado("PREM-101", 1, caminho_socket={self.socket!r})}}))
""")
        self.assertEqual(saidas.pop("estado"), "NEGADO:PROPOSTA")
        self.assertTudoNegado(saidas)

    def test_agente_adultera_o_que_o_humano_assina(self):
        self.propor("PREM-102", valor=10.0)
        self.como_agente(f"""
caminho = {str(self.caixa)!r} + "/PREM-102-v1.json"
env = json.load(open(caminho)); env["premissa"]["valor"] = 99999.0
from governanca import canonico
open(caminho, "wb").write(canonico(env))
""")
        self.humano_assina("PREM-102", 1)
        saidas = self.agente_registra("PREM-102", 1)
        self.assertEqual(saidas["registrar"], "NEGADO:ErroGuardiao")
        self.assertEqual(saidas["estado"], "PROPOSTA")

    def test_agente_nao_reverte_nem_exclui(self):
        self.propor("PREM-103")
        self.propor("PREM-103", versao=2, valor=50.0)
        d = f"{self.servico}/registros/premissas/PREM-103"
        self.assertTudoNegado(self.como_agente(f"""
import cliente_guardiao as c
tentar("excluir_v2", lambda: os.unlink({d!r} + "/v2.json"))
tentar("renomear_v2", lambda: os.rename({d!r} + "/v2.json", {d!r} + "/x"))
tentar("excluir_diretorio", lambda: os.rmdir({d!r}))
for op in ("excluir", "reverter", "restaurar"):
    tentar("api_" + op, lambda: c.chamar({{"op": op, "id": "PREM-103"}}, caminho_socket={self.socket!r}))
p = dict(id="PREM-103", versao=2, produto="P3", natureza="OBSERVADO", unidade="u",
         status="PROPOSTA", fonte_id="FONTE-001", valor=1.0)
tentar("reescrever_v2", lambda: c.propor(p, caminho_socket={self.socket!r}))
"""))

    def test_agente_nao_falsifica_proponente(self):
        self.propor("PREM-104")
        p = ('dict(id="PREM-105", versao=1, produto="P3", natureza="OBSERVADO", unidade="u",'
             ' status="PROPOSTA", fonte_id="FONTE-001")')
        self.assertTudoNegado(self.como_agente(f"""
import cliente_guardiao as c
tentar("campo_proponente", lambda: c.chamar({{"op": "propor", "premissa": {p},
       "proponente": "ana.aprovadora"}}, caminho_socket={self.socket!r}))
"""))
        self.assertTudoNegado(self.executar(UID_HUMANO, f"""
import cliente_guardiao as c
tentar("uid_nao_cadastrado", lambda: c.propor({p}, caminho_socket={self.socket!r}))
"""))
        envelope = json.loads((self.caixa / "PREM-104-v1.json").read_bytes())
        self.assertEqual(envelope["proponente"], "agente-p3")

    def test_agente_nao_contorna_por_terminal_ou_subprocesso(self):
        pid = self.processo.pid
        assinador = f"{self.scripts}/assinar_aprovacao.py"
        saidas = self.como_agente(f"""
import pty, signal, subprocess
tentar("setuid_root", lambda: os.setuid(0))
tentar("sinal_guardiao", lambda: os.kill({pid}, signal.SIGKILL))
def sudo():
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        raise PermissionError("sudo negado")
tentar("sudo", sudo)
def subprocesso_escreve():
    r = subprocess.run([sys.executable, "-c", "open({str(self.servico)!r}+'/registros/x','w')"],
                       capture_output=True)
    if r.returncode != 0:
        raise PermissionError("subprocesso negado")
tentar("subprocesso", subprocesso_escreve)
from premissas_repositorio import sha256
prefixo = sha256(open({str(self.caixa)!r} + "/PREM-100-v1.json", "rb").read())[:8].encode()
def assinar_via_pty():
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, {assinador!r}, "assinar",
                 "--chave", {str(self.humano)!r} + "/ana.pem", "--aprovador", "ana.aprovadora",
                 "--premissa", "PREM-100", "--versao", "1",
                 "--envelope", {str(self.caixa)!r} + "/PREM-100-v1.json", "--saida", "/tmp/x.aprov"])
    saida = b""
    while True:
        try:
            dados = os.read(fd, 4096)
        except OSError:
            break
        if not dados:
            break
        saida += dados
        if saida.endswith(b"aprovar: "):
            os.write(fd, prefixo + b"\\n")
        elif saida.endswith(b"chave: "):
            os.write(fd, b"qualquer\\n")
    _, st = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(st) != 0 and b"PermissionError" in saida:
        raise PermissionError("chave do aprovador ilegível para o agente")
    print(json.dumps({{"inconclusivo": saida[-300:].decode(errors="replace")}}))
tentar("assinar_via_pty", assinar_via_pty)
""")
        self.assertTudoNegado(saidas)
        self.assertIsNone(self.processo.poll(), "o guardião deveria seguir em execução")

    def test_guardiao_recusa_configuracao_insegura(self):
        codigo, erro = self.tentar_iniciar(self.config_alternativa("como-root"), uid=None)
        self.assertEqual(codigo, 3, "guardião iniciou como root")
        self.assertIn("root", erro)
        inseguro = self.base / "config-inseguro.json"
        dados = dict(self.config_dados, socket=str(self.servico / "run" / "inseguro.sock"))
        inseguro.write_text(json.dumps(dados))
        os.chmod(inseguro, 0o666)                    # gravável pelo agente
        codigo, erro = self.tentar_iniciar(inseguro)
        self.assertEqual(codigo, 3, "guardião iniciou com configuração gravável por terceiros")
        self.assertIn("protegido", erro)

    def test_ancorador_obtem_checkpoints_encadeados(self):
        import ancora
        from premissas_repositorio import RepositorioPremissas, sha256
        from governanca import canonico
        self.propor("PREM-108")
        saidas = self.executar(UID_ANCORA, f"""
import cliente_guardiao as c
print(json.dumps({{"cp1": c.chamar({{"op": "checkpoint"}}, caminho_socket={self.socket!r})}}))
print(json.dumps({{"cp2": c.chamar({{"op": "checkpoint"}}, caminho_socket={self.socket!r})}}))
""")
        primeiro, segundo = saidas["cp1"], saidas["cp2"]
        self.assertEqual(segundo["payload"]["seq"], primeiro["payload"]["seq"] + 1)
        self.assertEqual(segundo["payload"]["anterior"], sha256(canonico(primeiro)))
        repo = RepositorioPremissas(self.servico / "registros")
        self.assertTrue(ancora.verificar_checkpoint(repo, segundo, self.chave_guardiao_hex,
                                                    anterior=primeiro))
        self.assertIn("PREM-108", segundo["payload"]["estado"])

    def test_ancorador_so_ancora_e_nao_cria_nem_aprova(self):
        self.propor("PREM-110")
        self.humano_assina("PREM-110", 1)         # aprovação válida pronta, não registrada
        saidas = self.executar(UID_ANCORA, f"""
import cliente_guardiao as c
S = {self.socket!r}
a = json.load(open({str(self.caixa)!r} + "/PREM-110-v1.aprov"))
p = dict(id="PREM-111", versao=1, produto="P3", natureza="OBSERVADO", unidade="u",
         status="PROPOSTA", fonte_id="FONTE-001", valor=1.0)
tentar("propor", lambda: c.propor(p, caminho_socket=S))
tentar("registrar_aprovacao_valida", lambda: c.registrar_aprovacao(a, caminho_socket=S))
tentar("estado", lambda: c.estado("PREM-110", 1, caminho_socket=S))
tentar("exportar_versao", lambda: c.exportar_versao("PREM-110", 1, caminho_socket=S))
tentar("ler_aprovada", lambda: c.chamar({{"op": "ler_aprovada", "id": "PREM-110"}}, caminho_socket=S))
tentar("checkpoint_com_premissa", lambda: c.chamar({{"op": "checkpoint", "premissa": p}}, caminho_socket=S))
tentar("checkpoint_declarando_proponente", lambda: c.chamar({{"op": "checkpoint", "proponente": "agente-p3"}}, caminho_socket=S))
tentar("operacao_inexistente", lambda: c.chamar({{"op": "excluir", "id": "PREM-110"}}, caminho_socket=S))
tentar("pedido_nao_objeto", lambda: c.chamar(["checkpoint"], caminho_socket=S))
""")
        self.assertTudoNegado(saidas)
        self.assertFalse((self.servico / "registros" / "premissas" / "PREM-111").exists())
        self.assertFalse((self.servico / "registros" / "premissas" / "PREM-110"
                          / "v1.aprovacao.json").exists())
        self.assertEqual(self.como_agente(f"""
import cliente_guardiao as c
print(json.dumps({{"e": c.estado("PREM-110", 1, caminho_socket={self.socket!r})}}))
""")["e"], "PROPOSTA")

    def test_proponente_nao_adquire_permissao_de_ancoragem(self):
        antes = self.checkpoints_emitidos()
        saidas = self.como_agente(f"""
import cliente_guardiao as c
S = {self.socket!r}
tentar("checkpoint", lambda: c.chamar({{"op": "checkpoint"}}, caminho_socket=S))
tentar("checkpoint_alegando_papel", lambda: c.chamar({{"op": "checkpoint", "papel": "ancorador"}}, caminho_socket=S))
tentar("checkpoint_alegando_uid", lambda: c.chamar({{"op": "checkpoint", "uid": {UID_ANCORA}}}, caminho_socket=S))
""")
        self.assertTudoNegado(saidas)
        self.assertEqual(self.checkpoints_emitidos(), antes)

    def test_guardiao_recusa_codigo_gravavel_por_terceiros(self):
        copia = self.base / "codigo-gravavel"
        shutil.copytree(self.codigo, copia)
        os.chmod(copia / "scripts" / "aprovacao.py", 0o666)      # verificador gravável por todos
        codigo, erro = self.tentar_iniciar(self.config_alternativa("codigo-gravavel"),
                                           scripts=str(copia / "scripts"))
        self.assertEqual(codigo, 3, "guardião iniciou com verificador gravável")
        self.assertIn("aprovacao.py", erro)
        self.assertIn("protegido", erro)

    def test_identidade_vem_do_kernel_e_nao_do_cliente(self):
        antes = self.checkpoints_emitidos()
        self.assertTudoNegado(self.executar(UID_HUMANO, f"""
import cliente_guardiao as c
S = {self.socket!r}
tentar("uid_nao_cadastrado", lambda: c.chamar({{"op": "checkpoint"}}, caminho_socket=S))
tentar("alegando_uid_ancorador", lambda: c.chamar({{"op": "checkpoint", "uid": {UID_ANCORA}}}, caminho_socket=S))
tentar("alegando_papel", lambda: c.chamar({{"op": "checkpoint", "papel": "ancorador"}}, caminho_socket=S))
tentar("alegando_proponente", lambda: c.chamar({{"op": "propor", "proponente": "agente-p3"}}, caminho_socket=S))
"""))
        self.assertEqual(self.checkpoints_emitidos(), antes)

    def test_configuracao_recusa_ancoradores_invalidos_ou_conflitantes(self):
        casos = {
            "igual-proponente": [UID_AGENTE],
            "igual-guardiao": [UID_GUARDIAO],
            "root": [0],
            "negativo": [-5],
            "booleano": [True],
            "texto": [str(UID_ANCORA)],
            "nao-lista": UID_ANCORA,
        }
        for nome, valor in casos.items():
            with self.subTest(nome):
                codigo, erro = self.tentar_iniciar(
                    self.config_alternativa(f"anc-{nome}", ancoradores=valor))
                self.assertEqual(codigo, 3, f"guardião iniciou com ancoradores={valor!r}")
                self.assertIn("RECUSADO", erro)

    def test_cadastro_adulterado_com_guardiao_em_execucao_bloqueia_aprovacoes(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ancora import chave_hex
        for premissa_id in ("PREM-112", "PREM-113"):
            self.propor(premissa_id)
            self.humano_assina(premissa_id, 1)
        arquivo = self.config_alternativa("vivo")
        alternativo = str(self.servico / "run" / "vivo.sock")
        registrar = lambda pid: f"""
import cliente_guardiao as c
a = json.load(open({str(self.caixa)!r} + "/{pid}-v1.aprov"))
tentar("registrar_{pid}", lambda: c.registrar_aprovacao(a, caminho_socket={alternativo!r}))
"""
        with self.guardiao_alternativo(arquivo):
            controle = self.como_agente(registrar("PREM-112"))      # cadastro íntegro
            self.assertEqual(controle, {"registrar_PREM-112": "PERMITIDO"})
            registro = Path(json.loads(arquivo.read_text())["aprovadores"])
            dados = json.loads(registro.read_text())               # root adultera o cadastro
            dados["aprovadores"].append(dict(
                dados["aprovadores"][0], id="intruso.agente", nome="Intruso",
                chave_publica_ed25519=chave_hex(Ed25519PrivateKey.generate())))
            registro.write_text(json.dumps(dados))
            self.assertTudoNegado(self.como_agente(registrar("PREM-113")))
            self.assertTudoNegado(self.como_agente(f"""
import cliente_guardiao as c
tentar("estado_ja_aprovada", lambda: c.estado("PREM-112", 1, caminho_socket={alternativo!r}))
tentar("ler_aprovada", lambda: c.chamar({{"op": "ler_aprovada", "id": "PREM-112"}}, caminho_socket={alternativo!r}))
"""))
        premissas = self.servico / "registros" / "premissas"
        self.assertTrue((premissas / "PREM-112" / "v1.aprovacao.json").exists())
        self.assertFalse((premissas / "PREM-113" / "v1.aprovacao.json").exists())

    def test_controle_positivo_configuracao_alternativa_valida_inicia(self):
        codigo, erro = self.tentar_iniciar(self.config_alternativa("controle"))
        self.assertIsNone(codigo, erro)

    def test_ancorador_ausente_da_configuracao_ninguem_ancora(self):
        antes = self.checkpoints_emitidos()
        arquivo = self.config_alternativa("sem-ancoradores", ancoradores=None)
        with self.guardiao_alternativo(arquivo):
            alternativo = str(self.servico / "run" / "sem-ancoradores.sock")
            for uid in (UID_ANCORA, UID_AGENTE):
                self.assertTudoNegado(self.executar(uid, f"""
import cliente_guardiao as c
tentar("checkpoint", lambda: c.chamar({{"op": "checkpoint"}}, caminho_socket={alternativo!r}))
"""))
        self.assertEqual(self.checkpoints_emitidos(), antes)

    def test_cadastro_de_aprovadores_exige_assinatura_da_raiz(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ancora import chave_hex
        original = (self.config.parent / "aprovadores.json").read_bytes()
        adulterado = json.loads(original)
        adulterado["aprovadores"].append(dict(
            adulterado["aprovadores"][0], id="intruso.agente", nome="Intruso",
            chave_publica_ed25519=chave_hex(Ed25519PrivateKey.generate())))
        adulterado = json.dumps(adulterado).encode()
        outra_raiz = Ed25519PrivateKey.generate()
        casos = {
            "registro-adulterado": dict(registro=adulterado),
            "sem-assinatura": dict(assinatura=False),
            "assinado-por-outra-raiz": dict(
                assinatura=base64.b64encode(outra_raiz.sign(original)).decode()),
            "raiz-configurada-diferente": dict(raiz_hex=chave_hex(outra_raiz)),
            "assinatura-lixo": dict(assinatura="nao-e-base64!!"),
        }
        for nome, opcoes in casos.items():
            with self.subTest(nome):
                raiz_hex = opcoes.pop("raiz_hex", None)
                extras = {"chave_raiz_governanca": raiz_hex} if raiz_hex else {}
                codigo, erro = self.tentar_iniciar(
                    self.config_alternativa(f"reg-{nome}", **opcoes, **extras))
                self.assertEqual(codigo, 3, f"guardião iniciou com cadastro não verificável ({nome})")
                self.assertIn("RECUSADO", erro)

    def test_rollback_no_host_do_guardiao_e_detectado(self):
        """Simula comprometimento do host (root) e verifica contra a âncora externa.

        DESTRUTIVO: apaga arquivos do armazenamento; por isso deve ser o último
        da classe (ordem alfabética). Testes que dependem de checkpoint válido
        precisam ter nome anterior a "test_rollback".
        """
        import ancora
        from premissas_repositorio import RepositorioPremissas
        self.propor("PREM-106")
        self.propor("PREM-106", versao=2, valor=55.0)
        self.humano_assina("PREM-106", 2)
        self.assertEqual(self.agente_registra("PREM-106", 2)["estado"], "APROVADA")
        externo = self.ancora / "seq.json"
        saidas = self.executar(UID_ANCORA, f"""
import cliente_guardiao as c
cp = c.chamar({{"op": "checkpoint"}}, caminho_socket={self.socket!r})
open({str(externo)!r}, "x").write(json.dumps(cp)); os.chmod({str(externo)!r}, 0o444)
p = dict(id="PREM-107", versao=1, produto="P3", natureza="OBSERVADO", unidade="u",
         status="PROPOSTA", fonte_id="FONTE-001")
tentar("ancorador_propoe", lambda: c.propor(p, caminho_socket={self.socket!r}))
""")
        self.assertTudoNegado(saidas)
        repo = RepositorioPremissas(self.servico / "registros")
        ancorado = json.loads(externo.read_text())
        self.assertTrue(ancora.verificar_checkpoint(repo, ancorado, self.chave_guardiao_hex))
        d = self.servico / "registros" / "premissas" / "PREM-106"
        (d / "v2.aprovacao.json").unlink()           # ação de root: fora do modelo do agente
        (d / "v2.json").unlink()
        with self.assertRaises(ancora.RollbackDetectado):
            ancora.verificar_checkpoint(repo, ancorado, self.chave_guardiao_hex)
        forjado = json.loads(json.dumps(ancorado))
        forjado["payload"]["estado"].pop("PREM-106")
        with self.assertRaises(ancora.RollbackDetectado):
            ancora.verificar_checkpoint(repo, forjado, self.chave_guardiao_hex)


if __name__ == "__main__":
    unittest.main()
