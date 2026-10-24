"""Serviço guardião (GOV-03/GOV-04): única autoridade de escrita sobre premissas.

Executa com usuário de SO próprio, distinto do agente e de root. O agente não
tem escrita no armazenamento, no registro de aprovadores, na configuração nem
neste código; interage apenas pelo socket Unix. A identidade do proponente é
obtida do kernel (SO_PEERCRED), nunca da requisição.

Perfis de configuração:
- formato 2 (ESTRITO, para produção): exige referência externa de série do cadastro,
  ambiente Python conferido contra `requirements.lock`, modo isolado e limites estritos;
- formato 1 (LEGADO, só desenvolvimento/testes): aceito por compatibilidade com o GOV-03,
  sem proteção de rollback do cadastro nem verificação do ambiente, e com limites folgados.
  `--estrito` recusa iniciar com formato 1.

    python3 -I -B -X pycache_prefix=/nonexistent guardiao.py --estrito /etc/ppp-betim/guardiao.json
"""
import json
import os
import re
import socket
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path

CODIGO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODIGO / "scripts"))

import ambiente  # noqa: E402
import ancora  # noqa: E402
import aprovacao  # noqa: E402
from governanca import canonico, carregar_validador, erros_schema  # noqa: E402
from limites import LimiteExcedido, LimitadorTaxa, Limites, limites_estritos  # noqa: E402
from premissas_repositorio import RepositorioPremissas, gravar_exclusivo, sha256  # noqa: E402
from protecao import ConfiguracaoInsegura, exigir_protegido  # noqa: E402,F401  (nomes reexportados)
from serie import PoliticaSerie, substituir_atomico  # noqa: E402

LIMITE_REQUISICAO = 1 << 20          # mantido por compatibilidade; o limite efetivo vem de Limites
CAMPOS_PERMITIDOS = {"op", "premissa", "aprovacao", "id", "versao"}
LOCK_AMBIENTE = CODIGO / "requirements.lock"
AVISO_LEGADO = ("AVISO: perfil legado (formato 1): sem proteção de rollback do cadastro de "
                "aprovadores, sem verificação do ambiente Python e com limites folgados. "
                "Use formato 2 em produção.")


class ServidorOcupado(Exception):
    """Conexões simultâneas além do limite."""


def carregar_configuracao(caminho, estrito=False):
    uid = os.getuid()
    if uid == 0 or os.geteuid() == 0:
        raise ConfiguracaoInsegura("O guardião não executa como root")
    exigir_protegido(caminho, uid)
    exigir_protegido(CODIGO, uid, recursivo=True)
    config = json.loads(Path(caminho).read_text(encoding="utf-8"))     # só biblioteca padrão
    if isinstance(config, dict) and config.get("formato") == 2:
        # Verificar ANTES do primeiro import de código de terceiros (jsonschema/cryptography).
        ambiente.verificar(LOCK_AMBIENTE, uid_servico=uid, exigir_isolado=True, exigir_sem_pyc=True)
    elif estrito:
        raise ConfiguracaoInsegura("--estrito exige configuração de formato 2")
    erros = erros_schema(carregar_validador("guardiao.schema.json"), config)
    if erros:
        raise ConfiguracaoInsegura("Configuração inválida: " + "; ".join(erros))
    exigir_protegido(config["aprovadores"], uid)
    exigir_protegido(f"{config['aprovadores']}.sig", uid)
    chave = Path(config["chave_privada_guardiao"])
    st = chave.stat()
    if st.st_uid != uid or st.st_mode & 0o077:
        raise ConfiguracaoInsegura("Chave do guardião deve pertencer ao serviço com modo 0600")
    for registros in (config["registros"], Path(config["socket"]).parent):
        exigir_protegido(registros, uid)
        if Path(registros).stat().st_uid != uid:
            raise ConfiguracaoInsegura(f"{registros} deve pertencer ao serviço")
    if config["formato"] == 2:
        referencia = Path(config["referencia_serie"])
        exigir_protegido(referencia, uid)
        if referencia.stat().st_uid != 0:
            raise ConfiguracaoInsegura("A referência externa de série deve pertencer a root, "
                                       "fora do controle do próprio serviço")
        if referencia.resolve().is_relative_to(Path(config["registros"]).resolve()):
            raise ConfiguracaoInsegura("A referência externa não pode ficar dentro do armazenamento do guardião")
    proponentes = {int(u): i for u, i in config["proponentes"].items()}
    ancoradores = set(config.get("ancoradores", []))
    if uid in proponentes or 0 in proponentes:
        raise ConfiguracaoInsegura("Proponente não pode ser root nem o próprio guardião")
    if ancoradores & (set(proponentes) | {uid}):
        raise ConfiguracaoInsegura("Ancorador não pode ser proponente nem o próprio guardião")
    aprovadores = aprovacao.carregar_aprovadores(config["aprovadores"],
                                                 config["chave_raiz_governanca"])
    if set(proponentes.values()) & set(aprovadores):
        raise ConfiguracaoInsegura("Identidades de proponentes e aprovadores devem ser disjuntas")
    return config, proponentes, ancoradores


class Guardiao:
    def __init__(self, caminho_config, estrito=False):
        from cryptography.hazmat.primitives import serialization
        self.config, self.proponentes, self.ancoradores = carregar_configuracao(caminho_config, estrito)
        registros = Path(self.config["registros"])
        self.estrito = self.config["formato"] == 2
        if self.estrito:
            self.limites = limites_estritos(**self.config.get("limites", {}))
            self.politica_serie = PoliticaSerie(self.config["referencia_serie"],
                                                registros / "estado" / "serie-cadastro.json",
                                                self.config["chave_raiz_governanca"])
        else:
            self.limites = Limites()
            self.politica_serie = None
        self.limitador = LimitadorTaxa(self.limites.operacoes_por_minuto, self.limites.rajada,
                                       self.limites.max_identidades_rastreadas)
        self.repo = RepositorioPremissas(
            self.config["registros"], self.config["aprovadores"], self.config["chave_raiz_governanca"],
            politica_serie=self.politica_serie, limites=self.limites)
        self.chave = serialization.load_pem_private_key(
            Path(self.config["chave_privada_guardiao"]).read_bytes(), password=None)
        self.ultimo_checkpoint = registros / "ancora" / "ultimo.json"
        self.trava = threading.Lock()                   # um único escritor por vez
        self._trava_conexoes = threading.Lock()
        self._conexoes_por_uid = {}
        self._ultimo_checkpoint_em = None
        self.recuperado = self.recuperar()
        if self.politica_serie is not None:
            self.cadastro_vigente()      # falha cedo e inicializa a marca d'água da série

    # -- conexões simultâneas ------------------------------------------------------
    def reservar_conexao(self, uid):
        """Reserva uma vaga global e por identidade; falso se qualquer teto for atingido."""
        with self._trava_conexoes:
            if (sum(self._conexoes_por_uid.values()) >= self.limites.max_conexoes
                    or self._conexoes_por_uid.get(uid, 0) >= self.limites.max_conexoes_por_identidade):
                return False
            self._conexoes_por_uid[uid] = self._conexoes_por_uid.get(uid, 0) + 1
            return True

    def liberar_conexao(self, uid):
        with self._trava_conexoes:
            restante = self._conexoes_por_uid.get(uid, 0) - 1
            if restante > 0:
                self._conexoes_por_uid[uid] = restante
            else:
                self._conexoes_por_uid.pop(uid, None)

    # -- cadastro e recuperação ------------------------------------------------
    def cadastro_vigente(self):
        """Valida o cadastro contra a política de série e devolve {"serie", "sha256"}."""
        aprovacao.carregar_aprovadores(self.config["aprovadores"], self.config["chave_raiz_governanca"],
                                       self.politica_serie)
        serie, resumo = self.politica_serie.ultima
        return {"serie": serie, "sha256": resumo}

    def recuperar(self):
        """Remove restos de gravações interrompidas e conclui um checkpoint já gravado."""
        relato = [f"removido temporário {t}" for t in self.repo.recuperar()]
        relato += [f"removida pasta vazia {p}" for p in self.repo.recuperar_diretorios_vazios()]
        if self.politica_serie is not None:
            relato += [f"removido temporário {t}" for t in self.politica_serie.recuperar()]
        return relato + self.recuperar_checkpoints()

    def recuperar_checkpoints(self):
        pasta = self.ultimo_checkpoint.parent
        if not pasta.is_dir():
            return []
        relato = []
        for temporario in sorted(pasta.glob(".*.tmp")):
            temporario.unlink()
            relato.append(f"removido temporário {temporario}")
        arquivos = {int(m.group(1)): a for a in pasta.glob("seq-*.json")
                    if (m := re.fullmatch(r"seq-([1-9][0-9]*)\.json", a.name))}
        if not arquivos:
            if self.ultimo_checkpoint.exists():
                raise ConfiguracaoInsegura("ultimo.json existe, mas não há checkpoints seq-N (removidos?)")
            return relato
        ordem = sorted(arquivos)
        if ordem != list(range(1, len(ordem) + 1)):
            raise ConfiguracaoInsegura(f"Checkpoints locais com lacuna na sequência: {ordem}")
        publica, anterior = ancora.chave_hex(self.chave), None
        for numero in ordem:
            bruto = arquivos[numero].read_bytes()
            try:
                atual = json.loads(bruto)
                valido = (canonico(atual) == bruto and atual["payload"]["seq"] == numero
                          and atual["payload"]["anterior"] == (None if anterior is None
                                                               else sha256(canonico(anterior)))
                          and aprovacao.verificar_assinatura(publica, atual["assinatura"],
                                                             canonico(atual["payload"])))
            except (ValueError, KeyError, TypeError):
                valido = False
            if not valido:
                raise ConfiguracaoInsegura(f"Checkpoint local seq-{numero} inválido ou adulterado")
            anterior = atual
        if self.ultimo_checkpoint.exists():
            try:
                registrado = json.loads(self.ultimo_checkpoint.read_bytes())
                seq_registrado = registrado["payload"]["seq"]
            except (ValueError, KeyError, TypeError) as erro:
                raise ConfiguracaoInsegura("ultimo.json ilegível") from erro
            if seq_registrado > ordem[-1]:
                raise ConfiguracaoInsegura(
                    f"ultimo.json aponta seq {seq_registrado}, mas o maior arquivo é seq-{ordem[-1]}")
            if seq_registrado == ordem[-1] and registrado != anterior:
                raise ConfiguracaoInsegura("ultimo.json diverge de seq-N com o mesmo número")
            if seq_registrado == ordem[-1]:
                return relato
        substituir_atomico(self.ultimo_checkpoint, canonico(anterior))
        relato.append(f"ultimo.json atualizado para seq {ordem[-1]}")
        return relato

    # -- operações -------------------------------------------------------------
    def executar(self, uid, pedido):
        """`uid` vem do kernel (SO_PEERCRED); nada no pedido altera a identidade ou o papel."""
        if uid in self.ancoradores:
            # Papel restrito: SOMENTE checkpoint, sem nenhum outro campo. Os conjuntos de
            # ancoradores e proponentes são disjuntos (verificado na configuração).
            if pedido != {"op": "checkpoint"}:
                raise PermissionError("Ancorador só pode solicitar checkpoint")
            return self.emitir_checkpoint()
        proponente = self.proponentes.get(uid)
        if proponente is None:
            raise PermissionError(f"uid {uid} não autorizado")
        if not isinstance(pedido, dict) or not set(pedido) <= CAMPOS_PERMITIDOS:
            raise PermissionError("Campos não permitidos; a identidade é atribuída pelo guardião")
        op = pedido.get("op")
        if op == "propor":
            return {"sha256": self.repo.propor(pedido.get("premissa"), proponente)}
        if op == "registrar_aprovacao":
            return {"aprovador": self.repo.registrar_aprovacao(pedido.get("aprovacao"))}
        if op == "estado":
            return self.repo.estado(pedido.get("id"), pedido.get("versao"))
        if op == "ler_aprovada":
            return self.repo.ler_aprovada(pedido.get("id"))
        if op == "exportar_versao":
            cadeia = self.repo.historico(pedido.get("id"))
            n = pedido.get("versao")
            if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= len(cadeia):
                raise ValueError("Versão inexistente")
            return {"envelope": cadeia[n - 1][2], "sha256": cadeia[n - 1][1]}
        # "checkpoint" é exclusivo do papel ancorador (ramo acima): proponentes não ancoram.
        raise PermissionError(f"Operação não permitida: {op!r}")

    def emitir_checkpoint(self):
        pasta = self.ultimo_checkpoint.parent
        agora = time.monotonic()
        intervalo = self.limites.intervalo_minimo_checkpoint_s
        if self._ultimo_checkpoint_em is not None and agora - self._ultimo_checkpoint_em < intervalo:
            raise LimiteExcedido(f"Checkpoints com intervalo mínimo de {intervalo:g}s")
        if len(list(pasta.glob("seq-*.json"))) >= self.limites.max_checkpoints:
            raise LimiteExcedido(
                f"Limite de {self.limites.max_checkpoints} checkpoints locais; arquivar conforme o procedimento")
        usados = sum(a.stat().st_size for a in pasta.glob("seq-*.json"))
        if usados >= self.limites.max_bytes_checkpoints:
            raise LimiteExcedido(
                f"Checkpoints locais ocupam {usados} bytes (limite {self.limites.max_bytes_checkpoints}); "
                "arquivar conforme o procedimento")
        cadastro = self.cadastro_vigente() if self.politica_serie is not None else None
        anterior = None
        if self.ultimo_checkpoint.exists():
            anterior = json.loads(self.ultimo_checkpoint.read_bytes())
            ancora.verificar_checkpoint(self.repo, anterior, ancora.chave_hex(self.chave))
        novo = ancora.emitir_checkpoint(self.repo, self.chave, anterior, cadastro)
        pasta.mkdir(mode=0o700, exist_ok=True)
        gravar_exclusivo(pasta / f"seq-{novo['payload']['seq']}.json", canonico(novo))
        substituir_atomico(self.ultimo_checkpoint, canonico(novo))
        self._ultimo_checkpoint_em = agora
        return novo


def ler_linha(conexao, limite, prazo_s):
    """Lê uma linha com PRAZO TOTAL e limite de bytes; um cliente lento não prende o guardião."""
    fim = time.monotonic() + prazo_s
    dados = bytearray()
    while b"\n" not in dados:
        restante = fim - time.monotonic()
        if restante <= 0:
            raise TimeoutError(f"Prazo de leitura de {prazo_s:g}s excedido")
        conexao.settimeout(restante)
        try:
            bloco = conexao.recv(min(65536, limite + 1 - len(dados)))
        except socket.timeout as erro:
            raise TimeoutError(f"Prazo de leitura de {prazo_s:g}s excedido") from erro
        if not bloco:
            break
        dados += bloco
        if len(dados) > limite:
            raise LimiteExcedido(f"Requisição excede o limite de {limite} bytes")
    return bytes(dados)


def descartar_pendente(conexao, maximo):
    """Consome o que já chegou, para fechar sem RST e entregar a resposta de erro."""
    try:
        conexao.settimeout(0.05)
        conexao.recv(maximo)
    except OSError:
        pass


class Tratador(socketserver.BaseRequestHandler):
    def handle(self):
        guardiao, conexao = self.server.guardiao, self.request
        _, uid, _ = struct.unpack("3i", conexao.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                           struct.calcsize("3i")))
        recusa = None
        with guardiao.trava:
            try:
                guardiao.limitador.consumir(uid)               # antes de ler: barato para quem excede
            except LimiteExcedido as erro:
                recusa = erro
        if recusa is None and uid not in guardiao.proponentes and uid not in guardiao.ancoradores:
            recusa = PermissionError(f"uid {uid} não autorizado")   # sem papel: nem se lê a requisição
        if recusa is None and not guardiao.reservar_conexao(uid):
            recusa = ServidorOcupado("Conexões simultâneas além do limite")
        if recusa is not None:
            descartar_pendente(conexao, guardiao.limites.max_requisicao_bytes)
            self.responder({"ok": False, "erro": type(recusa).__name__, "mensagem": str(recusa)})
            return
        try:
            try:
                linha = ler_linha(conexao, guardiao.limites.max_requisicao_bytes,
                                  guardiao.limites.prazo_leitura_s)
            except LimiteExcedido:
                descartar_pendente(conexao, guardiao.limites.max_requisicao_bytes * 4)
                raise
            pedido = json.loads(linha)
            with guardiao.trava:
                resposta = {"ok": True, "resultado": guardiao.executar(uid, pedido)}
        except Exception as erro:  # falha fechada: nada é gravado, o erro é devolvido
            resposta = {"ok": False, "erro": type(erro).__name__, "mensagem": str(erro)}
        finally:
            guardiao.liberar_conexao(uid)
        self.responder(resposta)

    def responder(self, resposta):
        try:
            self.request.settimeout(5)
            self.request.sendall(canonico(resposta) + b"\n")
        except OSError:
            pass


class Servidor(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 64


def servir(caminho_config, estrito=False):
    guardiao = Guardiao(caminho_config, estrito)
    caminho_socket = Path(guardiao.config["socket"])
    caminho_socket.unlink(missing_ok=True)
    os.umask(0o077)
    servidor = Servidor(str(caminho_socket), Tratador)
    os.chmod(caminho_socket, 0o666)          # autorização por SO_PEERCRED, não por modo
    servidor.guardiao = guardiao
    if not guardiao.estrito:
        print(AVISO_LEGADO, file=sys.stderr, flush=True)
    for linha in guardiao.recuperado:
        print("RECUPERADO:", linha, file=sys.stderr, flush=True)
    print("PRONTO", flush=True)
    servidor.serve_forever()


if __name__ == "__main__":
    argumentos = [a for a in sys.argv[1:] if a != "--estrito"]
    if len(argumentos) != 1:
        print("uso: guardiao.py [--estrito] <configuração.json>", file=sys.stderr)
        sys.exit(2)
    try:
        servir(argumentos[0], estrito="--estrito" in sys.argv[1:])
    except (ConfiguracaoInsegura, ambiente.AmbienteInvalido, aprovacao.AutorizacaoIndisponivel,
            OSError, ValueError) as erro:
        print(f"RECUSADO: {erro}", file=sys.stderr, flush=True)
        sys.exit(3)
