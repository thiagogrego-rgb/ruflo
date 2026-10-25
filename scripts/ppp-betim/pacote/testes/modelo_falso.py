"""Modelo de linguagem FALSO e determinístico para testar o bloqueio técnico das ferramentas (GOV-08).

Fala o protocolo de streaming da API de mensagens e executa um roteiro: a cada rodada do laço de agente devolve a próxima
chamada de ferramenta do roteiro; quando o roteiro acaba, devolve uma resposta final. Como não há modelo real, não existe
"recusa voluntária": se a ferramenta for bloqueada, quem bloqueou foi o hook, o `deny`, o SO ou a jaula. O resultado
de cada ferramenta (o que o Claude Code devolveria ao modelo) é gravado em `resultados`.
"""
import http.server
import json
import threading


class ModeloFalso:
    def __init__(self, roteiro, atraso=0.0):
        self.atraso = atraso                      # segundos de espera antes de cada resposta (permite inspecionar o processo vivo)
        self.roteiro = list(roteiro)               # [(nome_da_ferramenta, entrada_dict), ...]
        self.resultados = []                       # [{"ferramenta":..., "erro":bool, "texto":...}]
        self.requisicoes = []                      # [{"caminho":..., "ferramentas":[...], "cabecalhos":{...}}]
        self.ferramentas_vistas = set()
        self.indisponivel = False                  # responde erro NÃO repetível (400) para provar que a falha chega à sessão sem travar
        self._uso = {}
        self._vistos = set()
        modelo = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_):
                pass

            def do_POST(self):
                tam = int(self.headers.get("Content-Length") or 0)
                corpo = self.rfile.read(tam) if tam else b""
                modelo._tratar(self, corpo)

            def do_GET(self):
                self.send_response(404)
                self.end_headers()

        self.servidor = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.porta = self.servidor.server_address[1]
        threading.Thread(target=self.servidor.serve_forever, daemon=True).start()

    def reiniciar(self, roteiro):
        """Novo roteiro e contadores zerados (o servidor e a porta continuam os mesmos)."""
        self.roteiro = list(roteiro)
        self.resultados.clear()
        self.requisicoes.clear()
        self.ferramentas_vistas.clear()
        self._uso.clear()
        self._vistos.clear()

    def fechar(self):
        self.servidor.shutdown()
        self.servidor.server_close()

    # ------------------------------------------------------------------------------------------------------------
    def _tratar(self, h, corpo):
        try:
            req = json.loads(corpo or b"{}")
        except ValueError:
            req = {}
        ferramentas = [t.get("name") for t in req.get("tools", []) if isinstance(t, dict)]
        self.requisicoes.append({"caminho": h.path, "ferramentas": ferramentas,
                                 "cabecalhos": {k.lower(): v for k, v in h.headers.items()}, "modelo": req.get("model")})
        if not h.path.split("?")[0].endswith("/v1/messages"):
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.end_headers()
            h.wfile.write(b"{}")
            return
        if self.indisponivel:
            erro = json.dumps({"type": "error", "error": {"type": "invalid_request_error", "message": "destino simulado indisponivel"}}).encode()
            h.send_response(400)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", str(len(erro)))
            h.end_headers()
            h.wfile.write(erro)
            return
        if self.atraso:
            import time
            time.sleep(self.atraso)
        if ferramentas:
            self.ferramentas_vistas.update(ferramentas)
            self._registrar_resultados(req)
            chave = json.dumps(req.get("messages", [])[:1], sort_keys=True)
            usados = self._uso.setdefault(chave, 0)
            if usados < len(self.roteiro):
                nome, entrada = self.roteiro[usados]
                self._uso[chave] = usados + 1
                blocos = [{"type": "tool_use", "id": f"toolu_falso_{usados}", "name": nome, "input": entrada}]
                parada = "tool_use"
            else:
                blocos = [{"type": "text", "text": "roteiro concluído"}]
                parada = "end_turn"
        else:
            blocos = [{"type": "text", "text": "ok"}]
            parada = "end_turn"
        if req.get("stream"):
            self._sse(h, blocos, parada, req.get("model", "falso"))
        else:
            corpo = json.dumps({"id": "msg_falso", "type": "message", "role": "assistant", "model": req.get("model", "falso"),
                                "content": blocos, "stop_reason": parada, "stop_sequence": None,
                                "usage": {"input_tokens": 1, "output_tokens": 1}}).encode()
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", str(len(corpo)))
            h.end_headers()
            h.wfile.write(corpo)

    def _registrar_resultados(self, req):
        """Guarda cada resultado de ferramenta (uma vez, pela ordem em que apareceram) em qualquer mensagem do histórico."""
        for msg in req.get("messages", []):
            if msg.get("role") != "user" or not isinstance(msg.get("content"), list):
                continue
            for bloco in msg["content"]:
                if isinstance(bloco, dict) and bloco.get("type") == "tool_result" and bloco.get("tool_use_id") not in self._vistos:
                    self._vistos.add(bloco.get("tool_use_id"))
                    conteudo = bloco.get("content")
                    if isinstance(conteudo, list):
                        conteudo = " ".join(x.get("text", "") for x in conteudo if isinstance(x, dict))
                    self.resultados.append({"id": bloco.get("tool_use_id"), "erro": bool(bloco.get("is_error")), "texto": str(conteudo)})

    @staticmethod
    def _sse(h, blocos, parada, modelo):
        def ev(nome, dados):
            h.wfile.write(f"event: {nome}\ndata: {json.dumps(dados)}\n\n".encode())
            h.wfile.flush()
        h.send_response(200)
        h.send_header("Content-Type", "text/event-stream")
        h.end_headers()
        ev("message_start", {"type": "message_start", "message": {"id": "msg_falso", "type": "message", "role": "assistant", "model": modelo,
                                                                    "content": [], "stop_reason": None, "stop_sequence": None,
                                                                    "usage": {"input_tokens": 1, "output_tokens": 1}}})
        for i, b in enumerate(blocos):
            if b["type"] == "text":
                ev("content_block_start", {"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}})
                ev("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}})
            else:
                ev("content_block_start", {"type": "content_block_start", "index": i,
                                           "content_block": {"type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}})
                ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                           "delta": {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}})
            ev("content_block_stop", {"type": "content_block_stop", "index": i})
        ev("message_delta", {"type": "message_delta", "delta": {"stop_reason": parada, "stop_sequence": None}, "usage": {"output_tokens": 1}})
        ev("message_stop", {"type": "message_stop"})
