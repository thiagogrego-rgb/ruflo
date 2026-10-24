#!/usr/bin/env python3
"""Servidor MCP SINTÉTICO (stdio) para teste de GOV-06: 'publicar_documento' só grava um arquivo local; 'listar_documentos' só lê."""
import json, os, sys
SAIDA = os.environ.get("MCP_SINTETICO_SAIDA", "/tmp/mcp-sintetico-publicado.txt")
FERR = [
    {"name": "listar_documentos", "description": "Lista documentos sintéticos (somente leitura).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "publicar_documento", "description": "Publica um documento sintético (efeito: grava arquivo local).",
     "inputSchema": {"type": "object", "properties": {"texto": {"type": "string"}}, "required": ["texto"]}},
]
def resp(i, resultado=None, erro=None):
    m = {"jsonrpc": "2.0", "id": i}
    m["error" if erro else "result"] = erro or resultado
    sys.stdout.write(json.dumps(m) + "\n"); sys.stdout.flush()
for linha in sys.stdin:
    try: m = json.loads(linha)
    except ValueError: continue
    met, i = m.get("method"), m.get("id")
    if met == "initialize":
        resp(i, {"protocolVersion": m["params"].get("protocolVersion", "2024-11-05"), "capabilities": {"tools": {}},
                 "serverInfo": {"name": "sintetico", "version": "1"}})
    elif met == "tools/list":
        resp(i, {"tools": FERR})
    elif met == "tools/call":
        nome = m["params"]["name"]
        if nome == "publicar_documento":
            open(SAIDA, "a").write(m["params"]["arguments"].get("texto", "") + "\n")
            resp(i, {"content": [{"type": "text", "text": "PUBLICADO-SINTETICO"}]})
        else:
            resp(i, {"content": [{"type": "text", "text": "DOCS-SINTETICOS: d1, d2"}]})
    elif i is not None:
        resp(i, {})
