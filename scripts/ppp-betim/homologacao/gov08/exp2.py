import sys, os, json, subprocess, shutil
sys.path.insert(0, "/home/user/ruflo/scripts/ppp-betim/pacote/testes")
from modelo_falso import ModeloFalso
P="/tmp/claude-0/exp8/proj"
def run(label, deny, hooks, roteiro, agente="p6-participacao"):
    cfg=json.load(open("/tmp/claude-0/exp8/settings.orig.json"))
    if not hooks: cfg["hooks"]={}
    cfg["permissions"]["deny"] = cfg["permissions"]["deny"] + deny
    json.dump(cfg, open(P+"/.claude/settings.json","w"))
    m=ModeloFalso(roteiro)
    env={"PATH":os.environ["PATH"],"HOME":"/tmp/claude-0/exp8/home","ANTHROPIC_BASE_URL":f"http://127.0.0.1:{m.porta}","ANTHROPIC_API_KEY":"x"}
    r=subprocess.run(["claude","-p","--agent",agente,"--setting-sources","project","--output-format","json","t"],cwd=P,env=env,capture_output=True,text=True,timeout=180,stdin=subprocess.DEVNULL)
    print("==",label,"rc",r.returncode)
    for x in m.resultados: print("  ",("ERRO" if x["erro"] else "OK  "), x["texto"][:150].replace("\n"," "))
    m.fechar()
R=lambda f:("Read",{"file_path":P+"/"+f})
G=("Grep",{"pattern":"SEGREDO","path":P+"/dados/restritos"})
GL=("Glob",{"pattern":"*","path":P+"/dados/restritos"})
deny=[f"Read(/{P}/dados/restritos/**)"]
run("A-controle-sem-deny-sem-hook",[],False,[R("dados/restritos/r.txt"),G,GL])
run("B-deny-sem-hook",deny,False,[R("dados/restritos/r.txt"),G,GL])
run("C-deny-barra-relativa",[f"Read(./dados/restritos/**)"],False,[R("dados/restritos/r.txt"),G,GL])
