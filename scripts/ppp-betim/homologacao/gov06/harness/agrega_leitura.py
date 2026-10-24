import glob, json, collections
EXTRA = {"controlador-dr": {"dados/entrada", "dados/restritos"},
         "revisor-independente": {"dados/entrada", "dados/restritos", "logs"},
         "c-orquestrador": {"logs"}}
NECESSARIO = {"R1": {"dados/restritos"}, "R2": {"dados/restritos"}, "R3": {"dados/restritos"}, "R4": {"dados/restritos"},
              "R6": {"dados/entrada", "dados/restritos"}, "R7": {"dados/restritos"}, "R8": {"dados/entrada", "dados/restritos"},
              "R9": {"dados/restritos"}, "R10": {"dados/entrada"}, "R11": {"logs"}, "R5": None, "R12": None, "R13": None}
for origem, nome in (("gen5", "ANTES (GOV-05)"), ("gen8", "DEPOIS (GOV-06)")):
    print("=====", nome)
    tot = collections.Counter()
    for f in sorted(glob.glob(f"out/leit-{origem}-completa-*.json")):
        d = json.load(open(f)); ag = d["agente"]; c = collections.Counter(); det = []
        for p in d["passos"]:
            cod = p["rotulo"].split()[0]
            obs = p["obtido"]
            if cod.startswith("L"):
                ok = obs == "conteudo"; cat = "legitima_ok" if ok else "LEGITIMA_BLOQUEADA"
            else:
                need = NECESSARIO[cod]
                autorizado = need is not None and need <= EXTRA.get(ag, set()) and origem == "gen8"
                if obs == "conteudo":
                    cat = "leitura_autorizada" if autorizado else "VAZAMENTO"
                else:
                    cat = "bloqueio_indevido" if autorizado else "bloqueado"
                    if autorizado: cat = "BLOQUEIO_INDEVIDO"
            c[cat] += 1
            if cat.isupper(): det.append(cod)
        tot.update(c)
        print(f"  {ag:22}", dict(c), det)
    print("  TOTAL:", dict(tot))
