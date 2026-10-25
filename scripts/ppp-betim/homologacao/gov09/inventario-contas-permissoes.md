# Inventário de contas e permissões (lido do SISTEMA: getent/id/stat), 2026-10-25T02:48:05Z

## Contas
- uid=61000(ppp-admin) gid=61000(ppp-admin) groups=61000(ppp-admin) shell=/usr/sbin/nologin
- uid=61010(ppp-guardiao) gid=61010(ppp-guardiao) groups=61010(ppp-guardiao),61100(ppp-leitura) shell=/usr/sbin/nologin
- uid=61030(ppp-rede) gid=61030(ppp-rede) groups=61030(ppp-rede),61100(ppp-leitura) shell=/usr/sbin/nologin
- uid=61001(ppp-coord) gid=61001(ppp-coord) groups=61001(ppp-coord),61100(ppp-leitura),61102(ppp-logs),61105(ppp-dr-leitura) shell=/usr/sbin/nologin
- uid=61002(ppp-dr) gid=61002(ppp-dr) groups=61002(ppp-dr),61100(ppp-leitura),61101(ppp-restrito),61105(ppp-dr-leitura) shell=/usr/sbin/nologin
- uid=61003(ppp-rev) gid=61003(ppp-rev) groups=61003(ppp-rev),61100(ppp-leitura),61101(ppp-restrito),61102(ppp-logs),61105(ppp-dr-leitura) shell=/usr/sbin/nologin
- uid=61021(ppp-p1) gid=61021(ppp-p1) groups=61021(ppp-p1),61100(ppp-leitura) shell=/usr/sbin/nologin
- uid=61022(ppp-p2) gid=61022(ppp-p2) groups=61022(ppp-p2),61100(ppp-leitura) shell=/usr/sbin/nologin
- uid=61023(ppp-p3) gid=61023(ppp-p3) groups=61023(ppp-p3),61100(ppp-leitura) shell=/usr/sbin/nologin
- uid=61024(ppp-p4) gid=61024(ppp-p4) groups=61024(ppp-p4),61100(ppp-leitura) shell=/usr/sbin/nologin
- uid=61025(ppp-p5) gid=61025(ppp-p5) groups=61025(ppp-p5),61100(ppp-leitura) shell=/usr/sbin/nologin
- uid=61026(ppp-p6) gid=61026(ppp-p6) groups=61026(ppp-p6),61100(ppp-leitura) shell=/usr/sbin/nologin
- uid=61027(ppp-p7) gid=61027(ppp-p7) groups=61027(ppp-p7),61100(ppp-leitura) shell=/usr/sbin/nologin

## Grupos
- ppp-leitura:x:61100:ppp-guardiao,ppp-rede,ppp-coord,ppp-dr,ppp-rev,ppp-p1,ppp-p2,ppp-p3,ppp-p4,ppp-p5,ppp-p6,ppp-p7
- ppp-restrito:x:61101:ppp-dr,ppp-rev
- ppp-logs:x:61102:ppp-coord,ppp-rev
- ppp-dr-leitura:x:61105:ppp-coord,ppp-dr,ppp-rev

## Dono/grupo/modo (stat)
```
ppp-admin:ppp-leitura 750 .
ppp-admin:ppp-leitura 750 dados
ppp-admin:ppp-restrito 750 dados/restritos
ppp-admin:ppp-restrito 750 dados/entrada
ppp-guardiao:ppp-logs 750 logs
ppp-guardiao:ppp-logs 640 logs/guarda-controlador-dr.jsonl
ppp-guardiao:ppp-logs 640 logs/guarda-coordenador.jsonl
ppp-guardiao:ppp-logs 640 logs/guarda-p1.jsonl
ppp-guardiao:ppp-logs 640 logs/guarda-p2.jsonl
ppp-guardiao:ppp-logs 640 logs/guarda-p3.jsonl
ppp-guardiao:ppp-logs 640 logs/guarda-p4.jsonl
ppp-guardiao:ppp-logs 640 logs/guarda-p5.jsonl
ppp-guardiao:ppp-logs 640 logs/guarda-p6.jsonl
ppp-guardiao:ppp-logs 640 logs/guarda-p7.jsonl
ppp-guardiao:ppp-logs 640 logs/guarda-revisor.jsonl
ppp-guardiao:ppp-logs 640 logs/rede.jsonl
ppp-admin:ppp-leitura 750 produtos
ppp-coord:ppp-leitura 2750 produtos/C
ppp-admin:ppp-dr-leitura 750 produtos/DR
ppp-p1:ppp-leitura 2750 produtos/P1
ppp-p2:ppp-leitura 2750 produtos/P2
ppp-p3:ppp-leitura 2750 produtos/P3
ppp-p4:ppp-leitura 2750 produtos/P4
ppp-p5:ppp-leitura 2750 produtos/P5
ppp-p6:ppp-leitura 2750 produtos/P6
ppp-p7:ppp-leitura 2750 produtos/P7
ppp-dr:ppp-dr-leitura 2750 produtos/DR/saida
ppp-admin:ppp-leitura 750 governanca
ppp-admin:ppp-leitura 750 scripts
ppp-admin:ppp-leitura 750 .claude
ppp-admin:ppp-leitura 750 .claude/hooks
ppp-admin:ppp-leitura 640 .claude/settings.json
root:root 755 /opt/ppp-betim
root:root 755 /opt/ppp-betim/codigo
root:root 755 /opt/ppp-betim/codigo/scripts
root:root 755 /etc/ppp-betim
root:root 644 /etc/ppp-betim/servicos.json
root:root 755 /var/lib/ppp-betim
root:root 700 /var/lib/ppp-betim/evidencias
root:root 755 /var/lib/ppp-betim/ancoras
root:root 755 /run/ppp-betim
ppp-guardiao:ppp-guardiao 755 /run/ppp-betim/log
ppp-rede:ppp-rede 755 /run/ppp-betim/gw
```

## Atributo só-anexar (lsattr)
```
-----a--------e------- logs/guarda-controlador-dr.jsonl
-----a--------e------- logs/guarda-coordenador.jsonl
-----a--------e------- logs/guarda-p1.jsonl
-----a--------e------- logs/guarda-p2.jsonl
-----a--------e------- logs/guarda-p3.jsonl
-----a--------e------- logs/guarda-p4.jsonl
-----a--------e------- logs/guarda-p5.jsonl
-----a--------e------- logs/guarda-p6.jsonl
-----a--------e------- logs/guarda-p7.jsonl
-----a--------e------- logs/guarda-revisor.jsonl
-----a--------e------- logs/rede.jsonl
```
