"""Verificação de proteção de caminhos contra escrita de terceiros (GOV-03/GOV-04).

Extraído de `guardiao.py` para ser compartilhado com `ambiente.py`; `guardiao` continua
exportando os mesmos nomes.
"""
import stat
from pathlib import Path


class ConfiguracaoInsegura(RuntimeError):
    """O guardião recusa iniciar: a fronteira não estaria garantida."""


def exigir_protegido(caminho, uid_servico, recursivo=False):
    """Dono root ou o serviço e sem escrita por grupo/outros em todo o caminho.

    Diretórios com sticky bit e dono root (ex.: /tmp) são aceitos como ancestrais.
    Com `recursivo`, todo o conteúdo também é conferido e links simbólicos são recusados.
    """
    alvo = Path(caminho).resolve()
    for parte in [alvo, *alvo.parents]:
        st = parte.stat()
        gravavel = st.st_mode & 0o022
        sticky_root = stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX and st.st_uid == 0
        if st.st_uid not in (0, uid_servico) or (gravavel and not (parte != alvo and sticky_root)):
            raise ConfiguracaoInsegura(f"{parte} não está protegido contra escrita de terceiros")
    if recursivo and alvo.is_dir():
        for item in alvo.rglob("*"):
            st = item.lstat()
            if stat.S_ISLNK(st.st_mode) or st.st_uid not in (0, uid_servico) or st.st_mode & 0o022:
                raise ConfiguracaoInsegura(f"{item} não está protegido contra escrita de terceiros")
