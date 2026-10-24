"""Limites de recursos do núcleo de governança (GOV-04).

Três famílias, todas com valores finitos por padrão:
- tamanho e tempo de leitura de cada requisição;
- frequência de operações por identidade do SO (balde de fichas);
- crescimento do armazenamento (premissas, versões, bytes, checkpoints).

São limites de APLICAÇÃO: reduzem abuso acidental ou de agente sem privilégio, mas não
substituem a cota do sistema de arquivos, que é a única barreira real contra esgotamento
de disco (ver governanca/GOV-04-robustez-nucleo.md).
"""
import time
from collections import OrderedDict
from dataclasses import dataclass, fields


class LimiteExcedido(Exception):
    """Operação recusada por limite de tamanho, frequência ou crescimento."""


@dataclass(frozen=True)
class Limites:
    """Perfil padrão (legado/biblioteca): folgado, mas finito. O guardião de formato 2 usa o estrito."""
    max_requisicao_bytes: int = 1 << 20
    prazo_leitura_s: float = 10.0
    operacoes_por_minuto: float = 600.0
    rajada: int = 500
    max_identidades_rastreadas: int = 4096
    max_conexoes: int = 32
    max_conexoes_por_identidade: int = 8
    max_premissas: int = 100_000
    max_versoes_por_premissa: int = 10_000
    max_bytes_por_versao: int = 1 << 20
    max_bytes_total: int = 10 << 30
    max_checkpoints: int = 100_000
    max_bytes_checkpoints: int = 10 << 30
    intervalo_minimo_checkpoint_s: float = 0.0

    def __post_init__(self):
        for campo in fields(self):
            valor = getattr(self, campo.name)
            if isinstance(valor, bool) or not isinstance(valor, (int, float)):
                raise ValueError(f"Limite {campo.name} deve ser numérico")
            if valor < 0 or (valor == 0 and campo.name != "intervalo_minimo_checkpoint_s"):
                raise ValueError(f"Limite {campo.name} deve ser positivo")


PERFIL_ESTRITO = dict(
    max_requisicao_bytes=64 * 1024,
    prazo_leitura_s=5.0,
    operacoes_por_minuto=120.0,
    rajada=30,
    max_conexoes=16,
    max_conexoes_por_identidade=4,
    max_premissas=2_000,
    max_versoes_por_premissa=50,
    max_bytes_por_versao=16 * 1024,
    max_bytes_total=64 << 20,
    max_checkpoints=2_000,
    max_bytes_checkpoints=256 << 20,
    intervalo_minimo_checkpoint_s=10.0,
)


def limites_estritos(**sobrescritas):
    """Perfil estrito (padrão do formato 2) com sobrescritas explícitas da configuração."""
    return Limites(**{**PERFIL_ESTRITO, **sobrescritas})


class LimitadorTaxa:
    """Balde de fichas por chave (uid), com memória limitada (descarta a chave menos recente)."""

    def __init__(self, por_minuto, rajada, max_chaves=4096, relogio=time.monotonic):
        if por_minuto <= 0 or rajada <= 0 or max_chaves <= 0:
            raise ValueError("Parâmetros do limitador devem ser positivos")
        self._taxa = por_minuto / 60.0
        self._capacidade = float(rajada)
        self._max_chaves = int(max_chaves)
        self._relogio = relogio
        self._baldes = OrderedDict()

    def consumir(self, chave, custo=1.0):
        agora = self._relogio()
        fichas, anterior = self._baldes.get(chave, (self._capacidade, agora))
        fichas = min(self._capacidade, fichas + max(0.0, agora - anterior) * self._taxa)
        if fichas < custo:
            self._baldes[chave] = (fichas, agora)
            self._baldes.move_to_end(chave)
            espera = (custo - fichas) / self._taxa
            raise LimiteExcedido(f"Frequência excedida para {chave}; tente em {espera:.1f}s")
        self._baldes[chave] = (fichas - custo, agora)
        self._baldes.move_to_end(chave)
        while len(self._baldes) > self._max_chaves:
            self._baldes.popitem(last=False)

    def rastreadas(self):
        return len(self._baldes)
