"""Baixa a divisão oficial de treino e teste do UNSW-NB15 pelo KaggleHub."""

from pathlib import Path
from shutil import copy2

import kagglehub


DATASET_ID = "dhoogla/unswnb15"
OUTPUT_DIR = Path("dados_unsw_nb15")
EXPECTED_FILES = (
    "UNSW_NB15_training-set.parquet",
    "UNSW_NB15_testing-set.parquet",
)


def encontrar_arquivo(base_dir: Path, nome: str) -> Path:
    encontrados = list(base_dir.rglob(nome))
    if not encontrados:
        raise FileNotFoundError(
            f"O arquivo {nome!r} não foi encontrado em {base_dir}. "
            "Confira se a versão do dataset no Kaggle foi alterada."
        )
    if len(encontrados) > 1:
        raise RuntimeError(f"Mais de um arquivo {nome!r} foi encontrado: {encontrados}")
    return encontrados[0]


def main() -> None:
    cache_dir = Path(kagglehub.dataset_download(DATASET_ID))
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Dataset armazenado pelo KaggleHub em: {cache_dir}")
    for nome in EXPECTED_FILES:
        origem = encontrar_arquivo(cache_dir, nome)
        destino = OUTPUT_DIR / nome

        if origem.resolve() != destino.resolve():
            copy2(origem, destino)

        tamanho_mb = destino.stat().st_size / (1024 * 1024)
        print(f"Arquivo pronto: {destino} ({tamanho_mb:.2f} MB)")


if __name__ == "__main__":
    main()
