# Detecção de intrusões em redes IoT com UNSW-NB15

Este projeto usa o dataset [UNSW-NB15 no Kaggle](https://www.kaggle.com/datasets/dhoogla/unswnb15) para treinar e avaliar um classificador binário de tráfego de rede:

- `0`: tráfego normal;
- `1`: ataque.

O dataset CIMD usado anteriormente foi removido do fluxo. O UNSW-NB15 fornece uma divisão oficial com 175.341 registros de treino e 82.332 registros de teste. A atribuição de cada registro à divisão oficial é preservada. Antes do treinamento, cópias exatas são removidas dentro de cada divisão e registros idênticos já vistos no treino são retirados do teste.

## Preparação do ambiente

Requer Python 3.10 ou mais recente.

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

## Execução

1. Baixe os arquivos do Kaggle:

   ```bash
   python 04_download_unsw_nb15.py
   ```

2. Execute `05_pre_processamento_unsw_nb15.ipynb` para inspecionar o esquema, as classes, os valores ausentes e as categorias.
3. Execute `06_lightgbm.ipynb` para treinar o LightGBM e gerar acurácia, acurácia balanceada, precisão, recall, F1, ROC AUC, matriz de confusão e importância dos atributos.

Os arquivos Parquet são copiados para `dados_unsw_nb15/`, que não é versionado por causa do tamanho. O notebook de treinamento lê diretamente `UNSW_NB15_training-set.parquet` e `UNSW_NB15_testing-set.parquet`.

## Decisões para evitar vazamento de dados

- A divisão oficial de treino e teste não é refeita.
- Duplicatas exatas são removidas e uma linha do teste nunca é mantida quando uma cópia idêntica já existe no treino. Isso evita métricas artificialmente otimistas.
- O atributo `attack_cat` não é usado como entrada: ele descreve a categoria do ataque e entregaria parte da resposta ao modelo binário.
- Imputação e codificação de categorias são ajustadas somente com o conjunto de treino por meio de um `Pipeline` do scikit-learn.
- Categorias que apareçam apenas no teste são ignoradas com segurança pelo `OneHotEncoder`.

## Fonte acadêmica

Moustafa, N.; Slay, J. *UNSW-NB15: A comprehensive data set for network intrusion detection systems*. MilCIS, 2015.
