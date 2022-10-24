FROM jupyter/datascience-notebook:lab-3.4.5
# https://jupyter-docker-stacks.readthedocs.io/en/latest/using/recipes.html#add-a-custom-conda-environment-and-jupyter-kernel
RUN conda install -q -y graphviz pydot psycopg2 xgboost catboost tensorflow shap && fix-permissions "${CONDA_DIR}" && fix-permissions "/home/${NB_USER}"
RUN pip install --quiet --no-cache-dir sklearn-evaluation prefect pandas-profiling scikeras[tensorflow] && fix-permissions "${CONDA_DIR}" && fix-permissions "/home/${NB_USER}"