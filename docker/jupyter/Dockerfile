FROM jupyter/datascience-notebook:lab-3.4.5
# https://jupyter-docker-stacks.readthedocs.io/en/latest/using/recipes.html#add-a-custom-conda-environment-and-jupyter-kernel
RUN conda install -q -y psycopg2 xgboost catboost shap && fix-permissions "${CONDA_DIR}" && fix-permissions "/home/${NB_USER}"
RUN pip install --quiet --no-cache-dir pandas-profiling && fix-permissions "${CONDA_DIR}" && fix-permissions "/home/${NB_USER}"