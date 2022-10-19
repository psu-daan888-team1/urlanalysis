FROM prefecthq/prefect:sha-d9dd444-python3.10-conda
RUN apt-get update && apt-get install -y build-essential libpq-dev
RUN pip3 install scikit-learn pandas psycopg2 xgboost