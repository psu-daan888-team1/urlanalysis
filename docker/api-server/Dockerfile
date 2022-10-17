FROM python:3.10-slim
RUN apt-get update && apt-get install -y build-essential libpq-dev
RUN pip3 install psycopg2 xgboost fastapi scikit-learn uvicorn watchfiles tldextract dnspython python-whois cymruwhois beautifulsoup4 ipaddress numpy pandas
WORKDIR /opt/app
EXPOSE 8000
ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--reload", "--reload-include", "./models/*.json"]