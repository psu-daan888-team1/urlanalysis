FROM python:3.10-slim
RUN apt-get update && apt-get install -y build-essential libpq-dev
RUN pip3 install streamlit psycopg2
WORKDIR /opt/app
EXPOSE 8501
ENTRYPOINT ["streamlit", "run", "Inference.py", "--server.port=8501", "--server.address=0.0.0.0"]