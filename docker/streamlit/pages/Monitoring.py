import pandas as pd
import psycopg2
import streamlit as st
import requests


st.set_page_config(page_title="Monitoring")
st.title('URLAnalysis: Phishing Detection Monitoring Interface')


@st.experimental_singleton
def init_connection():
    return psycopg2.connect(user='daan',
                            password=os.environ['PG_PW'],
                            host='pg',
                            port=5432,
                            dbname='phishing_data')


def run_query(query):
    with init_connection() as cx:
        return pd.read_sql_query(query, cx)


q = run_query('select * from new_data')
c1, c2, c3 = st.columns([2, 3, 2])
c1.markdown("<h4 style='text-align: center'>AVG Phishing Probability</h4>", unsafe_allow_html=True)
c1.markdown("<h1 style='text-align: center; color: MediumSeaGreen'>" + str(round(q.phish_probability.mean(), 3)) + "</h1>", unsafe_allow_html=True)

c2.markdown("<h4 style='text-align: center'>Inference Distribution</h4>", unsafe_allow_html=True)
c2.bar_chart(q.phish_probability.map(lambda x: 1 if x > 0.5 else 0).value_counts().rename('Phishing'))

c3.markdown("<h4 style='text-align: center'>Inferences</h4>", unsafe_allow_html=True)
c3.markdown("<h1 style='text-align: center; color: MediumSeaGreen'>" + str(len(q)) + "</h1>", unsafe_allow_html=True)
