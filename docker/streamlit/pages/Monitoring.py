import asyncio
import datetime
import os
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


# https://discuss.streamlit.io/t/issue-with-asyncio-run-in-streamlit/7745/7
async def monitor_flow():
    resp = requests.post('http://prefect:4200/api/deployments/filter', json={"name": {"like_": "XGB"}})
    dep_id = resp.json()[0]['id']
    t = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    resp = requests.post(f'http://prefect:4200/api/deployments/{dep_id}/create_flow_run',
                         json={'name': f'retrain_{t}', 'state': {'type': 'SCHEDULED'}})
    flow_id = resp.json()['id']
    w = await asyncio.sleep(1)
    while True:
        resp = requests.get(f'http://prefect:4200/api/flow_runs/{flow_id}')
        status = resp.json()['state_name']
        status_column.markdown(f"<h2 style='text-align: center'>{status}</h4>", unsafe_allow_html=True)
        if status in ['Scheduled', 'Running', 'Pending']:
            w = await asyncio.sleep(5)
        else:
            if status == 'Completed':
                logs = requests.post('http://prefect:4200/api/logs/filter',
                                     json={"logs": {"flow_run_id": {'any_': [flow_id]}}})
                results.text("\t" + logs.json()[18]['message'])

            break


q = run_query('select * from new_data')
c1, c2, c3 = st.columns([2, 3, 2])
c1.markdown("<h4 style='text-align: center'>AVG Phishing Probability</h4>", unsafe_allow_html=True)
c1.markdown("<h1 style='text-align: center; color: MediumSeaGreen'>" + str(round(q.phish_probability.mean(), 3)) + "</h1>", unsafe_allow_html=True)

c2.markdown("<h4 style='text-align: center'>Inference Distribution</h4>", unsafe_allow_html=True)
c2.bar_chart(q.phish_probability.map(lambda x: 1 if x > 0.5 else 0).value_counts().rename('Phishing'))

c3.markdown("<h4 style='text-align: center'>Inferences</h4>", unsafe_allow_html=True)
c3.markdown("<h1 style='text-align: center; color: MediumSeaGreen'>" + str(len(q)) + "</h1>", unsafe_allow_html=True)

c4, c5 = st.columns([1, 3])
c6, c7 = st.columns([1, 3])
if c4.button("Retrain Model", key='retrain'):
    status_column = c5.empty()
    results = c7.empty()
    asyncio.run(monitor_flow())


