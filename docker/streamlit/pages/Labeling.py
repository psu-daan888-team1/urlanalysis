import os
import psycopg2
import streamlit as st


st.set_page_config(page_title="Labeling")
st.title('URLAnalysis: Phishing Detection Labeling Interface')
# https://docs.streamlit.io/knowledge-base/tutorials/databases/postgresql
@st.experimental_singleton
def init_connection():
    return psycopg2.connect(user='daan',
                            password=os.environ['PG_PW'],
                            host='pg',
                            port=5432,
                            dbname='phishing_data')

conn = init_connection()

# @st.experimental_memo(ttl=600)
def run_query(query):
    with conn.cursor() as cur:
        cur.execute(query)
        return cur.fetchall()


def update_label(**kwargs):
    kwargs.get('phishing')
    with conn.cursor() as cur:
        if kwargs.get('phishing') == 1:
            cur.execute("update new_data set phishing = 1 where id=" + str(kwargs.get('id')))
            st.success('Updated the phishing database')
        elif kwargs.get('phishing') == 0:
            cur.execute("update new_data set phishing = 0 where id=" + str(kwargs.get('id')))
            st.success('Updated the phishing database')
    conn.commit()


rows = run_query("select id, full_url, phish_probability from new_data where phishing is null order by id")

h1, h2, h3, h4 = st.columns([3, 1, 1.25, 1.25])
h1.write('**URL**')
h2.write('**Phishing Probability**')
h3.write('**Report Phishing**')
h4.write('**Report Not Phishing**')

for row in rows:
    c1, c2, c3, c4 = st.columns([3, 1, 1.25, 1.25])
    c1.write(str(row[1]))
    c2.write(str(row[2]))
    # https://stackoverflow.com/questions/69492406/streamlit-how-to-display-buttons-in-a-single-line
    c3p = c3.empty()
    c4p = c4.empty()
    c3p.button("Phishing", key='phish' + str(row[0]), on_click=update_label, kwargs={'id': row[0], 'phishing': 1})
    c4p.button("Not Phishing", key='nophish' + str(row[0]), on_click=update_label, kwargs={'id': row[0], 'phishing': 0})

if len(rows) == 0:
    st.markdown("<h5 style='text-align: center'>No more data to label</h5>", unsafe_allow_html=True)