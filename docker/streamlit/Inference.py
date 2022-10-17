import streamlit as st
import requests


st.set_page_config(page_title="Inference")
st.title('URLAnalysis: Phishing Detection Inference')

with st.form('url_form'):
    url = st.text_input('URL', value='Enter URL')
    button = st.form_submit_button('Submit')
    if button:
        with st.spinner("Checking URL"):
            result = requests.post('http://api:8000/predict', json={'url': url})
        st.success('Success!')
        result = result.json()
        if round(result['benign']) < .5:
            st.warning('URL may be phishing')
        else:
            st.success('URL appears safe')
        st.write("Benign Probability: " + str(round(result['benign'], 3)))
        st.write("Phishing Probability: " + str(round(result['phishing'], 3)))
