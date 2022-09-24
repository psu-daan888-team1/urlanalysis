import streamlit as st
import requests


st.set_page_config(page_title="Inference")
st.title('URLAnalysis: Phishing Detection Inference')

with st.form('url_form'):
    url = st.text_input('URL', value='Enter URL')
    button = st.form_submit_button('Submit')
    if button:
        result = requests.post('http://localhost:8000/predict', json={'url': url})
        st.write(result.text)