import numpy as np
import pandas as pd
import shap
import streamlit as st
import streamlit.components.v1 as components
import requests


def st_shap(plot, height=None):
    shap_html = f"<head>{shap.getjs()}</head><body>{plot.html()}</body>"
    components.html(shap_html, height=height)


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
        d = pd.Series(eval(result['data']))
        st_shap(shap.force_plot(result['shap']['expected_value'],
                                np.array(list(result['shap']['shap_values'])),
                                d.drop(['qty_slash_domain',
                                        'qty_questionmark_domain',
                                        'qty_equal_domain',
                                        'qty_and_domain',
                                        'qty_exclamation_domain',
                                        'qty_space_domain',
                                        'qty_tilde_domain',
                                        'qty_comma_domain',
                                        'qty_plus_domain',
                                        'qty_asterisk_domain',
                                        'qty_hashtag_domain',
                                        'qty_dollar_domain',
                                        'qty_percent_domain',
                                        'full_url',
                                        'phish_probability']), link='logit'))

st.markdown("**Note: URLs saved to database for further analysis**")
