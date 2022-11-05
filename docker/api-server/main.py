# conda install -c conda-forge fastapi uvicorn
# uvicorn main:app --reload
# https://fastapi.tiangolo.com/tutorial/body/
import pandas as pd
from fastapi import BackgroundTasks, FastAPI
import os
from pydantic import BaseModel
import shap
from sqlalchemy import create_engine
from url_converter import build_inference
import xgboost as xgb


class URL(BaseModel):
    url: str


def load_model():
    clf = xgb.XGBClassifier(tree_method='hist', enable_categorical=True, max_cat_to_onehot=3)
    clf.load_model('./models/xgb.json')
    return clf


def insert_into_db(df):
    with engine.connect() as cx:
        df.to_sql('new_data', cx, if_exists='append', index=False)


app = FastAPI()

clf = load_model()
exp = shap.TreeExplainer(clf)

engine = create_engine("postgresql://daan:" + os.environ['PG_PW'] +"@pg:5432/phishing_data")


@app.post("/predict")
async def predict(url: URL, background_tasks: BackgroundTasks):
    u = url.dict()['url']
    d = build_inference(u)
    i = clf.predict_proba(d.drop(['qty_slash_domain',
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
                                  'qty_percent_domain'], axis=1))

    shap_values = exp.shap_values([d.drop(['qty_slash_domain',
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
                                           'qty_percent_domain'], axis=1).squeeze()])

    d['full_url'] = u
    d['phish_probability'] = round(i.tolist()[0][1], 3)
    background_tasks.add_task(insert_into_db, d)

    return {'benign': i.tolist()[0][0], 'phishing': i.tolist()[0][1],
            'shap': {'expected_value': float(exp.expected_value), 'shap_values': shap_values[0].tolist()},
            'data': d.squeeze().to_json()}

