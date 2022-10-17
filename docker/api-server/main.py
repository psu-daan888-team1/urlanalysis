# conda install -c conda-forge fastapi uvicorn
# uvicorn main:app --reload
# https://fastapi.tiangolo.com/tutorial/body/

from fastapi import FastAPI
from pydantic import BaseModel
from url_converter import build_inference
import xgboost as xgb


class URL(BaseModel):
    url: str


def load_model():
    clf = xgb.XGBClassifier(tree_method='hist', enable_categorical=True, max_cat_to_onehot=3)
    clf.load_model('./models/xgb.json')
    return clf


app = FastAPI()

clf = load_model()


@app.post("/predict")
def predict(url: URL):
    u = url.dict()['url']
    d = build_inference(u)
    i = clf.predict_proba(d)
    return {'benign': i.tolist()[0][0], 'phishing': i.tolist()[0][1]}