import os
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
import pandas as pd
from prefect import flow, get_run_logger, task
import psycopg2
from pydantic import BaseModel
import xgboost as xgb


# class HyperParameters(BaseModel):
#     learning_rate: float
#     max_depth: int
#     n_estimators: int
#

@task(retries=3, retry_delay_seconds=10)
def get_original_data():
    with psycopg2.connect(user='daan', password=os.environ['PG_PW'], host='pg', port=5432,
                          dbname='phishing_data') as cx:
        data = pd.read_sql_query('select * from full_dataset', cx)

        logger = get_run_logger()
        logger.info("Gathered " + str(len(data)) + " original samples")

        return data


@task(retries=3, retry_delay_seconds=10)
def get_new_data():
    with psycopg2.connect(user='daan', password=os.environ['PG_PW'], host='pg', port=5432,
                          dbname='phishing_data') as cx:
        new_data = pd.read_sql_query('select * from new_data where phishing is not null', cx)

        logger = get_run_logger()
        logger.info("Gathered " + str(len(new_data)) + " new samples")

        return new_data


@task
def combine_data(original, new):
    logger = get_run_logger()
    if len(new) > 0:
        df = pd.concat([original, new], ignore_index=True)
        logger.info("Concatenated " + str(len(df)) + " original and new data points")
        return df
    else:
        logger.info("No new data points, returning only original data")
        return original


@task
def filter_unused_columns(data):
    logger = get_run_logger()
    logger.info("Dropping unused columns")
    data = data.drop(['qty_slash_domain',
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
                      'phish_probability',
                      'id'], axis=1, errors='ignore')
    logger.info("New shape of df: " + str(data.shape))
    return data


@task
def train_and_evaluate_model(data, learning_rate, max_depth, n_estimators):
    logger = get_run_logger()
    logger.info("Splitting data into train and test sets")
    phishing = data.pop('phishing')
    X_train, X_test, y_train, y_test = train_test_split(data, phishing, random_state=42)
    clf = xgb.XGBClassifier(tree_method='hist',
                            enable_categorical=True,
                            max_cat_to_onehot=3,
                            learning_rate=learning_rate,
                            max_depth=max_depth,
                            n_estimators=n_estimators)
    logger.info("Fitting XGBoost model")
    clf.fit(X_train, y_train)

    train_pred = clf.predict(X_train)
    test_pred = clf.predict(X_test)

    logger.info(classification_report(train_pred, y_train))
    logger.info(classification_report(test_pred, y_test))

    logger.info("Train F1 " + str(round(f1_score(train_pred, y_train), 3)))
    logger.info("Test F1 " + str(round(f1_score(test_pred, y_test), 3)))

    return clf


@task
def export_model(clf):
    clf.save_model('/models/xgb.json')
    logger = get_run_logger()
    logger.info("New model saved to disk")


@flow
def train(learning_rate, max_depth, n_estimators):
    orig_data = get_original_data()
    new_data = get_new_data()
    data = combine_data(orig_data, new_data)
    data = filter_unused_columns(data)
    clf = train_and_evaluate_model(data, learning_rate, max_depth, n_estimators)
    export_model(clf)


if __name__ == "main":
    train()
