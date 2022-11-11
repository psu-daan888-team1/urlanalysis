# URLAnalysis - A Machine Learning-Based Phishing Detection System 

## Building
* Ensure [Docker Desktop](https://www.docker.com/products/docker-desktop/) and [git](https://github.com/git-guides/install-git) are installed 
* Open terminal (mac) or powershell (windows), and change to directory where project should be downloaded
* Clone this repository: `git clone https://github.com/psu-daan888-team1/urlanalysis.git`
* Change directory to base of repo: `cd urlanalysis`
* Create file called `.env` with the following text: `pg_pw = pass` where pass is the password you would like to use
* Run `docker compose up`
* The containers will begin building - it will take a while in the first instantiation.  It will be ready when you can access the services below

## Accessing
* JupyterLab
  * Access web interface [here](http://localhost:8888)
  * Password: in .env file
* Postgres
  * DB Name: phishing_data
  * User: daan
  * Password: in .env file
  * Host/Port: localhost:5432
* Streamlit
  * Access Streamlit UI [here](http://localhost:8501)
* Prefect
  * Access Prefect UI [here](http://localhost:4200)

## Citations
(andfanilo), F. A. (2020, September). Display SHAP diagrams with Streamlit. Retrieved from Using Streamlit - Streamlit: https://discuss.streamlit.io/t/display-shap-diagrams-with-streamlit/1029/9

(andfanilo), F. A. (2020, December). Issue with asyncio run in streamlit. Retrieved from Streamlit: https://discuss.streamlit.io/t/issue-with-asyncio-run-in-streamlit/7745/7

Adler, D. (2018, October 2). python - Extract email sub-strings from large document. Retrieved from Stack Overflow: https://stackoverflow.com/questions/17681670/extract-email-sub-strings-from-large-document

Arora, N. (2021, September 9). SSL Certificate Verification - Python requests. Retrieved from GeeksForGeeks: https://www.geeksforgeeks.org/ssl-certificate-verification-python-requests/

Azoff, J., & Castell, V. H. (2016, November 7). JustinAzoff/python-cymruwhois: Python client for the whois.cymru.com service. Retrieved from github.com: https://github.com/JustinAzoff/python-cymruwhois

Badaracco, A. G., & scikeras developers. (2020). Migrating from tf.keras.wrappers.scikit_learn. Retrieved from SciKeras 0.9.0 documentation: https://www.adriangb.com/scikeras/stable/migration.html#migration

Badaracco, A. G., & SciKeras developers. (2020). Quickstart. Retrieved from SciKeras 0.9.0 documentation: https://www.adriangb.com/scikeras/stable/quickstart.html#in-an-sklearn-pipeline

Brinkmann, J. (2018). Read SQL query from psycopg into pandas dataframe. Retrieved from github.com: https://gist.github.com/jakebrinkmann/de7fd185efe9a1f459946cf72def057e

Catboost developers. (n.d.). grid_search - CatBoostClassifier. Retrieved from CatBoost: https://catboost.ai/en/docs/concepts/python-reference_catboostclassifier_grid_search

Di Gregorio, F., Varrazzo, D., & The Psycopg Team. (2021). Psycopg - PostgreSQL database adapter for python. Retrieved from Psycopg 2.9.5 documentation: https://www.psycopg.org/docs/

Dnspython contributors. (n.d.). dnspython home page. Retrieved from dnspython: https://www.dnspython.org/examples.html

FastAPI Team. (2022). Request Body. Retrieved from FastAPI: https://fastapi.tiangolo.com/tutorial/body/

GFI Software. (2020). How to check and read a Sender Policy Framework record for a domain. Retrieved from GFI Mailessentials Support: https://support.mailessentials.gfi.com/hc/en-us/articles/360015116520-How-to-check-and-read-a-Sender-Policy-Framework-record-for-a-domain

Halford, M. (2017, May 18). Keras fit/predict scikit-learn pipeline. Retrieved from github.com: https://gist.github.com/MaxHalford/9bfaa8daf8b4bc17a7fb7ba58c880675

Ibanez, P. (2022, August 26). prefect-orion/docker-compose.yaml at main fraibacas/prefect-orion. Retrieved from github.com: https://github.com/fraibacas/prefect-orion/blob/main/docker-compose.yaml

Kukade, R. (2022). phishing-domain-detection. Retrieved from Kaggle: https://www.kaggle.com/datasets/ravirajkukade/phishingdomaindetection?select=dataset_full.csv

Kukade, R. (2022). phishing-domain-detection. Retrieved from Kaggle: https://www.kaggle.com/datasets/ravirajkukade/phishingdomaindetection?select=Info+About+data.txt

Kurbatov, C. (2021, December 12). python - Streamlit how to display buttons in a single line. Retrieved from stackoverflow: https://stackoverflow.com/questions/69492406/streamlit-how-to-display-buttons-in-a-single-line

Kurkowski, J. (2022, Oct 4). tldextract. Retrieved from PyPi: https://pypi.org/project/tldextract/

lrosique. (2021, July 28). tf.summary.create_file_writer error in callback : not deep copyable. Retrieved from github: https://github.com/keras-team/keras-tuner/issues/574

Lundberg, S. (n.d.). Basic SHAP Interaction Value Example in XGBoost. Retrieved from SHAP latest documentation: https://shap.readthedocs.io/en/latest/example_notebooks/tabular_examples/tree_based_models/Basic%20SHAP%20Interaction%20Value%20Example%20in%20XGBoost.html

ObjectRocket, Data Pilot. (2019, September 11). Connect to a PostgreSQL Database Using Python and the psycopg2 Adapter. Retrieved from Database Management and Hosting | ObjectRocket: https://kb.objectrocket.com/postgresql/connect-to-a-postgresql-database-using-python-and-the-psycopg2-adapter-758

Plotly. (2022). Bullet charts in Python. Retrieved from Plotly open source graphing libraries: https://plotly.com/python/bullet-charts/

Prefect Team. (n.d.). Deployments. Retrieved from Prefect 2 - Coordinating the world's dataflows: https://docs.prefect.io/tutorials/deployments/

Prefect Team. (n.d.). First Steps. Retrieved from Prefect 2 - Coordinating the world's dataflows: https://docs.prefect.io/tutorials/first-steps/

Prefect Team. (n.d.). Quick Start. Retrieved from Prefect 2 - Coordinating the world's dataflows: https://docs.prefect.io/getting-started/overview/

Project Jupyter. (2022). Contributed Recipes. Retrieved from Docker Stacks documentation: https://jupyter-docker-stacks.readthedocs.io/en/latest/using/recipes.html#add-a-custom-conda-environment-and-jupyter-kernel

Python Software Foundation. (2022). ipaddress - IPv4/IPv6 manipulation library. Retrieved from Python 3.10.8 Documentation: https://docs.python.org/3/library/ipaddress.html

Python SOftware Foundation. (2022). urllib.parse - Parse URLs into components. Retrieved from Python 3.10.8 documentation: https://docs.python.org/3/library/urllib.parse.html

Reyes, E. B. (2016). Classifier evaluation. Retrieved from sklearn-evaluation 0.7.9dev documentation: https://sklearn-evaluation.readthedocs.io/en/latest/user_guide/classifier.html

scikit-learn developers. (2022). Demonstration of multi-metric evaluation on cross_val_score and GridSearchCV. Retrieved from scikit-learn 1.1.3 documentation: https://scikit-learn.org/stable/auto_examples/model_selection/plot_multi_metric_evaluation.html

scikit-learn developers. (2022). Putting it all together. Retrieved from scikit-learn 1.1.3 documentation: https://scikit-learn.org/stable/tutorial/statistical_inference/putting_together.html

Shapiro, P. (2016, October 5). How to check which URLs have been indexed by Google using Python. Retrieved from searchengineland.com: https://searchengineland.com/check-urls-indexed-google-using-python-259773

Streamlit Inc. (2022). Connect Streamlit to PostgreSQL. Retrieved from Streamlit Docs: https://docs.streamlit.io/knowledge-base/tutorials/databases/postgresql

Streamlit Inc. (2022). st.plotly_chart. Retrieved from Streamlit Docs: https://docs.streamlit.io/library/api-reference/charts/st.plotly_chart

Tensorflow Developers. (2022, January 6). Using TensorBoard in Notebooks. Retrieved from Tensorboard | Tensorflow: https://www.tensorflow.org/tensorboard/tensorboard_in_notebooks

xgboost developers. (2022). Python Package Introduction. Retrieved from xgboost 1.7.1 documentation: https://xgboost.readthedocs.io/en/stable/python/python_intro.html

YData Labs Inc. (2022). Available settings. Retrieved from pandas-profiling 3.4.0 documentation: https://pandas-profiling.ydata.ai/docs/master/pages/advanced_usage/available_settings.html

YData, pandas-profiling developers. (2022). ydataai/pandas-profiling: Create HTML profiling reports from pandas DataFrame objects. Retrieved from github.com: https://github.com/ydataai/pandas-profiling
