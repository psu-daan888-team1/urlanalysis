from prefect_flow import train
from prefect.deployments import Deployment


# hp = HyperParameters(learning_rate=0.1,
#                      max_depth=8,
#                      n_estimators=1000)

deployment = Deployment.build_from_flow(
    flow=train,
    name="XGB Phishing Detection Model Training",
    work_queue_name="work_queue",
    path="/prefect",
    parameters={'learning_rate': 0.1, 'max_depth': 8, 'n_estimators': 1000}
)

if __name__ == "__main__":
    deployment.apply()
