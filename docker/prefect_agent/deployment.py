from prefect_flow import train
from prefect.deployments import Deployment


deployment = Deployment.build_from_flow(
    flow=train,
    name="XGB Phishing Detection Model Training",
    work_queue_name="work_queue",
    path="/prefect"
)

if __name__ == "__main__":
    deployment.apply()