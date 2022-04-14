from diagrams import Diagram, Cluster, Edge
from diagrams.onprem.client import Users
from diagrams.aws.compute import EC2
from diagrams.aws.storage import S3
from diagrams.onprem.database import Postgresql
from diagrams.onprem.network import Apache
from diagrams.onprem.inmemory import Redis 

with Diagram("Laika BOSS Processing", show=True, direction="LR") as diag:

    with Cluster('Mail Services 1..k'):
        laikamail = EC2("Laikamail")
        laikacollector_mail = EC2("Laikacollector")
        laikamail >> Edge(label='shared volume') >> laikacollector_mail

    with Cluster('Session'):
        redis = Redis("Redis - session db")

    with Cluster('Storage'):
        webserver =  Apache("Frontend")
        minio = S3("S3 Storage (MinIO)")
        laikacollector_storage = EC2("Laikacollector")
        laikarestd = EC2("Laikarestd - Submit Samples/View Storage")
        laikarestd >> Edge(label='S3 Protocol') >> minio
        webserver >> Edge(label='S3 Protocol') >> minio
        webserver >> laikarestd
        laikarestd >> Edge(label='Submit scan') >> laikacollector_storage

    with Cluster('Workers 1..n'):
        submitstoraged = EC2("SubmitstorageD")
        laikadq = EC2("Laikadq - worker")

    client_mail = [Users("Client E-Mail")]
    client_browser = [Users("Client Browser")]

    automated_processes = [EC2("Automated Processes")]
    client_mail >> Edge(label='SMTP or SMTPS') >> laikamail
    client_browser >> Edge(label='Submit samples/Pull results') >> webserver

    laikacollector_mail >> redis  
    laikacollector_storage >> Edge(label='Push work') >> redis

    automated_processes >> Edge(label='Submit samples/Pull results') >> webserver

    submitstoraged >> Edge(label='Store files to S3') >> webserver

    laikadq >> Edge(label="Store files to S3") >> webserver
    laikadq >> Edge(label='Submit samples/Pull results') >> redis
