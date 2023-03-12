import requests
import json
import msal
import csv
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError
import azure.functions as func
import logging
import tempfile

def main(mytimer: func.TimerRequest) -> None:
    # Set your Azure AD tenant ID, client ID, and client secret
    tenant_id = 'cc1b978b-e786-4a39-a359-REDACTED'
    client_id = 'f63dbd4c-48ab-4818-9c74-REDACTED'
    client_secret = '7WN8Q~L9VHKfq7O6NMKwfUdNXcfWxdu-REDACTED'

    # Initialize the MSAL app object
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority
    )

    # Acquire a token for the Graph API
    scope = ['https://graph.microsoft.com/.default']
    token = app.acquire_token_silent(scope, account=None)

    if not token:
        result = app.acquire_token_for_client(scopes=scope)
        token = result['access_token']

    ####################################
    # 
    #  Set the API endpoint, headers, and request body with KQL query
    #  todo: MDO can't select as data source
    # ####################################
    url = 'https://graph.microsoft.com/v1.0/security/runHuntingQuery'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    request_body = {
        "Query": "AlertInfo | where DetectionSource contains 'Microsoft Defender for Office 365' | summarize  TotalCount = count(),  HighSeverityCount = countif(Severity == 'High'),   MediumSeverityCount = countif(Severity == 'Medium'),LowSeverityCount = countif(Severity == 'Low')" 
                    }

    # Make the API call with the request body
    logging.info("Getting Total Count of Alerts and Severity Counts using KQL...")
    response = requests.post(url, headers=headers, data=json.dumps(request_body))
    jsonObject = json.loads(response.content)

    totalCount = jsonObject['results'][0]['TotalCount']
    highSeverityCount = jsonObject['results'][0]['HighSeverityCount']
    mediumSeverityCount = jsonObject['results'][0]['MediumSeverityCount']
    lowSeverityCount = jsonObject['results'][0]['LowSeverityCount']



    ####################################
    # 
    #  Set the API endpoint, headers, and request body to count Open Alerts
    # 
    # ####################################
    url = "https://graph.microsoft.com/v1.0/security/alerts_v2?$filter=status eq 'inProgress' or status eq 'new' and detectionSource eq 'microsoftDefenderForOffice365' &$count=true&$select=id,createdDateTime,status"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    request_body = {
                    }

    # Make the API call with the request body
    logging.info("Getting Total Count of Open Alerts...")
    response = requests.get(url, headers=headers, data=json.dumps(request_body))
    #jsonObject = json.loads(response.content)
    openCount = response.json()['@odata.count']


    ####################################
    # 
    #  Set the API endpoint, headers, and request body to count Closed Alerts
    # 
    # ####################################
    url = "https://graph.microsoft.com/v1.0/security/alerts_v2?$filter=status eq 'resolved' and detectionSource eq 'microsoftDefenderForOffice365'&$count=true&$select=id,createdDateTime,status"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    request_body = {
                    }

    # Make the API call with the request body
    logging.info("Getting Total Count of Closed Alerts...")
    response = requests.get(url, headers=headers, data=json.dumps(request_body))
    #jsonObject = json.loads(response.content)
    closedCount = response.json()['@odata.count']


    logging.info("Creating CSV file for called alert_count_ms365.csv")
    # Create a list of the variables
    data = [totalCount, highSeverityCount, mediumSeverityCount, lowSeverityCount, openCount, closedCount]

    # Open the CSV file in write mode and write the data
    try:
        # with open('alert_count_ms365.csv', mode='w', newline='') as file:
        #     writer = csv.writer(file)
        #     writer.writerow(['totalCount', 'highSeverityCount', 'mediumSeverityCount', 'lowSeverityCount', 'openCount', 'closedCount'])
        #     writer.writerow(data)
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            writer = csv.writer(f)
            writer.writerow(['totalCount', 'highSeverityCount', 'mediumSeverityCount', 'lowSeverityCount', 'openCount', 'closedCount'])
            writer.writerow(data)
        logging.info("Creating csv file done.")

    except IOError:
        logging.info("Error: Unable to write to CSV file")


    logging.info("Uploading alert_count_ms365.csv to Azure Blob Storage...")
    # Define the connection string and container name
    connection_string = "DefaultEndpointsProtocol=https;AccountName=cloudmonitorai;AccountKey=-REDACTEDxK0aShfbDkF134kmUE-REDACTEDq+NqX8C+prpKh6djHhs7ZyRB44gJhU2dL7aoVzFb0G43QELC+AStfZbCXA==;EndpointSuffix=core.windows.net"
    container_name = "reports"

    # Create a BlobServiceClient object
    try:
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    except ValueError:
        logging.info("Error: Invalid connection string")
        exit()

    # Get a reference to the container
    try:
        container_client = blob_service_client.get_container_client(container_name)
    except ResourceNotFoundError:
        logging.info("Error: Container does not exist")
        exit()

    # Upload the CSV file to the container
    # Breaking into chunks to upload data reliability
    try:
        with open(f.name, 'rb') as data:
            blob_client = container_client.upload_blob(name='alert_count_ms365.csv', data=data, overwrite=True, blob_type="BlockBlob")
        logging.info("CSV file uploaded successfully!")
    except FileNotFoundError:
        logging.info("Error: File not found")
    except Exception as ex:
        logging.info("Error: Unable to upload file - {}".format(str(ex)))