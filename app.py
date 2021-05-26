from flask import Flask
import time
import uuid
import requests
import automationassets
import datetime
import dateutil.parser
from datetime import datetime, timedelta, date
app = Flask(__name__)
_AUTOMATION_RESOURCE_GROUP = "EssAstPrdWu2RgMgmt01"
_AUTOMATION_ACCOUNT = "PrdAstWu2Automation01"
_SoftwareUpdateConfigName = "W-NPE-UTC-SCHEDULE-01"

# Return token based on Azure automation Runas connection
def get_automation_runas_token(runas_connection):
    """ Returs a token that can be used to authenticate against Azure resources """
    from OpenSSL import crypto
    import adal

    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    sp_cert = crypto.load_pkcs12(cert)
    pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, sp_cert.get_privatekey())

    # Get run as connection information for the Azure Automation service principal
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    resource = "https://management.core.windows.net/"
    authority_url = ("https://login.microsoftonline.com/" + tenant_id)
    context = adal.AuthenticationContext(authority_url)
    azure_credential = context.acquire_token_with_client_certificate(
        resource,
        application_id,
        pem_pkey,
        thumbprint)

    # Return the token
    return azure_credential.get('accessToken')

# Authenticate to Azure using the Azure Automation RunAs service principal




#machineListUrl = "https://management.azure.com/subscriptions/1e4f30e0-ba75-4721-ad01-092454a46d8b/resourceGroups/EssAstPrdWu2RgMgmt01/providers/Microsoft.Automation/automationAccounts/PrdAstWu2Automation01/softwareUpdateConfigurationMachineRuns?api-version=2017-05-15-preview&$filter=properties/softwareUpdateConfiguration/name eq 'L-NPE-UTC-SCHEDULE-01'"
#machineList = requests.get(machineListUrl, headers=headers).json()
#for machine in machineList['value']:
#	print machine['properties']['softwareUpdateConfiguration']['name']

@app.route("/")
def hello():
	automation_runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
	access_token = get_automation_runas_token(automation_runas_connection)
	headers = {"Authorization": 'Bearer ' + access_token}
    #return "Hello, World!"
    machineListUrl = "https://management.azure.com/subscriptions/1e4f30e0-ba75-4721-ad01-092454a46d8b/resourceGroups/EssAstPrdWu2RgMgmt01/providers/Microsoft.Automation/automationAccounts/PrdAstWu2Automation01/softwareUpdateConfigurationMachineRuns?api-version=2017-05-15-preview&$filter=properties/softwareUpdateConfiguration/name eq 'L-NPE-UTC-SCHEDULE-01'"
    machineList = requests.get(machineListUrl, headers=headers).json()
    return machineList