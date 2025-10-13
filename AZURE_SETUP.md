# Azure Container App
To run this application as an Azure Container App follow these steps:
* Create a storage account
* Create an storage account blob, in the new storage account, by going to Object storage > Storage accounts and clicking Create
* Create a file share in the storage account blob.  Call it testappdata
* Upload all the files into testappdata, keeping the directory structure
* Modify the config.json as needed

* Login to Azure Portal
    * Go to Container Apps
    * Create a new container app
        * On the Basics tab:
            * Give the app a name
            * Deployment source: Container image
            * Select the appropriate region
            * Create a new environment: testapp1env
                * Zone redundancy: Disabled
                * Monitoring > Logs Destination: Azure Monitor
                * Networking > Public Network Access: Enable
                * Click Create
        * On the Container tab:
            * Image source: Docker hub or other registries
            * Image type: public
            * registry login server: docker.io
            * image and tag: cybersmithio/saml-oidc-test-app:20251012
            * CPU and memory: 0.5 CPU cores and 1 Gi memory
        * On the Ingress tab:
            * Ingress: Enabled
            * Ingress traffic: Accept traffic from anywhere
            * Target port: 3001
        * Click Review + Create


Go to the container app environment
Settings > Azure Files
Add SMB
Name: "data"
stroage account name: For example: "iamlab1"
storage account key:
fileshare name: data
access mode: readonly
Click Save

Container app 
Application > Volumnes
Click Add
Name: data
File share name: data
Click save new revision

Container App
Application > Containers > Volumne Mounts
Click Add
Volume name: data
Mount path: /app/data