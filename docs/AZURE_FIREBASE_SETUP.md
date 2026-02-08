# Complete Azure and Firebase Setup Guide

## Prerequisites

Before starting, ensure you have:
- Azure account (create free at https://azure.microsoft.com/free)
- Firebase account (create free at https://firebase.google.com)
- Azure CLI installed (https://docs.microsoft.com/cli/azure/install-azure-cli)
- Firebase CLI installed (`npm install -g firebase-tools`)

---

## PART 1: AZURE SETUP (Backend)

### Step 1: Install Azure CLI

**Windows:**
```powershell
# Download and run installer from:
https://aka.ms/installazurecliwindows
```

**Mac:**
```bash
brew install azure-cli
```

**Linux:**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Verify installation:**
```bash
az --version
```

### Step 2: Login to Azure

```bash
az login
```
This will open a browser window. Sign in with your Azure account.

### Step 3: Create Resource Group

```bash
# Set variables (change these values)
RESOURCE_GROUP="honeypot-rg"
LOCATION="eastus"
APP_NAME="honeypot-backend-12345"  # Must be globally unique

# Create resource group
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION
```

**Output:** You should see a JSON response with "provisioningState": "Succeeded"

### Step 4: Create Storage Account

```bash
# Storage account name (must be unique, lowercase, no hyphens)
STORAGE_ACCOUNT="honeypotstore12345"

# Create storage account
az storage account create \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS

# Create blob container for logs
az storage container create \
  --name honeypot-logs \
  --account-name $STORAGE_ACCOUNT

# Get connection string (SAVE THIS!)
az storage account show-connection-string \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --output tsv
```

**Copy and save the connection string** - you'll need it later!

### Step 5: Create Application Insights

```bash
# Create Application Insights
az monitor app-insights component create \
  --app honeypot-insights \
  --location $LOCATION \
  --resource-group $RESOURCE_GROUP \
  --application-type web

# Get instrumentation key (SAVE THIS!)
az monitor app-insights component show \
  --app honeypot-insights \
  --resource-group $RESOURCE_GROUP \
  --query instrumentationKey \
  --output tsv
```

**Copy and save the instrumentation key!**

### Step 6: Create App Service Plan

```bash
# Create App Service plan
az appservice plan create \
  --name honeypot-plan \
  --resource-group $RESOURCE_GROUP \
  --sku B1 \
  --is-linux
```

**Cost:** B1 tier costs ~$13/month. Can use F1 (free) for testing, but limited to 60 minutes/day.

### Step 7: Create Web App

```bash
# Create Web App
az webapp create \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --plan honeypot-plan \
  --runtime "PYTHON:3.11"

# Get the URL (SAVE THIS!)
echo "Your backend URL: https://$APP_NAME.azurewebsites.net"
```

### Step 8: Configure Environment Variables

```bash
# Set environment variables
az webapp config appsettings set \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --settings \
    AZURE_STORAGE_CONNECTION_STRING="YOUR_CONNECTION_STRING_FROM_STEP_4" \
    APPINSIGHTS_INSTRUMENTATION_KEY="YOUR_KEY_FROM_STEP_5" \
    FLASK_ENV="production" \
    PYTHONUNBUFFERED="1"
```

**Replace** `YOUR_CONNECTION_STRING_FROM_STEP_4` and `YOUR_KEY_FROM_STEP_5` with actual values!

### Step 9: Deploy Backend Code

```bash
# Navigate to backend folder
cd backend

# Create deployment package
zip -r ../deploy.zip . -x "*.pyc" "__pycache__/*" "venv/*" ".env"

# Deploy
cd ..
az webapp deployment source config-zip \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --src deploy.zip

# Clean up
rm deploy.zip
```

### Step 10: Enable CORS

```bash
# Allow your Firebase domain (update after Firebase deployment)
az webapp cors add \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --allowed-origins "https://YOUR-PROJECT.web.app" "https://YOUR-PROJECT.firebaseapp.com"
```

### Step 11: Verify Azure Deployment

```bash
# Test health endpoint
curl https://$APP_NAME.azurewebsites.net/health

# Expected response:
# {"status":"healthy","timestamp":"2024-02-08T...","model_loaded":true}
```

**If you get an error:**
```bash
# Check logs
az webapp log tail --name $APP_NAME --resource-group $RESOURCE_GROUP
```

---

## PART 2: FIREBASE SETUP (Frontend)

### Step 1: Install Firebase CLI

```bash
npm install -g firebase-tools
```

**Verify:**
```bash
firebase --version
```

### Step 2: Login to Firebase

```bash
firebase login
```
This opens a browser for authentication.

### Step 3: Create Firebase Project

**Option A: Via Web Console (Recommended)**
1. Go to https://console.firebase.google.com
2. Click "Add project"
3. Enter project name: `honeypot-login`
4. Disable Google Analytics (optional for honeypot)
5. Click "Create project"

**Option B: Via CLI**
```bash
firebase projects:create honeypot-login
```

### Step 4: Initialize Firebase in Your Project

```bash
# In your project root directory
firebase init hosting

# Answer the prompts:
# ? Select Firebase project: Choose your honeypot-login project
# ? What do you want to use as your public directory? public
# ? Configure as a single-page app? No
# ? Set up automatic builds and deploys with GitHub? No
```

This creates `firebase.json` and `.firebaserc` files.

### Step 5: Prepare Frontend Files

```bash
# Create public directory
mkdir -p public

# Copy your files
cp index.html public/
cp style.css public/
cp script.js public/
cp honeypot-minimal.js public/
cp processing.html public/
```

### Step 6: Update index.html

Add this line BEFORE the closing `</body>` tag:

```html
    <script src="script.js"></script>
    <script src="honeypot-minimal.js"></script>  <!-- ADD THIS LINE -->
</body>
```

### Step 7: Configure honeypot-minimal.js

Edit `public/honeypot-minimal.js` and update the configuration:

```javascript
const CONFIG = {
    azureEndpoint: 'https://YOUR-APP-NAME.azurewebsites.net/api/track',
    enableTracking: true
};
```

Replace `YOUR-APP-NAME` with your actual Azure app name from Step 7!

### Step 8: Deploy to Firebase

```bash
firebase deploy --only hosting
```

**Output:**
```
✔ Deploy complete!

Project Console: https://console.firebase.google.com/project/honeypot-login
Hosting URL: https://honeypot-login.web.app
```

**Save your Hosting URL!**

### Step 9: Update Azure CORS

Now that you have your Firebase URL, update CORS:

```bash
az webapp cors add \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --allowed-origins "https://honeypot-login.web.app" "https://honeypot-login.firebaseapp.com"
```

---

## PART 3: ADMIN DASHBOARD SETUP

### Option 1: Host Dashboard on Firebase

```bash
# Copy dashboard to public folder
cp dashboard.html public/admin.html

# Edit public/admin.html and update API endpoint:
# const API_ENDPOINT = 'https://YOUR-APP-NAME.azurewebsites.net/api/stats';

# Deploy
firebase deploy --only hosting
```

**Access at:** https://honeypot-login.web.app/admin.html

### Option 2: Host Dashboard Separately (More Secure)

```bash
# Create a separate Firebase project for admin
firebase projects:create honeypot-admin

# Create new directory
mkdir admin-dashboard
cd admin-dashboard

# Initialize
firebase init hosting

# Copy dashboard
cp ../dashboard.html public/index.html

# Deploy
firebase deploy --only hosting
```

### Option 3: Azure Static Web App (Recommended for Production)

```bash
# Create static web app
az staticwebapp create \
  --name honeypot-dashboard \
  --resource-group $RESOURCE_GROUP \
  --location eastus2

# Deploy dashboard
az staticwebapp upload \
  --name honeypot-dashboard \
  --resource-group $RESOURCE_GROUP \
  --source dashboard.html
```

---

## VERIFICATION CHECKLIST

### ✅ Azure Backend
```bash
# 1. Health check
curl https://YOUR-APP-NAME.azurewebsites.net/health

# 2. Test tracking endpoint
curl -X POST https://YOUR-APP-NAME.azurewebsites.net/api/track \
  -H "Content-Type: application/json" \
  -d '{"session_id":"test","mouse_movements":5}'

# 3. Check stats endpoint
curl https://YOUR-APP-NAME.azurewebsites.net/api/stats
```

### ✅ Firebase Frontend
1. Open https://honeypot-login.web.app
2. Open browser DevTools → Console
3. Fill form and submit
4. Check console for API call to Azure

### ✅ Dashboard
1. Open admin dashboard URL
2. Verify charts load
3. Check for attack data

---

## TROUBLESHOOTING

### Problem: Backend returns 500 error

```bash
# Check logs
az webapp log tail --name $APP_NAME --resource-group $RESOURCE_GROUP

# Check environment variables
az webapp config appsettings list --name $APP_NAME --resource-group $RESOURCE_GROUP

# Restart app
az webapp restart --name $APP_NAME --resource-group $RESOURCE_GROUP
```

### Problem: CORS error in browser

```bash
# Add CORS for localhost (testing)
az webapp cors add \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --allowed-origins "http://localhost:8000"

# Check current CORS
az webapp cors show --name $APP_NAME --resource-group $RESOURCE_GROUP
```

### Problem: Model not loading

```bash
# SSH into Azure Web App
az webapp ssh --name $APP_NAME --resource-group $RESOURCE_GROUP

# Check if models directory exists
ls -la /home/site/wwwroot/models/

# Create if needed
mkdir -p /home/site/wwwroot/models
```

### Problem: Firebase deployment fails

```bash
# Check if logged in
firebase login --reauth

# Check project
firebase projects:list

# Use specific project
firebase use honeypot-login
```

---

## COST BREAKDOWN

### Azure (Monthly)
- App Service B1: $13.14
- Storage Account: $0.20 (for 1GB)
- Application Insights: Free tier (5GB/month)
- **Total Azure: ~$13-14/month**

### Firebase
- Hosting: Free tier (10GB/month)
- **Total Firebase: $0/month**

### **Grand Total: ~$13-14/month**

**To reduce costs:**
- Use Azure F1 tier (free, but 60 min/day limit)
- Use Azure Storage only (delete App Insights)

---

## MAINTENANCE

### View Attack Logs

```bash
# List all attack logs
az storage blob list \
  --account-name $STORAGE_ACCOUNT \
  --container-name honeypot-logs \
  --prefix "attacks/"

# Download a specific log
az storage blob download \
  --account-name $STORAGE_ACCOUNT \
  --container-name honeypot-logs \
  --name "attacks/20240208_103000_session123.json" \
  --file attack.json
```

### Update Backend Code

```bash
cd backend
zip -r ../deploy.zip . -x "*.pyc" "__pycache__/*" "venv/*"
cd ..
az webapp deployment source config-zip \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --src deploy.zip
rm deploy.zip
```

### Update Frontend

```bash
# Make changes to files in public/
firebase deploy --only hosting
```

---

## SECURITY RECOMMENDATIONS

1. **Dashboard Access:**
   ```bash
   # Set IP restrictions for dashboard
   az webapp config access-restriction add \
     --name $APP_NAME \
     --resource-group $RESOURCE_GROUP \
     --rule-name "AdminOnly" \
     --action Allow \
     --ip-address YOUR_IP_ADDRESS/32 \
     --priority 100
   ```

2. **Enable HTTPS only:**
   ```bash
   az webapp update \
     --name $APP_NAME \
     --resource-group $RESOURCE_GROUP \
     --https-only true
   ```

3. **Add authentication to dashboard** (recommended)

---

## NEXT STEPS

1. Test the honeypot with legitimate and bot-like behavior
2. Monitor Application Insights for attack patterns
3. Review attack logs in Azure Blob Storage
4. Adjust ML model threshold in backend/app.py if needed
5. Set up Azure cost alerts

---

## SUPPORT

- Azure Documentation: https://docs.microsoft.com/azure
- Firebase Documentation: https://firebase.google.com/docs
- Azure CLI Reference: https://docs.microsoft.com/cli/azure

**Your honeypot is now live!** 🎯
