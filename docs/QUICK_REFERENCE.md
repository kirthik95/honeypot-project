# Quick Reference - Azure & Firebase Commands

## 🚀 AZURE SETUP (10 minutes)

### 1. Login and Create Resources
```bash
# Login
az login

# Set variables (CHANGE THESE!)
RESOURCE_GROUP="honeypot-rg"
LOCATION="eastus"
APP_NAME="honeypot-backend-12345"  # Must be globally unique!
STORAGE_ACCOUNT="honeypotstore12345"  # Lowercase, no hyphens

# Create everything
az group create --name $RESOURCE_GROUP --location $LOCATION

az storage account create \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS

az storage container create \
  --name honeypot-logs \
  --account-name $STORAGE_ACCOUNT

az monitor app-insights component create \
  --app honeypot-insights \
  --location $LOCATION \
  --resource-group $RESOURCE_GROUP \
  --application-type web

az appservice plan create \
  --name honeypot-plan \
  --resource-group $RESOURCE_GROUP \
  --sku B1 \
  --is-linux

az webapp create \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --plan honeypot-plan \
  --runtime "PYTHON:3.11"
```

### 2. Get Connection Strings (SAVE THESE!)
```bash
# Storage connection string
az storage account show-connection-string \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --output tsv

# App Insights key
az monitor app-insights component show \
  --app honeypot-insights \
  --resource-group $RESOURCE_GROUP \
  --query instrumentationKey \
  --output tsv
```

### 3. Configure App
```bash
# Set environment variables (replace YOUR_* with actual values!)
az webapp config appsettings set \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --settings \
    AZURE_STORAGE_CONNECTION_STRING="YOUR_STORAGE_CONNECTION_STRING" \
    APPINSIGHTS_INSTRUMENTATION_KEY="YOUR_INSIGHTS_KEY" \
    FLASK_ENV="production"
```

### 4. Deploy Backend
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

### 5. Test
```bash
curl https://$APP_NAME.azurewebsites.net/health
# Should return: {"status":"healthy",...}
```

---

## 🔥 FIREBASE SETUP (5 minutes)

### 1. Login and Initialize
```bash
# Login
firebase login

# Create project (or use web console)
firebase projects:create honeypot-login

# Initialize in your directory
firebase init hosting
# Select: honeypot-login project
# Public directory: public
# Single-page app: No
```

### 2. Prepare Files
```bash
mkdir -p public
cp index.html public/
cp style.css public/
cp script.js public/
cp honeypot-minimal.js public/
cp processing.html public/
```

### 3. Update Configuration
Edit `public/honeypot-minimal.js`:
```javascript
const CONFIG = {
    azureEndpoint: 'https://YOUR-APP-NAME.azurewebsites.net/api/track',
    enableTracking: true
};
```

### 4. Deploy
```bash
firebase deploy --only hosting
```

### 5. Update CORS
```bash
# Get your Firebase URL from deploy output, then:
az webapp cors add \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --allowed-origins "https://honeypot-login.web.app"
```

---

## 📊 DASHBOARD SETUP

### Simple Way (Same Firebase Project)
```bash
cp dashboard.html public/admin.html
# Edit public/admin.html - update API endpoint
firebase deploy --only hosting
# Access at: https://honeypot-login.web.app/admin.html
```

---

## ✅ VERIFICATION

```bash
# 1. Test backend health
curl https://YOUR-APP-NAME.azurewebsites.net/health

# 2. Test tracking
curl -X POST https://YOUR-APP-NAME.azurewebsites.net/api/track \
  -H "Content-Type: application/json" \
  -d '{"session_id":"test","mouse_movements":5}'

# 3. Open frontend
https://honeypot-login.web.app

# 4. Open dashboard
https://honeypot-login.web.app/admin.html
```

---

## 🔧 COMMON ISSUES

**Backend 500 error:**
```bash
az webapp log tail --name $APP_NAME --resource-group $RESOURCE_GROUP
az webapp restart --name $APP_NAME --resource-group $RESOURCE_GROUP
```

**CORS error:**
```bash
az webapp cors show --name $APP_NAME --resource-group $RESOURCE_GROUP
az webapp cors add --name $APP_NAME --resource-group $RESOURCE_GROUP \
  --allowed-origins "https://YOUR-FIREBASE-URL.web.app"
```

**Firebase deploy fails:**
```bash
firebase login --reauth
firebase use honeypot-login
```

---

## 📈 VIEW LOGS

```bash
# List attack logs
az storage blob list \
  --account-name $STORAGE_ACCOUNT \
  --container-name honeypot-logs \
  --prefix "attacks/"

# Download log
az storage blob download \
  --account-name $STORAGE_ACCOUNT \
  --container-name honeypot-logs \
  --name "attacks/FILENAME.json" \
  --file attack.json
```

---

## 💰 COST

- Azure App Service B1: **$13/month**
- Azure Storage: **$0.20/month**
- Firebase Hosting: **FREE**
- **Total: ~$13-14/month**

---

## 🎯 WHAT YOU GET

✅ Original beautiful UI (unchanged)
✅ Invisible honeypot fields
✅ Behavioral tracking
✅ ML-based attack detection
✅ Azure cloud storage for logs
✅ Real-time monitoring dashboard
✅ Attack delay page (tarpit)

**Setup time: 15-20 minutes**
**Cost: ~$13/month**
