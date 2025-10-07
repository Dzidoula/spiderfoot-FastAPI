from fastapi import FastAPI, HTTPException
from fastapi.security import APIKeyHeader
from logging import logging
import os, requests, json
from fastapi import FastAPI, HTTPException, Query ,Security ,Depends
from typing import List
from validation import ScanRequest, TYPESLIST
from config.config import settings

from requests.auth import HTTPDigestAuth

from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from auth import authenticate_basic_auth  # Importez la fonction d'auth




# Utilisation des constantes
#print(f"SPIDERFOOT_API_KEY = {config.SPIDERFOOT_API_KEY}")
#print(f"DEBUG = {config.DEBUG}")


app = FastAPI(
    title="SpiderFoot API Wrapper",
    description="Une API pour interagir avec SpiderFoot via son API REST.",
    version="0.115.0",
    contact= { "name": "Vullify"},
    docs_url=None,  # Désactive la route docs par défaut
    redoc_url=None, # Désactive la route redoc par défaut
)


API_KEY = settings.spiderfoot_api_key #os.getenv("SPIDERFOOT_API_KEY")
BASE_URL = settings.spiderfoot_base_url #os.getenv("SPIDERFOOT_BASE_URL")
username = settings.user_name #os.getenv("USER_NAME")
password = settings.password #os.getenv("PASSWORD")


# Si ton SpiderFoot est protégé par authentification HTTPDigest
AUTH = HTTPDigestAuth(username, password)  # adapte login/pass selon ton cas





api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False,description="Clé API pour authentification")

def get_api_key(api_key: str = Security(api_key_header)):
    if not api_key:
        raise HTTPException(status_code=401, detail="Clé API manquante")
    
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Clé API invalide")
    return api_key


# Surcharger les routes de documentation pour y ajouter l'authentification

#endpoint swagger protégé par authentification de base
@app.get("/docs", include_in_schema=False)
async def get_swagger_documentation(username: str = Depends(authenticate_basic_auth)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Docs")

#endpoint redoc protégé par authentification de base
@app.get("/redoc", include_in_schema=False)
async def get_redoc_documentation(username: str = Depends(authenticate_basic_auth)):
    return get_redoc_html(openapi_url="/openapi.json", title="ReDoc")

# Protéger également le schéma OpenAPI JSON lui-même
@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(username: str = Depends(authenticate_basic_auth)):
    from main import app
    return app.openapi()

#endpoint pour lancer un scan
@app.post("/scan")
def run_spiderfoot(request: ScanRequest, api_key: str=Security(get_api_key)):
    try:
        
        # Gestion flexible des modules
        modules = (
            request.modules if isinstance(request.modules, list)
            else request.modules.split(",") if isinstance(request.modules, str) and request.modules.strip()
            else []
        )
        
        # Préparer les données pour SpiderFoot API
        payload = {
            "scanname": request.scan_name,
            "scantarget": request.target,
            "usecase": request.use_case,
            "modulelist": ",".join(modules) if modules else "",
            "typelist": TYPESLIST if not modules else ""
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        #url ou lancer le scan dans spiderfoot
        url = f"{BASE_URL}/startscan"
        
        # Faire la requête POST à SpiderFoot
        response = requests.post(url, data=payload, headers=headers, auth=AUTH)
        logging.info("scan started")

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Erreur SpiderFoot: {response.text}")
        
        logging.info("scan started successfully")

        return {
            "status": "success",
            "scan_name": request.scan_name,
            "target": request.target,
            "modules": modules,
            "spiderfoot_response": response.json()
        }

    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Erreur de requête HTTP: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur inattendue: {str(e)}")
    
    


@app.get("/scanexportjsonmulti")
def export_multiple_scans(ids: List[str] = Query(...), api_key: str = Security(get_api_key)):
    try:
        # Préparer l'URL avec les IDs
        joined_ids = ",".join(ids)
        url = f"{BASE_URL}/scanexportjsonmulti?ids={joined_ids}"
        headers = {"Accept": "application/json"}

        response = requests.get(url, headers=headers, auth=AUTH)

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Erreur SpiderFoot: {response.text}")

        data = response.json()

        output_dir = "scan_exports_json"
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, f"multi_export_{'_'.join(ids)}.json")

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        return {
            "status": "success",
            "scan_ids": ids,
            "file": file_path,
            "event_count": len(data),
            "data": data
        }


    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Erreur HTTP: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur inattendue: {str(e)}")
    
    
    

@app.post("/scanstatus/{scan_id}")
def scan_status(scan_id: str, api_key: str =Security(get_api_key)):
    try:
        
        url = f"{BASE_URL}/scanstatus?id={scan_id}"
        headers = {"Accept": "application/json"}

        response = requests.get(url, headers=headers, auth=AUTH)

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Erreur SpiderFoot: {response.text}")

        return {
            "status": "success",
            "scan_id": scan_id,
            "message": "Scan status récupéré",
            "spiderfoot_response": response.json()
        }


    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Erreur HTTP: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur inattendue: {str(e)}")


@app.get("/stopscan/{scan_id}")
def stop_scan(scan_id: str, api_key: str = Security(get_api_key)):
    try:
        
       
            
        url = f"{BASE_URL}/stopscan?id={scan_id}"
        headers = {"Accept": "application/json"}

        response = requests.get(url, headers=headers, auth=AUTH)

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Erreur SpiderFoot: {response.text}")

        return {
            "status": "success",
            "scan_id": scan_id,
            "message": "Scan arrêté avec succès",
            "spiderfoot_response": response.json()
        }


    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Erreur HTTP: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur inattendue: {str(e)}")
    


@app.get("/scanlist")
def get_scan_list(api_key: str = Security(get_api_key)):
    try:
        url = f"{BASE_URL}/scanlist"
        headers = {"Accept": "application/json"}

        response = requests.get(url, headers=headers, auth=AUTH)

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Erreur SpiderFoot: {response.text}")

        scans = response.json()

        return {
            "status": "success",
            "scan_count": len(scans),
            "scans": scans
        }

    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Erreur HTTP: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur inattendue: {str(e)}")


