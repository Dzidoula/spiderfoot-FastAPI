from fastapi import FastAPI, HTTPException,Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os, requests, json, re
from validation import ScanRequest, TYPESLIST
app = FastAPI()



API_KEY = os.getenv("SPIDERFOOT_API_KEY", "c9b1d2e4-7f8a-4b3c-9d1e-2f3a4b5c6d7e")

BASE_URL = "http://localhost:5001"

@app.middleware("http")
async def api_key_auth_middleware(request: Request, call_next):
    key = request.headers.get("X-API-Key")
    print("key ..... : ", key)
    print("API_KEY ..... : ", API_KEY)
    if key != API_KEY:
        return JSONResponse(
            status_code=403,
            content={"error": "Invalid or missing API key."}
        )
    return await call_next(request)



@app.post("/scan",)
def run_spiderfoot(request: ScanRequest):
    try:
        # Préparer les données pour SpiderFoot API
        payload = {
            "scanname": request.scan_name,
            "scantarget": request.target,
            "usecase": request.use_case,
            "modulelist": request.modules,
            "typelist": "" if request.modules else TYPESLIST
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        url = BASE_URL + "/startscan"
        # Requête HTTP vers SpiderFoot
        response = requests.post(url, data=payload, headers=headers)

        # Vérification de la réponse
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Erreur SpiderFoot: {response.text}")

        # Retour JSON structuré
        return {
            "status": "success",
            "scan_name": request.scan_name,
            "target": f'"{request.target}"',
            "modules": request.modules.split(","),
            "spiderfoot_response": response.json()
        }

    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Erreur de requête HTTP: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur inattendue: {str(e)}")
    
    
    

from fastapi import FastAPI, HTTPException, Query
from typing import List


@app.get("/scanexportjsonmulti")
def export_multiple_scans(ids: List[str] = Query(...)):
    try:
        # Construction de l’URL avec les IDs encodés
        joined_ids = ",".join(ids)
        url = f"{BASE_URL}/scanexportjsonmulti?ids={joined_ids}"

        headers = {
            "Accept": "application/json"
        }

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Erreur SpiderFoot")

        data = response.json()

        # Sauvegarde dans un fichier
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
    
    
    



@app.get("/stopscan/{scan_id}")
def stop_scan(scan_id: str):
    try:
        url = f"{BASE_URL}/stopscan?id={scan_id}"
        headers = {"Accept": "application/json"}

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Erreur SpiderFoot")

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
def get_scan_list():
    try:
        url = f"{BASE_URL}/scanlist"
        headers = {"Accept": "application/json"}

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Erreur SpiderFoot")

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


