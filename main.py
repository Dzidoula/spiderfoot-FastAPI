from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os, requests, json
from validation import ScanRequest
app = FastAPI()

#class ScanRequest(BaseModel):
#    scan_name: str
#    target: str
#    modules: str  # modules séparés par des virgules

@app.post("/scan")
def run_spiderfoot(request: ScanRequest):
    try:
        # Préparer les données pour SpiderFoot API
        payload = {
            "scanname": request.scan_name,
            "scantarget": request.target,
            "usecase": "all",
            "modulelist": request.modules,
            "typelist": request.typelist
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        # Requête HTTP vers SpiderFoot
        response = requests.post("http://localhost:5001/startscan", data=payload, headers=headers)

        # Vérification de la réponse
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Erreur SpiderFoot: {response.text}")

        # Retour JSON structuré
        return {
            "status": "success",
            "scan_name": request.scan_name,
            "target": request.target,
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
        url = f"http://127.0.0.1:5001/scanexportjsonmulti?ids={joined_ids}"

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
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
        url = f"http://localhost:5001/stopscan?id={scan_id}"
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
        url = "http://localhost:5001/scanlist"
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


