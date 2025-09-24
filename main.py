from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="SpiderFoot FastAPI", description="API to control SpiderFoot scans")

class ScanRequest(BaseModel):
    scan_name: str
    target: str
    modules: str = "sfp_dnsresolve,sfp_whois"  # Modules par défaut pour tests rapides

@app.post("/scan")
async def run_spiderfoot(request: ScanRequest):
    try:
        # Validation des entrées
        if not request.target or not request.scan_name:
            raise HTTPException(status_code=400, detail="Scan name and target are required")
        
        # Chemin vers SpiderFoot
        spiderfoot_path = os.getenv("SPIDERFOOT_PATH")
        if not spiderfoot_path or not os.path.exists(spiderfoot_path):
            raise HTTPException(status_code=500, detail="SpiderFoot path not found")

        # Commande SpiderFoot
        cmd = [
            "python3", "sf.py",
            "-s", request.target,
            "-m", request.modules,
            "-o", "json",
            "-q"  # Mode silencieux
        ]
        
        # Exécuter le scan
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=spiderfoot_path,
            timeout=300  # Timeout de 5 minutes
        )

        # Vérifier le code de retour
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Scan failed: {result.stderr}")

        # Parser la sortie JSON
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise HTTPException(status_code=500, detail="Invalid JSON output from SpiderFoot")

        return {
            "status": "success",
            "scan_name": request.scan_name,
            "target": request.target,
            "data": output
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Scan timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="SpiderFoot executable not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/health")
async def health_check():
    return {"status": "API is running"}