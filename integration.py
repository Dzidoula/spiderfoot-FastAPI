import os
import json
import time
import sqlite3
import threading
import subprocess
import requests
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
import logging
from dataclasses import dataclass
from enum import Enum

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SpiderFootConfig:
    """Configuration pour SpiderFoot"""
    spiderfoot_path: str = "/opt/spiderfoot"  # Chemin vers SpiderFoot
    data_path: str = "/opt/spiderfoot/data"   # Chemin vers les données
    web_port: int = 5001                      # Port web de SpiderFoot
    web_host: str = "127.0.0.1"              # Host web de SpiderFoot
    max_concurrent_scans: int = 5             # Nombre max de scans simultanés
    default_timeout: int = 3600               # Timeout par défaut (1h)

class SpiderFootScanStatus(str, Enum):
    """Statuts des scans SpiderFoot"""
    CREATED = "CREATED"
    STARTING = "STARTING"
    STARTED = "STARTED"
    RUNNING = "RUNNING"
    FINISHED = "FINISHED"
    STOPPED = "STOPPED"
    ERROR = "ERROR"

class SpiderFootIntegration:
    """Classe principale d'intégration avec SpiderFoot"""
    
    def __init__(self, config: SpiderFootConfig):
        self.config = config
        self.base_url = f"http://{config.web_host}:{config.web_port}"
        self.session = requests.Session()
        self.active_scans: Dict[str, Dict] = {}
        self._ensure_spiderfoot_running()
    
    def _ensure_spiderfoot_running(self):
        """S'assure que SpiderFoot est démarré"""
        try:
            response = self.session.get(f"{self.base_url}/", timeout=5)
            if response.status_code == 200:
                logger.info("SpiderFoot web interface is running")
                return True
        except requests.exceptions.RequestException:
            logger.warning("SpiderFoot web interface not accessible, attempting to start...")
            return self._start_spiderfoot_web()
        return False
    
    def _start_spiderfoot_web(self) -> bool:
        """Démarre l'interface web SpiderFoot si nécessaire"""
        try:
            cmd = [
                "python3", 
                f"{self.config.spiderfoot_path}/sf.py",
                "-l", f"{self.config.web_host}:{self.config.web_port}"
            ]
            
            # Démarrer en arrière-plan
            subprocess.Popen(
                cmd,
                cwd=self.config.spiderfoot_path,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Attendre que le service soit prêt
            for _ in range(30):  # Attendre max 30 secondes
                time.sleep(1)
                try:
                    response = self.session.get(f"{self.base_url}/", timeout=2)
                    if response.status_code == 200:
                        logger.info("SpiderFoot web interface started successfully")
                        return True
                except requests.exceptions.RequestException:
                    continue
            
            logger.error("Failed to start SpiderFoot web interface")
            return False
            
        except Exception as e:
            logger.error(f"Error starting SpiderFoot: {e}")
            return False
    
    async def create_scan(self, scan_request, scan_id: str) -> bool:
        """Créer un nouveau scan dans SpiderFoot"""
        try:
            # Préparer les modules
            modules = self._prepare_modules(scan_request.modules)
            
            # Préparer les options du scan
            scan_options = self._prepare_scan_options(scan_request)
            
            # Données pour l'API SpiderFoot
            scan_data = {
                "scanname": scan_request.scan_name,
                "scantarget": scan_request.target,
                "modulelist": ",".join(modules),
                "typelist": "ALL",  # Types de données à collecter
            }
            
            # Ajouter les options personnalisées
            scan_data.update(scan_options)
            
            # Créer le scan via l'API REST
            response = self.session.post(
                f"{self.base_url}/api/scannew",
                data=scan_data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    spiderfoot_scan_id = result.get("id")
                    
                    # Stocker l'association des IDs
                    self.active_scans[scan_id] = {
                        "spiderfoot_id": spiderfoot_scan_id,
                        "scan_name": scan_request.scan_name,
                        "target": scan_request.target,
                        "created_at": datetime.now(),
                        "status": SpiderFootScanStatus.CREATED
                    }
                    
                    logger.info(f"Scan created successfully: {scan_id} -> {spiderfoot_scan_id}")
                    return True
                else:
                    logger.error(f"SpiderFoot API error: {result.get('error', 'Unknown error')}")
                    return False
            else:
                logger.error(f"HTTP error creating scan: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating scan: {e}")
            return False
    
    async def start_scan(self, scan_id: str) -> bool:
        """Démarrer un scan SpiderFoot"""
        try:
            if scan_id not in self.active_scans:
                logger.error(f"Scan {scan_id} not found in active scans")
                return False
            
            spiderfoot_id = self.active_scans[scan_id]["spiderfoot_id"]
            
            # Démarrer le scan via l'API
            response = self.session.get(
                f"{self.base_url}/api/scanstart/{spiderfoot_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    self.active_scans[scan_id]["status"] = SpiderFootScanStatus.STARTED
                    logger.info(f"Scan started successfully: {scan_id}")
                    return True
                else:
                    logger.error(f"Error starting scan: {result.get('error')}")
                    return False
            else:
                logger.error(f"HTTP error starting scan: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error starting scan: {e}")
            return False
    
    async def get_scan_status(self, scan_id: str) -> Tuple[str, int]:
        """Récupérer le statut et le progrès d'un scan"""
        try:
            if scan_id not in self.active_scans:
                return "ERROR", 0
            
            spiderfoot_id = self.active_scans[scan_id]["spiderfoot_id"]
            
            # Récupérer le statut via l'API
            response = self.session.get(
                f"{self.base_url}/api/scanstatus/{spiderfoot_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                status = result.get("status", "ERROR")
                
                # Calculer le progrès approximatif
                progress = self._calculate_progress(result)
                
                # Mettre à jour le cache local
                self.active_scans[scan_id]["status"] = status
                
                return status, progress
            else:
                logger.error(f"HTTP error getting scan status: {response.status_code}")
                return "ERROR", 0
                
        except Exception as e:
            logger.error(f"Error getting scan status: {e}")
            return "ERROR", 0
    
    async def stop_scan(self, scan_id: str) -> bool:
        """Arrêter un scan SpiderFoot"""
        try:
            if scan_id not in self.active_scans:
                return False
            
            spiderfoot_id = self.active_scans[scan_id]["spiderfoot_id"]
            
            # Arrêter le scan via l'API
            response = self.session.get(
                f"{self.base_url}/api/scanstop/{spiderfoot_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    self.active_scans[scan_id]["status"] = SpiderFootScanStatus.STOPPED
                    logger.info(f"Scan stopped successfully: {scan_id}")
                    return True
                else:
                    logger.error(f"Error stopping scan: {result.get('error')}")
                    return False
            else:
                logger.error(f"HTTP error stopping scan: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error stopping scan: {e}")
            return False
    
    async def get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Récupérer les résultats d'un scan"""
        try:
            if scan_id not in self.active_scans:
                return []
            
            spiderfoot_id = self.active_scans[scan_id]["spiderfoot_id"]
            
            # Récupérer les résultats via l'API
            response = self.session.get(
                f"{self.base_url}/api/scanresults/{spiderfoot_id}",
                timeout=30
            )
            
            if response.status_code == 200:
                results = response.json()
                
                # Transformer les résultats au format de notre API
                formatted_results = []
                for result in results:
                    formatted_result = {
                        "scan_id": scan_id,
                        "module": result.get("module", "unknown"),
                        "data_type": result.get("type", "unknown"),
                        "data_value": result.get("data", ""),
                        "source": result.get("source", ""),
                        "timestamp": datetime.fromisoformat(result.get("time", datetime.now().isoformat())),
                        "confidence": self._calculate_confidence(result),
                        "raw_data": result
                    }
                    formatted_results.append(formatted_result)
                
                return formatted_results
            else:
                logger.error(f"HTTP error getting scan results: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting scan results: {e}")
            return []
    
    async def delete_scan(self, scan_id: str) -> bool:
        """Supprimer un scan SpiderFoot"""
        try:
            if scan_id not in self.active_scans:
                return False
            
            spiderfoot_id = self.active_scans[scan_id]["spiderfoot_id"]
            
            # Supprimer le scan via l'API
            response = self.session.get(
                f"{self.base_url}/api/scandelete/{spiderfoot_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    # Retirer du cache local
                    del self.active_scans[scan_id]
                    logger.info(f"Scan deleted successfully: {scan_id}")
                    return True
                else:
                    logger.error(f"Error deleting scan: {result.get('error')}")
                    return False
            else:
                logger.error(f"HTTP error deleting scan: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting scan: {e}")
            return False
    
    def get_available_modules(self) -> Dict[str, List[str]]:
        """Récupérer la liste des modules disponibles"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/modules",
                timeout=10
            )
            
            if response.status_code == 200:
                modules = response.json()
                # Organiser les modules par catégorie
                return self._organize_modules(modules)
            else:
                logger.error(f"HTTP error getting modules: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error getting modules: {e}")
            return {}
    
    def _prepare_modules(self, modules_str: str) -> List[str]:
        """Préparer la liste des modules"""
        modules = [m.strip() for m in modules_str.split(",")]
        return [m for m in modules if m]  # Filtrer les modules vides
    
    def _prepare_scan_options(self, scan_request) -> Dict[str, str]:
        """Préparer les options du scan"""
        options = {}
        
        # Options de délai
        if hasattr(scan_request, 'delay_between_requests'):
            options['_maxdelay'] = str(int(scan_request.delay_between_requests * 1000))  # en ms
        
        # Options de threads
        if hasattr(scan_request, 'max_threads'):
            options['_maxthreads'] = str(scan_request.max_threads)
        
        # Options de profondeur
        if hasattr(scan_request, 'max_depth'):
            options['_maxdepth'] = str(scan_request.max_depth)
        
        # Domaines exclus
        if hasattr(scan_request, 'excluded_domains') and scan_request.excluded_domains:
            options['_excludedomains'] = ",".join(scan_request.excluded_domains)
        
        return options
    
    def _calculate_progress(self, status_data: Dict) -> int:
        """Calculer le progrès approximatif d'un scan"""
        # SpiderFoot ne fournit pas directement le pourcentage
        # On peut estimer basé sur les données disponibles
        
        if status_data.get("status") == "FINISHED":
            return 100
        elif status_data.get("status") == "RUNNING":
            # Estimation basée sur le nombre de résultats ou le temps écoulé
            return min(85, 10 + len(status_data.get("results", [])) // 10)
        elif status_data.get("status") == "STARTED":
            return 5
        else:
            return 0
    
    def _calculate_confidence(self, result: Dict) -> int:
        """Calculer le niveau de confiance d'un résultat"""
        # Logique simple de calcul de confiance
        # À adapter selon les besoins spécifiques
        
        data_type = result.get("type", "")
        module = result.get("module", "")
        
        # Modules de haute confiance
        high_confidence_modules = ["sfp_dnsresolve", "sfp_whois", "sfp_subdomain_enum"]
        if module in high_confidence_modules:
            return 95
        
        # Types de données de haute confiance
        if data_type in ["IP_ADDRESS", "DOMAIN", "SUBDOMAIN"]:
            return 90
        
        # Confiance moyenne par défaut
        return 75
    
    def _organize_modules(self, modules: List[Dict]) -> Dict[str, List[str]]:
        """Organiser les modules par catégories"""
        categories = {
            "dns": [],
            "web": [],
            "network": [],
            "threat_intel": [],
            "social": [],
            "passive": [],
            "active": [],
            "other": []
        }
        
        for module in modules:
            name = module.get("name", "")
            desc = module.get("description", "").lower()
            
            # Catégorisation basique
            if "dns" in name or "dns" in desc:
                categories["dns"].append(name)
            elif "web" in name or "http" in name or "web" in desc:
                categories["web"].append(name)
            elif "port" in name or "scan" in name:
                categories["network"].append(name)
            elif "threat" in desc or "malware" in desc or "virus" in desc:
                categories["threat_intel"].append(name)
            elif "social" in desc or "email" in desc or "phone" in desc:
                categories["social"].append(name)
            elif "passive" in desc:
                categories["passive"].append(name)
            elif "active" in desc:
                categories["active"].append(name)
            else:
                categories["other"].append(name)
        
        return categories

# Service singleton
_spiderfoot_service: Optional[SpiderFootIntegration] = None

def get_spiderfoot_service() -> SpiderFootIntegration:
    """Récupérer l'instance du service SpiderFoot"""
    global _spiderfoot_service
    if _spiderfoot_service is None:
        config = SpiderFootConfig(
            spiderfoot_path=os.getenv("SPIDERFOOT_PATH", "/opt/spiderfoot"),
            data_path=os.getenv("SPIDERFOOT_DATA_PATH", "/opt/spiderfoot/data"),
            web_port=int(os.getenv("SPIDERFOOT_WEB_PORT", "5001")),
            web_host=os.getenv("SPIDERFOOT_WEB_HOST", "127.0.0.1")
        )
        _spiderfoot_service = SpiderFootIntegration(config)
    
    return _spiderfoot_service

# Fonction utilitaire pour le mapping des statuts
def map_spiderfoot_status_to_api(sf_status: str) -> str:
    """Mapper les statuts SpiderFoot vers ceux de notre API"""
    mapping = {
        "CREATED": "pending",
        "STARTING": "pending", 
        "STARTED": "running",
        "RUNNING": "running",
        "FINISHED": "completed",
        "STOPPED": "cancelled",
        "ERROR": "failed"
    }
    return mapping.get(sf_status, "failed")