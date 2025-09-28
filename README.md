# SpiderFoot API Wrapper

Une API REST FastAPI qui sert de wrapper pour l'interface SpiderFoot, permettant d'automatiser et de simplifier l'utilisation de SpiderFoot via des appels HTTP.

## 🚀 Fonctionnalités

- **Lancement de scans** : Démarrer des scans SpiderFoot avec configuration personnalisée
- **Gestion des scans** : Lister et arrêter les scans en cours
- **Export de données** : Exporter les résultats de plusieurs scans au format JSON
- **Authentification** : Protection par clé API
- **Validation** : Validation automatique des données d'entrée

## 📋 Prérequis

- Python 3.8+
- SpiderFoot installé et configuré (port 5001 par défaut)
- Les dépendances Python listées dans `requirements.txt`

## 🛠️ Installation

1. Clonez le repository :
```bash
git clone <url-du-repo>
cd spiderfoot-api-wrapper
```

2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

3. Configurez la variable d'environnement pour la clé API :
```bash
export SPIDERFOOT_API_KEY="votre-cle-api-securisee"
```

4. Assurez-vous que SpiderFoot est en cours d'exécution sur `localhost:5001`

## 🚀 Démarrage

Lancez l'API avec uvicorn :
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

L'API sera accessible sur `http://localhost:8000`

## 📖 Documentation API

### Authentification

Toutes les requêtes doivent inclure l'en-tête d'authentification :
```
X-API-Key: votre-cle-api
```

### Endpoints

#### 🔍 POST `/scan` - Lancer un scan

Lance un nouveau scan SpiderFoot.

**Body (JSON) :**
```json
{
  "scan_name": "Mon scan",
  "target": "example.com",
  "use_case": "Footprint",
  "modules": "sfp_dnsbrute,sfp_spider"
}
```

**Réponse :**
```json
{
  "status": "success",
  "scan_name": "Mon scan",
  "target": "\"example.com\"",
  "modules": ["sfp_dnsbrute", "sfp_spider"],
  "spiderfoot_response": {...}
}
```

#### 📊 GET `/scanlist` - Lister les scans

Récupère la liste de tous les scans.

**Réponse :**
```json
{
  "status": "success",
  "scan_count": 5,
  "scans": [...]
}
```

#### ⏹️ GET `/stopscan/{scan_id}` - Arrêter un scan

Arrête un scan en cours d'exécution.

**Paramètres :**
- `scan_id` : Identifiant du scan à arrêter

**Réponse :**
```json
{
  "status": "success",
  "scan_id": "12345",
  "message": "Scan arrêté avec succès",
  "spiderfoot_response": {...}
}
```

#### 📥 GET `/scanexportjsonmulti` - Exporter des scans

Exporte les résultats de plusieurs scans au format JSON.

**Paramètres de requête :**
- `ids` : Liste des IDs de scans à exporter (répétable)

**Exemple :**
```
GET /scanexportjsonmulti?ids=123&ids=456&ids=789
```

**Réponse :**
```json
{
  "status": "success",
  "scan_ids": ["123", "456", "789"],
  "file": "scan_exports_json/multi_export_123_456_789.json",
  "event_count": 150,
  "data": [...]
}
```

## 📁 Structure du projet

```
.
├── main.py              # Application FastAPI principale
├── validation.py        # Modèles de validation Pydantic
├── scan_exports_json/   # Dossier des exports (créé automatiquement)
└── README.md           # Ce fichier
```

## ⚙️ Configuration

### Variables d'environnement

| Variable | Défaut | Description |
|----------|---------|-------------|
| `SPIDERFOOT_API_KEY` | `c9b1d2e4-7f8a-4b3c-9d1e-2f3a4b5c6d7e` | Clé API pour l'authentification |

### Configuration SpiderFoot

Assurez-vous que votre instance SpiderFoot :
- Fonctionne sur `localhost:5001`
- Accepte les connexions API
- Est correctement configurée avec les modules nécessaires

## 🔒 Sécurité

- **Authentification requise** : Toutes les requêtes nécessitent une clé API valide
- **Validation des données** : Les données d'entrée sont validées automatiquement
- **Gestion d'erreurs** : Gestion robuste des erreurs avec messages appropriés

## 🧪 Tests

### Test avec curl

#### Lancer un scan
```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: votre-cle-api" \
  -d '{
    "scan_name": "Test Scan",
    "target": "example.com",
    "use_case": "Footprint",
    "modules": ""
  }'
```

#### Lancer un scan avec modules spécifiques
```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: votre-cle-api" \
  -d '{
    "scan_name": "Scan DNS",
    "target": "example.com",
    "use_case": "Investigate",
    "modules": "sfp_dnsbrute,sfp_spider,sfp_whois"
  }'
```

#### Lister tous les scans
```bash
curl -X GET "http://localhost:8000/scanlist" \
  -H "X-API-Key: votre-cle-api"
```

#### Arrêter un scan spécifique
```bash
curl -X GET "http://localhost:8000/stopscan/12345" \
  -H "X-API-Key: votre-cle-api"
```

#### Exporter un seul scan
```bash
curl -X GET "http://localhost:8000/scanexportjsonmulti?ids=12345" \
  -H "X-API-Key: votre-cle-api"
```

#### Exporter plusieurs scans
```bash
curl -X GET "http://localhost:8000/scanexportjsonmulti?ids=12345&ids=67890&ids=11111" \
  -H "X-API-Key: votre-cle-api"
```

#### Test d'authentification (devrait retourner 403)
```bash
curl -X GET "http://localhost:8000/scanlist" \
  -H "X-API-Key: mauvaise-cle"
```

## 🐛 Dépannage

### Erreurs communes

1. **403 Forbidden** : Vérifiez que la clé API est correcte dans l'en-tête `X-API-Key`
2. **500 Internal Server Error** : Vérifiez que SpiderFoot fonctionne sur le port 5001
3. **Connection refused** : Assurez-vous que SpiderFoot est démarré

### Logs

L'API affiche les logs d'authentification dans la console. Surveillez ces messages pour diagnostiquer les problèmes d'accès.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer de nouvelles fonctionnalités
- Améliorer la documentation
- Soumettre des pull requests


## 📞 Support

Pour toute question ou problème :
- Créez une issue sur le repository
- Consultez la documentation SpiderFoot officielle
- Vérifiez les logs d'erreur dans la console

---

**Note** : Cette API est un wrapper pour SpiderFoot. Assurez-vous de respecter les conditions d'utilisation de SpiderFoot et les réglementations locales concernant la reconnaissance et l'analyse de sécurité.