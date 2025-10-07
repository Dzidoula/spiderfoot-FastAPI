# auth.py
import secrets
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from config.config import settings  # Importez vos paramètres comme dans votre code existant

# Initialiser le schéma HTTP Basic
security = HTTPBasic()

def authenticate_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    """
    Vérifie les identifiants HTTP Basic Auth de manière sécurisée contre les attaques temporelles.
    Les noms d'utilisateur et mots de passe sont chargés depuis les variables d'environnement.
    """
    # Récupération des identifiants depuis vos settings (qui lisent le .env)
    correct_username = settings.v_username
    correct_password = settings.v_password

    # Conversion en bytes pour la comparaison sécurisée
    current_username_bytes = credentials.username.encode("utf8")
    correct_username_bytes = correct_username.encode("utf8")
    current_password_bytes = credentials.password.encode("utf8")
    correct_password_bytes = correct_password.encode("utf8")

    # Comparaison sécurisée contre les attaques temporelles
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )

    # Si l'un des deux est incorrect, on lève une exception
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    # Si tout est correct, on retourne le nom d'utilisateur
    return credentials.username