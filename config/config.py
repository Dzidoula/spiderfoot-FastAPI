from pydantic import BaseSettings

class Settings(BaseSettings):
    spiderfoot_api_key: str
    spiderfoot_base_url: str
    debug: bool = True
    user_name: str 
    password: str
    
    v_username: str
    v_password: str

    class Config:
        env_file = ".env"  # lire le fichier .env automatiquement

# Instance globale qu'on peut importer partout
settings = Settings()
