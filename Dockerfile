# Utiliser une image de base Python officielle
FROM python:3.9-slim

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Copier le fichier des dépendances
COPY requirements.txt .

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copier l'ensemble du projet
COPY . .

# Exposer le port par défaut pour FastAPI (8043)
EXPOSE 8043

# Commande pour lancer l'application avec Gunicorn et Uvicorn
CMD ["uvicorn", "main:app", "--bind", "0.0.0.0:8043"]