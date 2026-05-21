# Utilise une image de base Debian légère et officielle avec Python 3.11
FROM python:3.11-slim-bookworm

# Variables d'environnement pour optimiser Python et configurer Streamlit
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0

# Définition du répertoire de travail dans le conteneur
WORKDIR /app

# Installation des dépendances système requises (Nmap, weasyprint cairo/pango et rust/cargo pour compilation pip)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    wget \
    curl \
    git \
    unzip \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libjpeg-dev \
    libopenjp2-7-dev \
    libffi-dev \
    rustc \
    cargo \
    fontconfig \
    fonts-dejavu-core \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Téléchargement et installation automatique de Nuclei selon l'architecture CPU (amd64 / arm64)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then ARCH_TYPE="amd64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then ARCH_TYPE="arm64"; \
    else ARCH_TYPE="amd64"; fi && \
    wget "https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_${ARCH_TYPE}.zip" -O /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei && \
    rm -f /tmp/nuclei.zip && \
    nuclei -update-templates

# Copie du requirements.txt pour optimiser le cache de build Docker
COPY requirements.txt .

# Installation des paquets Python requis
RUN pip install --no-cache-dir -r requirements.txt

# Copie du reste des fichiers sources de l'application
COPY . .

# Exposition du port par défaut de Streamlit
EXPOSE 8501

# Démarrage de l'application Streamlit
CMD ["streamlit", "run", "app.py"]
