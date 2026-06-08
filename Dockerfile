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
    gobuster \
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

# Téléchargement et installation automatique de Nuclei, Subfinder et Trivy
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then ARCH_TYPE="amd64" && T_ARCH="64bit" && S_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then ARCH_TYPE="arm64" && T_ARCH="ARM64" && S_ARCH="arm64"; \
    else ARCH_TYPE="amd64" && T_ARCH="64bit" && S_ARCH="amd64"; fi && \
    # Nuclei
    wget "https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_${ARCH_TYPE}.zip" -O /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei && \
    rm -f /tmp/nuclei.zip && \
    nuclei -update-templates && \
    # Subfinder
    wget "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5_linux_${S_ARCH}.zip" -O /tmp/subfinder.zip && \
    unzip -o /tmp/subfinder.zip -d /usr/local/bin subfinder && \
    rm -f /tmp/subfinder.zip && \
    # Trivy
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin


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
