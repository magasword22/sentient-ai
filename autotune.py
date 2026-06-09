#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script d'optimisation matérielle automatique (Hardware Tuning) pour Sentient AI.
Profilage de la RAM, du CPU, de la VRAM et du GPU pour auto-configurer l'application.
"""

import os
import sys
import json
import subprocess

CONFIG_FILE = "autotune_config.json"

def get_cpu_cores():
    return os.cpu_count() or 1

def get_total_ram_gb():
    try:
        if os.path.exists('/proc/meminfo'):
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        mem_kb = int(line.split()[1])
                        return mem_kb / (1024 * 1024)
        # Fallback macOS or other
        output = subprocess.check_output(['sysctl', '-n', 'hw.memsize'], stderr=subprocess.DEVNULL)
        return int(output.strip()) / (1024 * 1024 * 1024)
    except:
        return 8.0 # Fallback 8GB

def get_gpu_info():
    gpu_type = "None"
    vram_gb = 0.0
    
    # 1. Test NVIDIA GPU via nvidia-smi
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"], stderr=subprocess.DEVNULL)
        if out:
            vram_mb = int(out.decode().strip().split('\n')[0])
            gpu_type = "NVIDIA"
            vram_gb = vram_mb / 1024.0
            return gpu_type, vram_gb
    except:
        pass

    # 2. Test AMD GPU via lspci or rocm-smi
    try:
        lspci_out = subprocess.check_output(["lspci"], stderr=subprocess.DEVNULL).decode()
        if "VGA compatible controller" in lspci_out and ("AMD" in lspci_out or "ATI" in lspci_out):
            gpu_type = "AMD"
            vram_gb = 4.0 # default fallback for AMD if details not queryable
            # Essai de lecture de la VRAM sysfs
            vram_path = "/sys/class/drm/card0/device/mem_info_vram_total"
            if os.path.exists(vram_path):
                with open(vram_path, 'r') as f:
                    vram_bytes = int(f.read().strip())
                    vram_gb = vram_bytes / (1024 * 1024 * 1024)
            return gpu_type, vram_gb
    except:
        pass

    return gpu_type, vram_gb

def autotune():
    print("=== Sentient AI - Optimisation Matérielle Dynamique ===")
    cores = get_cpu_cores()
    ram = get_total_ram_gb()
    gpu, vram = get_gpu_info()
    
    print(f"[*] CPU : {cores} coeurs détectés")
    print(f"[*] RAM : {ram:.2f} Go disponibles")
    print(f"[*] GPU : {gpu} (VRAM : {vram:.2f} Go)")
    
    # Calcul des optimisations
    # 1. Threads Ollama (conseillé : cores - 1 ou cores - 2 pour garder de la réactivité)
    ollama_threads = max(1, cores - 1)
    
    # 2. Limites concurrentes de scan Nuclei (réduction si faible CPU/RAM pour éviter OOM/saturation)
    if ram < 4.0:
        nuclei_concurrency = 10
        nuclei_rate_limit = 50
    elif ram < 8.0:
        nuclei_concurrency = 25
        nuclei_rate_limit = 100
    else:
        nuclei_concurrency = 50
        nuclei_rate_limit = 150
        
    # 3. Choix recommandé de taille de modèle LLM selon la VRAM/RAM
    if vram >= 12.0 or (ram >= 32.0 and gpu != "None"):
        recommended_model = "llama3.1:70b"
        model_size = "Large"
    elif vram >= 6.0 or ram >= 16.0:
        recommended_model = "llama3.1:8b"
        model_size = "Medium"
    else:
        recommended_model = "qwen2.5:1.5b"
        model_size = "Small"
        
    tuning_config = {
        "cpu_cores": cores,
        "total_ram_gb": round(ram, 2),
        "gpu_detected": gpu,
        "vram_gb": round(vram, 2),
        "ollama_threads": ollama_threads,
        "nuclei_concurrency": nuclei_concurrency,
        "nuclei_rate_limit": nuclei_rate_limit,
        "recommended_llm": recommended_model,
        "model_size_category": model_size
    }
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(tuning_config, f, indent=4)
        
    print(f"[+] Optimisations enregistrées dans {CONFIG_FILE} :")
    print(json.dumps(tuning_config, indent=2))
    
if __name__ == "__main__":
    autotune()

def get_telemetry():
    """Retourne les métriques système enrichies pour l'API."""
    import psutil
    cpu_count = os.cpu_count() or 1
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    gpu_info = {"available": False, "model": "CPU Fallback", "util": 0, "vram_used": 0, "vram_total": 0, "vram_pct": 0}

    # ── GPU Detection ──────────────────────────────────────────────────
    gpu_model = "CPU Fallback"
    try:
        out = subprocess.check_output(['lspci'], stderr=subprocess.DEVNULL, timeout=5).decode().lower()
        if 'nvidia' in out: gpu_model = "NVIDIA GPU"
        elif 'amd' in out or 'radeon' in out: gpu_model = "AMD Radeon GPU"
        elif 'strix' in out: gpu_model = "AMD Strix Halo"
    except: pass

    # ── NVIDIA metrics ─────────────────────────────────────────────────
    try:
        out = subprocess.check_output(['nvidia-smi', '--query-gpu=name,memory.total,memory.used,utilization.gpu', '--format=csv,noheader,nounits'], stderr=subprocess.DEVNULL, timeout=5).decode()
        parts = out.strip().split(',')
        if len(parts) >= 4:
            gpu_model = parts[0].strip()
            gpu_info = {
                "available": True, "model": gpu_model,
                "vram_total": float(parts[1].strip()) / 1024.0,
                "vram_used": float(parts[2].strip()) / 1024.0,
                "util": float(parts[3].strip()),
            }
            gpu_info["vram_pct"] = (gpu_info["vram_used"] / gpu_info["vram_total"] * 100) if gpu_info["vram_total"] > 0 else 0
    except: pass

    # ── AMD ROCm metrics ───────────────────────────────────────────────
    if not gpu_info["available"]:
        try:
            # Try sysfs first
            for d in os.listdir('/sys/class/drm/'):
                if d.startswith('card') and os.path.exists(f'/sys/class/drm/{d}/device/gpu_busy_percent'):
                    sys_path = f'/sys/class/drm/{d}/device'
                    with open(f'{sys_path}/gpu_busy_percent') as f: gpu_util = int(f.read().strip())
                    with open(f'{sys_path}/mem_info_vram_total') as f: vram_tot = int(f.read().strip())
                    with open(f'{sys_path}/mem_info_vram_used') as f: vram_used = int(f.read().strip())
                    vram_tot_gb = vram_tot / (1024**3)
                    vram_used_gb = vram_used / (1024**3)
                    gpu_info = {
                        "available": True, "model": gpu_model if "Strix" in gpu_model else "AMD Radeon GPU",
                        "util": gpu_util, "vram_total": vram_tot_gb, "vram_used": vram_used_gb,
                        "vram_pct": (vram_used_gb / vram_tot_gb * 100) if vram_tot_gb > 0 else 0,
                    }
                    break
        except: pass

    # ── Ollama status ──────────────────────────────────────────────────
    ollama_connected = False
    ollama_models = []
    try:
        import requests
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        if r.status_code == 200:
            ollama_connected = True
            ollama_models = [m.get("name", "") for m in r.json().get("models", [])]
    except: pass

    return {
        "cpu_count": cpu_count,
        "cpu_pct": cpu,
        "ram_pct": ram.percent,
        "ram_total_gb": round(ram.total / (1024**3), 1),
        "ram_used_gb": round(ram.used / (1024**3), 1),
        "gpu": gpu_info,
        "ollama_connected": ollama_connected,
        "ollama_models": ollama_models,
    }
