#!/bin/bash

# ==============================================================================
# SCRIPT DE AUDITORÍA Y COMPROBACIÓN AUTOMÁTICA - SMR (FTPS y SFTP)
# ==============================================================================
# Este script verifica los 8 Logros de la práctica en el servidor Linux.
# Debe ejecutarse con privilegios de superusuario (sudo).
# ==============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

TOTAL_SCORE=0
MAX_SCORE=100

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}        AUDITORÍA AUTOMÁTICA DE SERVICIOS DE RED (SMR - FTPS / SFTP)  ${NC}"
echo -e "${BLUE}======================================================================${NC}\n"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] Este script debe ejecutarse como root (usa sudo ./smr_checker.sh).${NC}"
  exit 1
fi

pass_check() {
    local points=$1
    local msg=$2
    echo -e " [${GREEN}OK - +${points} pts${NC}]$msg"
    TOTAL_SCORE=$((TOTAL_SCORE + points))
}

fail_check() {
    local msg=$1
    echo -e " [${RED}FAIL - 0 pts${NC}]$msg"
}

# ------------------------------------------------------------------------------
# LOGRO 1: Cortafuegos UFW y Red
# ------------------------------------------------------------------------------
echo -e "${YELLOW}--- [LOGRO 1] Comprobando Cortafuegos (UFW) y Puertos ---${NC}"

if ufw status | grep -q "Status: active"; then
    pass_check 5 "El cortafuegos UFW está activo."
    
    # Comprobar SSH (Puerto 22)
    if ufw status | grep -E "22/(tcp|v6)" | grep -q "ALLOW"; then
        pass_check 3 "UFW permite el puerto 22 (SSH/SFTP)."
    else
        fail_check "Puerto 22 (SSH/SFTP) no está permitido explícitamente en UFW."
    fi

    # Comprobar FTP Control (Puerto 21)
    if ufw status | grep -E "21/(tcp|v6)" | grep -q "ALLOW"; then
        pass_check 3 "UFW permite el puerto 21 (FTP Control)."
    else
        fail_check "Puerto 21 (FTP Control) no está permitido en UFW."
    fi

    # Comprobar Rango Pasivo (10000:10050)
    if ufw status | grep -E "10000:10050/tcp" | grep -q "ALLOW"; then
        pass_check 4 "UFW permite el rango pasivo 10000:10050/tcp."
    else
        fail_check "Rango de puertos pasivos (10000:10050/tcp) no abierto en UFW."
    fi
else
    fail_check "El cortafuegos UFW está desactivado."
fi

# ------------------------------------------------------------------------------
# LOGRO 2: Instalación del servicio y copia de seguridad
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- [LOGRO 2] Verificando Instalación de vsftpd y Copia de Respaldo ---${NC}"

if dpkg -l | grep -q vsftpd; then
    pass_check 5 "El paquete vsftpd está instalado en el sistema."
else
    fail_check "vsftpd no está instalado."
fi

if ls /etc/vsftpd.conf.bak* >/dev/null 2>&1 || ls /etc/vsftpd.conf.orig* >/dev/null 2>&1; then
    pass_check 5 "Se ha detectado copia de seguridad de vsftpd.conf."
else
    fail_check "No se encontró copia de respaldo de vsftpd.conf en /etc/."
fi

# ------------------------------------------------------------------------------
# LOGRO 3: Gestión de Identidades (Grupo ftpgroup y Usuario ftpuser)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- [LOGRO 3] Comprobando Entidades POSIX (ftpgroup / ftpuser) ---${NC}"

if getent group ftpgroup >/dev/null; then
    pass_check 5 "Existe el grupo de sistema 'ftpgroup'."
else
    fail_check "El grupo 'ftpgroup' no existe."
fi

if id -u ftpuser >/dev/null 2>&1; then
    pass_check 5 "Existe el usuario de sistema 'ftpuser'."
    
    if id -nG ftpuser | grep -q "\bftpgroup\b"; then
        pass_check 5 "'ftpuser' pertenece al grupo 'ftpgroup'."
    else
        fail_check "'ftpuser' no pertenece al grupo 'ftpgroup'."
    fi
else
    fail_check "El usuario 'ftpuser' no existe."
fi

# ------------------------------------------------------------------------------
# LOGRO 4: Enjaulado Defensivo (Chroot) y Permisos