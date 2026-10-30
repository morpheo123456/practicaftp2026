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
    echo -e " [${GREEN}OK - +${points} pts${NC}] $msg"
    TOTAL_SCORE=$((TOTAL_SCORE + points))
}

fail_check() {
    local msg=$1
    echo -e " [${RED}FAIL - 0 pts${NC}] $msg"
}

# ------------------------------------------------------------------------------
# LOGRO 1: Cortafuegos UFW y Red (Total: 15 pts)
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
# LOGRO 2: Instalación y Estado del Servicio vsftpd (Total: 10 pts)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- [LOGRO 2] Verificando Instalación y Estado del Servicio vsftpd ---${NC}"

if dpkg -l | grep -q vsftpd; then
    pass_check 3 "El paquete vsftpd está instalado en el sistema."
else
    fail_check "vsftpd no está instalado."
fi

# Comprobar si el servicio está activo (running)
if systemctl is-active --quiet vsftpd; then
    pass_check 4 "El servicio vsftpd está activo y en ejecución."
else
    fail_check "El servicio vsftpd NO está activo (systemctl is-active vsftpd)."
fi

# Comprobar si el servicio está habilitado para el arranque (enabled)
if systemctl is-enabled --quiet vsftpd; then
    pass_check 3 "El servicio vsftpd está habilitado para iniciar con el sistema (enabled)."
else
    fail_check "El servicio vsftpd NO está habilitado en el arranque (systemctl enable vsftpd)."
fi

# ------------------------------------------------------------------------------
# LOGRO 3: Gestión de Identidades (Grupo ftpgroup y Usuario ftpuser) (Total: 15 pts)
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
# LOGRO 4: Enjaulado Defensivo (Chroot) y Permisos (Total: 15 pts)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- [LOGRO 4] Comprobando Chroot y Permisos en el Home ---${NC}"

VSFTPD_CONF="/etc/vsftpd.conf"

if grep -Eq "^\s*chroot_local_user=YES" "$VSFTPD_CONF"; then
    pass_check 5 "vsftpd está configurado con chroot_local_user=YES."
else
    fail_check "vsftpd NO tiene activado chroot_local_user=YES."
fi

USER_HOME=$(getent passwd ftpuser | cut -d: -f6)

if [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ]; then
    HOME_OWNER=$(stat -c '%U:%G' "$USER_HOME")

    if [ "$HOME_OWNER" = "root:root" ]; then
        pass_check 5 "La raíz de la jaula ($USER_HOME) pertenece a root:root."
    else
        fail_check "La raíz de la jaula ($USER_HOME) no pertenece a root:root (Actual: $HOME_OWNER)."
    fi

    if [ -d "$USER_HOME/uploads" ]; then
        UPLOADS_OWNER=$(stat -c '%U:%G' "$USER_HOME/uploads")
        pass_check 5 "Existe la subcarpeta '$USER_HOME/uploads' (Propietario: $UPLOADS_OWNER)."
    else
        fail_check "No se encontró el subdirectorio 'uploads' dentro de $USER_HOME."
    fi
else
    fail_check "No se pudo encontrar el directorio personal del usuario ftpuser."
fi

# ------------------------------------------------------------------------------
# LOGRO 5: Cifrado SSL/TLS (FTPS) y Certificados (Total: 15 pts)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- [LOGRO 5] Verificando Cifrado FTPS (SSL/TLS) ---${NC}"

if grep -Eq "^\s*ssl_enable=YES" "$VSFTPD_CONF"; then
    pass_check 5 "Cifrado SSL/TLS habilitado en vsftpd.conf (ssl_enable=YES)."
else
    fail_check "ssl_enable no está activo en vsftpd.conf."
fi

if grep -Eq "^\s*force_local_logins_ssl=YES" "$VSFTPD_CONF" && grep -Eq "^\s*force_local_data_ssl=YES" "$VSFTPD_CONF"; then
    pass_check 5 "Cifrado forzado para autenticación y datos (force_local_*_ssl=YES)."
else
    fail_check "No se está forzando el cifrado en logins o datos."
fi

CERT_FILE=$(grep -E "^\s*rsa_cert_file=" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
if [ -n "$CERT_FILE" ] && [ -f "$CERT_FILE" ]; then
    pass_check 5 "El archivo de certificado X.509 existe en la ruta $CERT_FILE."
else
    fail_check "No se encuentra el certificado indicado en vsftpd.conf."
fi

# ------------------------------------------------------------------------------
# LOGRO 6: Puertos Pasivos y Reglas de Calidad de Servicio (QoS) (Total: 10 pts)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- [LOGRO 6] Verificando Puertos Pasivos y Límites de Rendimiento ---${NC}"

MIN_PORT=$(grep -E "^\s*pasv_min_port=" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
MAX_PORT=$(grep -E "^\s*pasv_max_port=" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')

if [ "$MIN_PORT" = "10000" ] && [ "$MAX_PORT" = "10050" ]; then
    pass_check 5 "Puertos pasivos delimitados correctamente (10000:10050)."
else
    fail_check "Rango pasivo incorrecto en vsftpd.conf (Detectado: $MIN_PORT - $MAX_PORT, Requerido: 10000-10050)."
fi

RATE_LIMIT=$(grep -E "^\s*local_max_rate=" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
if [ "$RATE_LIMIT" = "500000" ]; then
    pass_check 3 "Tasa límite de transferencia configurada en 500 KB/s (500000 bytes/s)."
else
    fail_check "Ancho de banda local (local_max_rate) no configurado a 500000."
fi

IP_LIMIT=$(grep -E "^\s*max_per_ip=" "$VSFTPD_CONF" | cut -d= -f2 | tr -d ' ')
if [ "$IP_LIMIT" = "2" ]; then
    pass_check 2 "Límite de conexiones por IP configurado correctamente (max_per_ip=2)."
else
    fail_check "Límite de conexiones por IP (max_per_ip) no configurado a 2."
fi

# ------------------------------------------------------------------------------
# LOGRO 7: Subsistema SFTP Aislado en OpenSSH (Total: 10 pts)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- [LOGRO 7] Verificando Subsistema SFTP en OpenSSH (/etc/ssh/sshd_config) ---${NC}"

SSHD_CONF="/etc/ssh/sshd_config"

if grep -Eq "^\s*Subsystem\s+sftp\s+internal-sftp" "$SSHD_CONF"; then
    pass_check 4 "Uso del subsistema internal-sftp activado."
else
    fail_check "OpenSSH no utiliza internal-sftp."
fi

if grep -A 10 -i "Match Group ftpgroup" "$SSHD_CONF" | grep -q "ChrootDirectory" && \
   grep -A 10 -i "Match Group ftpgroup" "$SSHD_CONF" | grep -q "ForceCommand internal-sftp"; then
    pass_check 6 "Regla 'Match Group ftpgroup' con ChrootDirectory y ForceCommand configurada."
else
    fail_check "No se encuentra el bloque Match Group ftpgroup correctamente configurado en sshd_config."
fi

# ------------------------------------------------------------------------------
# LOGRO 8: Verificación y Auditoría de Fichero Subido (Total: 10 pts)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}--- [LOGRO 8] Comprobando Archivo de Auditoría Subido (audit.txt) ---${NC}"

AUDIT_FILE="$USER_HOME/uploads/audit.txt"

if [ -f "$AUDIT_FILE" ]; then
    pass_check 5 "El archivo 'audit.txt' existe en la carpeta /uploads del usuario."
    AUDIT_OWNER=$(stat -c '%U' "$AUDIT_FILE")
    if [ "$AUDIT_OWNER" = "ftpuser" ]; then
        pass_check 5 "El propietario de 'audit.txt' es 'ftpuser'."
    else
        fail_check "El archivo 'audit.txt' pertenece a $AUDIT_OWNER (debe pertenecer a ftpuser)."
    fi
else
    fail_check "No se encontró el archivo '$AUDIT_FILE'. Comprueba la subida por cliente."
fi

# ------------------------------------------------------------------------------
# RESUMEN DE PUNTUACIÓN
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "                   RESULTADO FINAL DE LA AUDITORÍA                    "
echo -e "${BLUE}======================================================================${NC}"

if [ "$TOTAL_SCORE" -ge 90 ]; then
    echo -e " PUNTUACIÓN TÉCNICA: ${GREEN}${TOTAL_SCORE} / ${MAX_SCORE} pts${NC} - ¡EXCELENTE TRABAJO!"
elif [ "$TOTAL_SCORE" -ge 50 ]; then
    echo -e " PUNTUACIÓN TÉCNICA: ${YELLOW}${TOTAL_SCORE} / ${MAX_SCORE} pts${NC} - PRÁCTICA APROBADA (Revisar fallos)"
else
    echo -e " PUNTUACIÓN TÉCNICA: ${RED}${TOTAL_SCORE} / ${MAX_SCORE} pts${NC} - PRÁCTICA NO SUPERADA"
fi

echo -e "${BLUE}======================================================================${NC}\n"