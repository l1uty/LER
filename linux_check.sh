#!/bin/bash

ERROR_LOG="/tmp/security_check_errors.log"

exec 2>"$ERROR_LOG"

handle_errors() {
    if [ -f "$ERROR_LOG" ]; then
        IMPORTANT_ERRORS=$(grep -iE "error|failed|warning" "$ERROR_LOG" | grep -ivE "wtmp|systemd|database|cannot open")
        if [ ! -z "$IMPORTANT_ERRORS" ]; then
            echo -e "\n重要的错误信息:"
            echo "$IMPORTANT_ERRORS"
        fi
        rm -f "$ERROR_LOG"
    fi
}

trap handle_errors EXIT
VERSION="3.0"
AUTHOR="liuty"
LAST_UPDATE="2024-01-19"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="incident_response_${TIMESTAMP}"
LOG_FILE="${OUTPUT_DIR}/investigation.log"
EVIDENCE_DIR="${OUTPUT_DIR}/evidence"
ERROR_LOG="${OUTPUT_DIR}/error.log"

show_banner() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "   Linux基线检查与应急响应工具 V${VERSION}"
    echo "   作者: ${AUTHOR}"
    echo "   更新: ${LAST_UPDATE}"
    echo "=============================================="
    echo -e "${NC}"
}

log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} ${timestamp} - ${message}" | tee -a "${LOG_FILE}"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} ${timestamp} - ${message}" | tee -a "${LOG_FILE}"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} ${timestamp} - ${message}" | tee -a "${LOG_FILE}"
            ;;
    esac
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION=$VERSION_ID
        OS_PRETTY_NAME=$PRETTY_NAME
    elif [ -f /etc/redhat-release ]; then
        OS_NAME="rhel"
        OS_PRETTY_NAME=$(cat /etc/redhat-release)
    elif [ -f /etc/debian_version ]; then
        OS_NAME="debian"
        OS_VERSION=$(cat /etc/debian_version)
        OS_PRETTY_NAME="Debian $OS_VERSION"
    else
        OS_NAME="unknown"
        OS_PRETTY_NAME="Unknown Linux Distribution"
    fi
    
    if command -v apt >/dev/null 2>&1; then
        PKG_MANAGER="apt"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MANAGER="pacman"
    else
        PKG_MANAGER="unknown"
    fi
    
    log_message "INFO" "系统信息: $OS_PRETTY_NAME"
    log_message "INFO" "包管理器: $PKG_MANAGER"
}

check_tools() {
    log_message "INFO" "检查必要工具..."
    
    BASIC_TOOLS="netstat ss lsof ps top vmstat iostat iftop htop strace"
    SECURITY_TOOLS="chkrootkit rkhunter lynis"
    NETWORK_TOOLS="tcpdump nmap curl wget"
    FORENSIC_TOOLS="volatility autopsy sleuthkit"
    
    MISSING_TOOLS=""
    
    for tool in $BASIC_TOOLS $SECURITY_TOOLS $NETWORK_TOOLS; do
        if ! command -v $tool >/dev/null 2>&1; then
            MISSING_TOOLS="$MISSING_TOOLS $tool"
        fi
    done
    
    if [ ! -z "$MISSING_TOOLS" ]; then
        log_message "WARN" "缺少以下工具: $MISSING_TOOLS"
        
        case $PKG_MANAGER in
            "apt")
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y -qq $MISSING_TOOLS >/dev/null 2>&1
                ;;
            "yum"|"dnf")
                $PKG_MANAGER install -y -q epel-release >/dev/null 2>&1
                $PKG_MANAGER install -y -q $MISSING_TOOLS >/dev/null 2>&1
                ;;
            "pacman")
                pacman -Sy --noconfirm $MISSING_TOOLS >/dev/null 2>&1
                ;;
        esac
    fi
}

init_dirs() {
    mkdir -p "${OUTPUT_DIR}"
    mkdir -p "${EVIDENCE_DIR}"
    mkdir -p "${EVIDENCE_DIR}/system"
    mkdir -p "${EVIDENCE_DIR}/network"
    mkdir -p "${EVIDENCE_DIR}/security"
    mkdir -p "${EVIDENCE_DIR}/logs"
    mkdir -p "${EVIDENCE_DIR}/files"
    mkdir -p "${EVIDENCE_DIR}/memory"
    touch "${LOG_FILE}"
    touch "${ERROR_LOG}"
}

check_environment() {
    if [ "$(id -u)" -ne 0 ]; then
        log_message "ERROR" "此脚本需要root权限运行"
        exit 1
    fi
    
    FREE_SPACE=$(df -h / | awk 'NR==2 {print $4}')
    log_message "INFO" "可用磁盘空间: $FREE_SPACE"
    
    FREE_MEM=$(free -h | awk '/^Mem:/ {print $4}')
    log_message "INFO" "可用内存: $FREE_MEM"
    
    LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}')
    log_message "INFO" "系统负载: $LOAD_AVG"
}

collect_system_info() {
    log_message "INFO" "收集系统基础信息..."
    
    {
        echo "================ 系统基本信息 ================"
        echo "检查时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "主机名: $(hostname)"
        echo "内核版本: $(uname -a)"
        echo "操作系统: $OS_PRETTY_NAME"
        echo "运行时间: $(uptime)"
        
        echo -e "\n================ CPU信息 ================"
        lscpu
        echo -e "\nCPU使用率TOP10进程:"
        ps aux --sort=-%cpu | head -n 11
        
        echo -e "\n================ 内存信息 ================"
        free -h
        echo -e "\n内存使用率TOP10进程:"
        ps aux --sort=-%mem | head -n 11
        
        echo -e "\n================ 磁盘信息 ================"
        df -h
        echo -e "\n磁盘I/O状态:"
        iostat -x 1 5 2>/dev/null
        
        echo -e "\n================ 挂载信息 ================"
        mount | column -t
        echo -e "\n可疑挂载点检查:"
        findmnt -t nfs,cifs,fuse.sshfs
        
        echo -e "\n================ 系统变量 ================"
        env | sort
        
        echo -e "\n================ 系统限制 ================"
        ulimit -a
        
        echo -e "\n================ 系统时间信息 ================"
        timedatectl 2>/dev/null || date
        echo "NTP同步状态:"
        if command -v ntpq >/dev/null 2>&1; then
            ntpq -p
        else
            echo "NTP服务未安装"
        fi
        
    } > "${EVIDENCE_DIR}/system/basic_info.txt"
}

check_security_config() {
    log_message "INFO" "检查系统安全配置..."
    
    {
        echo "================ 密码策略 ================"
        echo "密码过期策略:"
        cat /etc/login.defs | grep -i "pass"
        
        echo -e "\n密码强度策略:"
        if [ -f "/etc/security/pwquality.conf" ]; then
            cat /etc/security/pwquality.conf
        elif [ -f "/etc/pam.d/system-auth" ]; then
            cat /etc/pam.d/system-auth
        fi
        
        echo -e "\n================ SELinux/AppArmor状态 ================"
        if command -v getenforce >/dev/null 2>&1; then
            echo "SELinux状态: $(getenforce)"
            sestatus
        elif command -v apparmor_status >/dev/null 2>&1; then
            echo "AppArmor状态:"
            apparmor_status
        else
            echo "未发现SELinux或AppArmor"
        fi
        
        echo -e "\n================ 系统完整性检查 ================"
        echo "SUID文件列表:"
        find / -type f -perm -4000 -ls 2>/dev/null
        
        echo -e "\nSGID文件列表:"
        find / -type f -perm -2000 -ls 2>/dev/null
        
        echo -e "\n世界可写文件列表:"
        find / -type f -perm -2 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" -ls 2>/dev/null
        
        echo -e "\n================ 重要文件权限 ================"
        for file in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config; do
            if [ -f "$file" ]; then
                echo "=== $file ==="
                ls -l "$file"
                stat "$file"
            fi
        done
        
        echo -e "\n================ 文件完整性 ================"
        echo "关键系统文件Hash值:"
        for file in /bin/bash /bin/sh /bin/login /bin/ls /usr/bin/top /bin/netstat /usr/sbin/sshd; do
            if [ -f "$file" ]; then
                echo "$file:"
                md5sum "$file"
                sha256sum "$file"
            fi
        done
        
        echo -e "\n================ 系统审计配置 ================"
        if [ -f "/etc/audit/auditd.conf" ]; then
            cat /etc/audit/auditd.conf
        fi
        
        echo -e "\n================ 系统核心转储配置 ================"
        if [ -f "/etc/security/limits.conf" ]; then
            grep -i "core" /etc/security/limits.conf
        fi
        
        echo -e "\n================ 系统随机数熵值 ================"
        if [ -f "/proc/sys/kernel/random/entropy_avail" ]; then
            cat /proc/sys/kernel/random/entropy_avail
        fi
        
        echo -e "\n================ 系统共享内存段 ================"
        ipcs -a
        
        echo -e "\n================ 可加载内核模块 ================"
        lsmod
        
    } > "${EVIDENCE_DIR}/security/security_config.txt"
}

check_accounts() {
    log_message "INFO" "检查系统账户..."
    
    {
        echo "================ 用户账户检查 ================"
        echo "特权用户列表(UID=0):"
        awk -F: '($3 == 0) {print}' /etc/passwd
        
        echo -e "\n系统用户列表:"
        awk -F: '($3 < 1000) {print}' /etc/passwd
        
        echo -e "\n普通用户列表:"
        awk -F: '($3 >= 1000) {print}' /etc/passwd
        
        echo -e "\n可登录用户列表:"
        grep -v '/nologin\|/false' /etc/passwd
        
        echo -e "\n空密码用户检查:"
        awk -F: '($2 == "") {print}' /etc/shadow
        
        echo -e "\n================ 用户组检查 ================"
        echo "所有组列表:"
        cat /etc/group
        
        echo -e "\n特权组成员:"
        for group in root wheel sudo admin; do
            echo "=== $group 组成员 ==="
            getent group $group 2>/dev/null
        done
        
        echo -e "\n================ sudo配置检查 ================"
        if [ -d "/etc/sudoers.d" ]; then
            echo "主配置文件:"
            cat /etc/sudoers 2>/dev/null
            echo -e "\n附加配置文件:"
            for file in /etc/sudoers.d/*; do
                if [ -f "$file" ]; then
                    echo "=== $file ==="
                    cat "$file" 2>/dev/null
                fi
            done
        fi
        
        echo -e "\n================ 最近登录活动 ================"
        echo "成功登录记录:"
        last 2>/dev/null | head -n 20
        
        echo -e "\n失败登录记录:"
        if command -v lastb >/dev/null 2>&1; then
            lastb 2>/dev/null | head -n 20
        fi
        
        echo -e "\n当前登录用户:"
        who -a 2>/dev/null
        
        echo -e "\n================ SSH密钥检查 ================"
        echo "授权密钥文件:"
        find /home /root -name "authorized_keys" -ls -exec cat {} \; 2>/dev/null
        
        echo "已知主机:"
        find /home /root -name "known_hosts" -ls 2>/dev/null
        
    } > "${EVIDENCE_DIR}/security/account_audit.txt"
}

check_processes() {
    log_message "INFO" "检查系统进程..."
    
    {
        echo "================ 进程基本信息 ================"
        echo "进程树:"
        pstree -p
        
        echo -e "\n完整进程列表:"
        ps auxf
        
        echo -e "\n================ 异常进程检查 ================"
        echo "CPU使用率超过50%的进程:"
        ps aux | awk '$3 > 50.0 {print}'
        
        echo -e "\n内存使用率超过50%的进程:"
        ps aux | awk '$4 > 50.0 {print}'
        
        echo -e "\n僵尸进程:"
        ps aux | awk '$8 ~ /Z/ {print}'
        
        echo -e "\n无父进程的进程:"
        ps aux | awk '$3 == 1 {print}'
        
        echo -e "\n================ 可疑进程特征 ================"
        echo "命令行包含base64的进程:"
        ps aux | grep -i "base64"
        
        echo -e "\n可能的挖矿进程:"
        ps aux | grep -i "minerd\|cpuminer\|xmrig\|cryptonight\|stratum\|monero"
        
        echo -e "\n可能的反弹shell:"
        ps aux | grep -i "bash -i\|/dev/tcp/\|nc\|netcat\|python.*connect"
        
        echo -e "\n================ 进程文件完整性 ================"
        echo "检查进程可执行文件:"
        for pid in $(ps -ef | awk '{print $2}'); do
            if [ -f "/proc/$pid/exe" ]; then
                echo "PID $pid:"
                ls -l "/proc/$pid/exe" 2>/dev/null
                file "/proc/$pid/exe" 2>/dev/null
                md5sum "/proc/$pid/exe" 2>/dev/null
            fi
        done
        
        echo -e "\n================ 进程网络连接 ================"
        echo "进程网络连接状态:"
        netstat -tunp 2>/dev/null
        
        echo -e "\n================ 进程文件句柄 ================"
        echo "打开的文件数量TOP10进程:"
        lsof | awk '{print $2}' | sort | uniq -c | sort -rn | head -10
        
        echo -e "\n================ 进程资源限制 ================"
        for pid in $(ps -ef | awk '{print $2}' | head -10); do
            if [ -f "/proc/$pid/limits" ]; then
                echo "PID $pid limits:"
                cat "/proc/$pid/limits" 2>/dev/null
            fi
        done
        
    } > "${EVIDENCE_DIR}/system/process_audit.txt"
}

check_network() {
    log_message "INFO" "检查网络连接..."
    
    {
        echo "================ 网络接口信息 ================"
        echo "接口配置:"
        ip addr show 2>/dev/null || ifconfig -a
        
        echo -e "\n路由表:"
        ip route show 2>/dev/null || route -n
        
        echo -e "\n接口统计:"
        ip -s link 2>/dev/null
        
        echo -e "\n================ 网络连接状态 ================"
        echo "活动连接:"
        netstat -antup 2>/dev/null || ss -antup
        
        echo -e "\n监听端口:"
        netstat -tlnp 2>/dev/null || ss -tlnp
        
        echo -e "\nSocket统计:"
        netstat -s 2>/dev/null || ss -s
        
        echo -e "\n================ ARP缓存 ================"
        arp -an 2>/dev/null || ip neigh show
        
        echo -e "\n================ DNS配置 ================"
        echo "resolv.conf:"
        cat /etc/resolv.conf
        
        echo -e "\nhost.conf:"
        cat /etc/host.conf
        
        echo -e "\nhosts文件:"
        cat /etc/hosts
        
        echo -e "\n================ 防火墙规则 ================"
        echo "iptables规则:"
        iptables-save 2>/dev/null
        
        echo -e "\nip6tables规则:"
        ip6tables-save 2>/dev/null
        
        if command -v firewall-cmd >/dev/null 2>&1; then
            echo -e "\nfirewalld规则:"
            firewall-cmd --list-all 2>/dev/null
        fi
        
        if command -v ufw >/dev/null 2>&1; then
            echo -e "\nufw规则:"
            ufw status verbose 2>/dev/null
        fi
        
        echo -e "\n================ 网络流量分析 ================"
        if command -v tcpdump >/dev/null 2>&1; then
            echo "捕获60秒网络流量摘要:"
            timeout 60 tcpdump -nn -c 1000 2>/dev/null
        fi
        
        echo -e "\n================ 网络服务发现 ================"
        if command -v nmap >/dev/null 2>&1; then
            echo "本地端口扫描:"
            nmap -sT -p- localhost 2>/dev/null
        fi
        
        echo -e "\n================ 网络配置文件 ================"
        echo "网络配置文件列表:"
        ls -la /etc/sysconfig/network-scripts/* 2>/dev/null
        ls -la /etc/network/interfaces.d/* 2>/dev/null
        
        echo -e "\n================ 网络性能 ================"
        echo "网络延迟检测:"
        ping -c 4 8.8.8.8 2>/dev/null
        
        if command -v traceroute >/dev/null 2>&1; then
            echo -e "\n路由跟踪:"
            traceroute -n 8.8.8.8 2>/dev/null
        fi
        
    } > "${EVIDENCE_DIR}/network/network_audit.txt"
}

check_services() {
    log_message "INFO" "检查系统服务..."
    
    {
        echo "================ 系统服务状态 ================"
        if command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --all >/dev/null 2>&1; then
            echo "Systemd服务列表:"
            systemctl list-units --type=service --all 2>/dev/null
            
            echo -e "\n开机自启动服务:"
            systemctl list-unit-files --state=enabled 2>/dev/null
            
            echo -e "\n失败的服务:"
            systemctl --failed 2>/dev/null
        elif command -v service >/dev/null 2>&1; then
            echo "SysV服务列表:"
            service --status-all 2>/dev/null
            
            echo -e "\n开机自启动服务:"
            chkconfig --list 2>/dev/null
        else
            echo "未找到支持的服务管理器"
        fi
        
        echo -e "\n================ Web服务检查 ================"
        if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
            echo "Apache配置:"
            if [ -f "/etc/apache2/apache2.conf" ]; then
                cat /etc/apache2/apache2.conf
            elif [ -f "/etc/httpd/conf/httpd.conf" ]; then
                cat /etc/httpd/conf/httpd.conf
            fi
            
            echo -e "\nApache模块:"
            apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null
        fi
        
        if command -v nginx >/dev/null 2>&1; then
            echo -e "\nNginx配置:"
            cat /etc/nginx/nginx.conf 2>/dev/null
            
            echo -e "\nNginx虚拟主机:"
            ls -la /etc/nginx/sites-enabled/ 2>/dev/null
            ls -la /etc/nginx/conf.d/ 2>/dev/null
        fi
        
        echo -e "\n================ 数据库服务检查 ================"
        if command -v mysql >/dev/null 2>&1; then
            echo "MySQL/MariaDB配置:"
            cat /etc/mysql/my.cnf 2>/dev/null
            
            echo -e "\nMySQL进程:"
            ps aux | grep mysql
        fi
        
        if command -v psql >/dev/null 2>&1; then
            echo -e "\nPostgreSQL配置:"
            cat /etc/postgresql/*/main/postgresql.conf 2>/dev/null
            
            echo -e "\nPostgreSQL进程:"
            ps aux | grep postgres
        fi
        
        echo -e "\n================ SSH服务检查 ================"
        if [ -f "/etc/ssh/sshd_config" ]; then
            echo "SSH配置:"
            cat /etc/ssh/sshd_config
            
            echo -e "\nSSH密钥:"
            ls -la /etc/ssh/ssh_host_*
        fi
        
        echo -e "\n================ 定时任务服务 ================"
        echo "系统定时任务:"
        cat /etc/crontab 2>/dev/null
        
        echo -e "\n用户定时任务:"
        for user in $(cut -f1 -d: /etc/passwd); do
            echo "=== $user 的定时任务 ==="
            crontab -u $user -l 2>/dev/null
        done
        
        echo -e "\n================ 邮件服务检查 ================"
        if command -v postfix >/dev/null 2>&1; then
            echo "Postfix配置:"
            postconf 2>/dev/null
        fi
        
        if command -v sendmail >/dev/null 2>&1; then
            echo -e "\nSendmail配置:"
            sendmail -d0.1 -bv root 2>/dev/null
        fi
        
    } > "${EVIDENCE_DIR}/system/services_audit.txt"
} 

analyze_logs() {
    log_message "INFO" "分析系统日志..."
    
    {
        echo "================ 系统日志分析 ================"
        case $OS_NAME in
            "ubuntu"|"debian")
                AUTH_LOG="/var/log/auth.log"
                SYSLOG="/var/log/syslog"
                ;;
            "centos"|"rhel"|"fedora")
                AUTH_LOG="/var/log/secure"
                SYSLOG="/var/log/messages"
                ;;
            *)
                AUTH_LOG="/var/log/auth.log"
                SYSLOG="/var/log/syslog"
                ;;
        esac
        
        echo "认证日志分析:"
        if [ -f "$AUTH_LOG" ]; then
            echo "失败的登录尝试:"
            grep -i "failed\|failure" "$AUTH_LOG" | tail -n 100
            
            echo -e "\n成功的登录:"
            grep -i "session opened" "$AUTH_LOG" | tail -n 50
            
            echo -e "\n密码修改:"
            grep -i "password changed" "$AUTH_LOG" | tail -n 20
            
            echo -e "\nSSH登录尝试:"
            grep -i "sshd" "$AUTH_LOG" | tail -n 100
        fi
        
        echo -e "\n系统日志分析:"
        if [ -f "$SYSLOG" ]; then
            echo "系统错误:"
            grep -i "error\|fail\|warning" "$SYSLOG" | tail -n 100
            
            echo -e "\n系统重启记录:"
            grep -i "restart\|shutdown\|boot" "$SYSLOG" | tail -n 20
        fi
        
        echo -e "\n================ 安全审计日志 ================"
        if command -v ausearch >/dev/null 2>&1; then
            echo "特权命令执行记录:"
            ausearch -ua 0 -p 0 2>/dev/null | tail -n 50
            
            echo -e "\n文件访问审计:"
            ausearch -f /etc/passwd -f /etc/shadow 2>/dev/null | tail -n 50
        fi
        
        echo -e "\n================ Web服务器日志 ================"
        for log in /var/log/apache2/access.log /var/log/httpd/access_log; do
            if [ -f "$log" ]; then
                echo "Apache访问日志分析 ($log):"
                echo "访问量TOP 10 IP:"
                awk '{print $1}' "$log" | sort | uniq -c | sort -nr | head -10
                
                echo -e "\n可疑的Web请求:"
                grep -i "union\|select\|concat\|eval\|exec" "$log" | tail -n 50
            fi
        done
        
        for log in /var/log/nginx/access.log; do
            if [ -f "$log" ]; then
                echo -e "\nNginx访问日志分析 ($log):"
                echo "访问量TOP 10 IP:"
                awk '{print $1}' "$log" | sort | uniq -c | sort -nr | head -10
                
                echo -e "\n可疑的Web请求:"
                grep -i "union\|select\|concat\|eval\|exec" "$log" | tail -n 50
            fi
        done
        
    } > "${EVIDENCE_DIR}/logs/log_analysis.txt"
    
    log_message "INFO" "打包重要日志文件..."
    tar czf "${EVIDENCE_DIR}/logs/important_logs.tar.gz" \
        /var/log/auth.log* \
        /var/log/secure* \
        /var/log/syslog* \
        /var/log/messages* \
        /var/log/apache2/* \
        /var/log/httpd/* \
        /var/log/nginx/* \
        /var/log/mysql/* \
        /var/log/postgresql/* \
        /var/log/audit/* \
        2>/dev/null
}

check_suspicious_files() {
    log_message "INFO" "检查可疑文件..."
    
    {
        echo "================ 最近修改的文件 ================"
        echo "过去24小时内修改的文件:"
        find / -type f -mtime -1 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" -ls 2>/dev/null
        
        echo -e "\n================ 可疑文件检查 ================"
        echo "可执行文件权限检查:"
        find /tmp /var/tmp /dev/shm -type f -perm -100 -ls 2>/dev/null
        
        echo -e "\n隐藏文件和目录:"
        find / -name ".*" -ls 2>/dev/null | grep -v "/\.|/..$"
        
        echo -e "\n================ Web Shell检查 ================"
        echo "PHP可疑文件:"
        find / -name "*.php" -type f -exec grep -l "eval\|base64_decode\|system\|passthru\|shell_exec" {} \; 2>/dev/null
        
        echo -e "\nJSP可疑文件:"
        find / -name "*.jsp" -type f -exec grep -l "Runtime.getRuntime\|ProcessBuilder" {} \; 2>/dev/null
        
        echo -e "\n================ 系统关键文件检查 ================"
        echo "检查关键文件修改时间:"
        for file in /bin/ls /bin/ps /bin/netstat /bin/ss /bin/top /usr/sbin/sshd; do
            if [ -f "$file" ]; then
                echo "$file:"
                ls -la "$file"
                stat "$file"
            fi
        done
        
        echo -e "\n================ 临时文件检查 ================"
        echo "检查临时目录大文件:"
        find /tmp /var/tmp /dev/shm -type f -size +1M -ls 2>/dev/null
        
        echo -e "\n检查临时目录脚本文件:"
        find /tmp /var/tmp /dev/shm -type f -name "*.sh" -o -name "*.py" -o -name "*.pl" -ls 2>/dev/null
        
    } > "${EVIDENCE_DIR}/files/suspicious_files.txt"
}

generate_statistics() {
    log_message "INFO" "生成统计信息..."
    
    {
        echo "================ 系统安全统计 ================"
        echo "特权用户数量: $(grep -c '^.*:.*:0:' /etc/passwd)"
        echo "可登录用户数量: $(grep -c '/bin/bash\|/bin/sh' /etc/passwd)"
        echo "当前登录用户数: $(who | wc -l)"
        echo "失败的登录尝试: $(grep -c "Failed password" "$AUTH_LOG" 2>/dev/null)"
        echo "SUID文件数量: $(find / -type f -perm -4000 2>/dev/null | wc -l)"
        echo "SGID文件数量: $(find / -type f -perm -2000 2>/dev/null | wc -l)"
        echo "世界可写文件数量: $(find / -type f -perm -2 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | wc -l)"
        
        echo -e "\n================ 系统性能统计 ================"
        echo "CPU使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
        echo "内存使用率: $(free | grep Mem | awk '{print $3/$2 * 100}')%"
        echo "磁盘使用率: $(df -h / | awk 'NR==2 {print $5}')"
        echo "进程总数: $(ps aux | wc -l)"
        echo "TCP连接数: $(netstat -ant | wc -l)"
        echo "监听端口数: $(netstat -tlun | grep -c LISTEN)"
        
        echo -e "\n================ 安全检查统计 ================"
        echo "可疑进程数: $(ps aux | grep -i "minerd\|cpuminer\|xmrig" | grep -v grep | wc -l)"
        echo "可疑网络连接: $(netstat -ant | grep -c "ESTABLISHED")"
        echo "可疑的Web Shell: $(find / -name "*.php" -type f -exec grep -l "eval" {} \; 2>/dev/null | wc -l)"
        
    } > "${EVIDENCE_DIR}/statistics.txt"
}

generate_html_report() {
    log_message "INFO" "生成HTML报告..."
    
    cat > "${OUTPUT_DIR}/report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Linux系统安全检查报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #bdc3c7; }
        .warning { color: #c0392b; }
        .info { color: #2980b9; }
        pre { background-color: #f9f9f9; padding: 10px; }
    </style>
</head>
<body>
    <h1>Linux系统安全检查报告</h1>
    <div class="section">
        <h2>基本信息</h2>
        <pre>$(cat "${EVIDENCE_DIR}/system/basic_info.txt")</pre>
    </div>
    
    <div class="section">
        <h2>安全统计</h2>
        <pre>$(cat "${EVIDENCE_DIR}/statistics.txt")</pre>
    </div>
    
    <div class="section">
        <h2>系统服务</h2>
        <pre>$(cat "${EVIDENCE_DIR}/system/services_audit.txt")</pre>
    </div>
    
    <div class="section">
        <h2>网络连接</h2>
        <pre>$(cat "${EVIDENCE_DIR}/network/network_audit.txt")</pre>
    </div>
    
    <div class="section">
        <h2>可疑文件</h2>
        <pre>$(cat "${EVIDENCE_DIR}/files/suspicious_files.txt")</pre>
    </div>
    
    <div class="section">
        <h2>日志分析</h2>
        <pre>$(cat "${EVIDENCE_DIR}/logs/log_analysis.txt")</pre>
    </div>
</body>
</html>
EOF
}

main() {
    show_banner
    
    if [ "$(id -u)" -ne 0 ]; then
        log_message "ERROR" "此脚本需要root权限运行"
        exit 1
    fi 
    init_dirs
    detect_os
    check_tools
    check_environment
    
    {
    collect_system_info
    check_security_config
    check_accounts
    check_processes
    check_network
    check_services
    check_suspicious_files
    analyze_logs
    } 2>>"$ERROR_LOG"
    
    generate_statistics
    generate_html_report
    
    log_message "INFO" "打包检查结果..."
    tar czf "incident_response_${TIMESTAMP}.tar.gz" "${OUTPUT_DIR}" 2>/dev/null
    
    log_message "INFO" "检查完成！"
    log_message "INFO" "报告位置: ${OUTPUT_DIR}/report.html"
    log_message "INFO" "完整结果: incident_response_${TIMESTAMP}.tar.gz"
    
    echo -e "\n=== 检查结果摘要 ==="
    cat "${EVIDENCE_DIR}/statistics.txt"
}

main "$@"