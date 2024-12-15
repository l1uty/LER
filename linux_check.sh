#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="incident_response_${TIMESTAMP}"
LOG_FILE="${OUTPUT_DIR}/investigation.log"
EVIDENCE_DIR="${OUTPUT_DIR}/evidence"

init_dirs() {
    mkdir -p "${OUTPUT_DIR}"
    mkdir -p "${EVIDENCE_DIR}"
    touch "${LOG_FILE}"
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

collect_system_info() {
    log_message "INFO" "开始收集系统信息..."
    
    {
        echo "=== 系统基本信息 ==="
        uname -a
        echo -e "\n=== IP地址信息 ==="
        ip addr
        echo -e "\n=== 当前登录用户 ==="
        who
        w
    } > "${EVIDENCE_DIR}/system_info.txt"
}

check_accounts() {
    log_message "INFO" "开始检查用户账户..."
    
    {
        echo "=== /etc/passwd 检查 ==="
        cat /etc/passwd
        
        echo -e "\n=== 超级用户检查 ==="
        awk -F: '($3 == 0) {print}' /etc/passwd
        
        echo -e "\n=== 最近添加的用户 ==="
        grep "^.*:.*:.*:.*:.*:.*:.*$" /etc/passwd | sort -t: -k3 -n | tail
        
        echo -e "\n=== Sudoers 配置 ==="
        grep "NOPASSWD" /etc/sudoers 2>/dev/null
        
        echo -e "\n=== SSH 公钥检查 ==="
        find /home -name "authorized_keys" -exec ls -l {} \;
    } > "${EVIDENCE_DIR}/account_audit.txt"
}

check_processes() {
    log_message "INFO" "开始检查系统进程..."
    
    {
        echo "=== CPU使用率最高的进程 ==="
        ps aux | sort -rn -k 3 | head -10
        
        echo -e "\n=== 内存使用率最高的进程 ==="
        ps aux | sort -rn -k 4 | head -10
        
        echo -e "\n=== 网络连接状态 ==="
        netstat -antup
        
        echo -e "\n=== 可疑进程检查 ==="
        ps aux | grep -i "nc\|bash -i\|perl -e\|python -c"
    } > "${EVIDENCE_DIR}/process_audit.txt"
}

check_filesystem() {
    log_message "INFO" "开始检查文件系统..."
    
    {
        echo "=== 最近24小时内修改的文件 ==="
        find / -mtime -1 -ls 2>/dev/null
        
        echo -e "\n=== 系统命令Hash值 ==="
        md5sum /bin/ls /bin/ps /bin/netstat 2>/dev/null
        
        echo -e "\n=== SUID文件检查 ==="
        find / -perm -4000 -ls 2>/dev/null
    } > "${EVIDENCE_DIR}/filesystem_audit.txt"
}

check_startup() {
    log_message "INFO" "开始检查启动项和计划任务..."
    
    {
        echo "=== 系统服务 ==="
        systemctl list-units --type=service
        
        echo -e "\n=== 系统定时任务 ==="
        cat /etc/crontab
        ls -la /etc/cron.*
        
        echo -e "\n=== 用户定时任务 ==="
        for user in $(cut -f1 -d: /etc/passwd); do
            crontab -l -u $user 2>/dev/null
        done
    } > "${EVIDENCE_DIR}/startup_audit.txt"
}

analyze_logs() {
    log_message "INFO" "开始分析系统日志..."
    
    {
        echo "=== Secure日志分析 ==="
        grep -i "failed\|accepted\|new user" /var/log/secure 2>/dev/null
        
        echo -e "\n=== 登录失败记录 ==="
        lastb | head -n 20
        
        echo -e "\n=== 最后登录记录 ==="
        last | head -n 20
    } > "${EVIDENCE_DIR}/log_analysis.txt"
    
    # 打包所有日志
    tar czf "${EVIDENCE_DIR}/system_logs.tar.gz" /var/log/* 2>/dev/null
}

check_backdoors() {
    log_message "INFO" "开始检查后门..."
    
    {
        echo "=== SSH配置检查 ==="
        cat /etc/ssh/sshd_config
        
        echo -e "\n=== 检查Alias后门 ==="
        alias
        
        echo -e "\n=== 检查可疑的SSH密钥 ==="
        find / -name "authorized_keys" -exec cat {} \; 2>/dev/null
    } > "${EVIDENCE_DIR}/backdoor_check.txt"
}

check_firewall() {
    log_message "INFO" "开始检查防火墙配置..."
    
    {
        echo "=== IPTables规则 ==="
        iptables -L -n
        
        echo -e "\n=== 防火墙状态 ==="
        systemctl status firewalld 2>/dev/null
    } > "${EVIDENCE_DIR}/firewall_audit.txt"
}

main() {
    init_dirs
    log_message "INFO" "开始Linux应急响应检查..."
    
    collect_system_info
    check_accounts
    check_processes
    check_filesystem
    check_startup
    analyze_logs
    check_backdoors
    check_firewall
    
    
    tar czf "incident_response_${TIMESTAMP}.tar.gz" "${OUTPUT_DIR}"
    
    log_message "INFO" "检查完成！结果保存在: incident_response_${TIMESTAMP}.tar.gz"
}

main
