#!/bin/bash

current_time=$(date +"%Y%m%d_%H%M%S")
result_file="result.txt"
final_result="rootkit_check_${current_time}.txt"

> $result_file

echo "=== Rootkit检测开始 ===" | tee -a $result_file
echo "检测时间: $(date)" | tee -a $result_file
echo "" | tee -a $result_file


check_proc_mount() {
    echo "=== 1. 检查/proc挂载异常 ===" | tee -a $result_file
    echo "检查/proc/$$/mountinfo:" | tee -a $result_file
    cat /proc/$$/mountinfo | tee -a $result_file
    echo "" | tee -a $result_file
    
    echo "检查/proc目录异常:" | tee -a $result_file
    ls -lai /proc | tee -a $result_file
    echo "" | tee -a $result_file
}

check_loader_hijack() {
    echo "=== 2. 检查动态链接器劫持 ===" | tee -a $result_file
    
    echo "检查LD_PRELOAD环境变量:" | tee -a $result_file
    if [ -n "$LD_PRELOAD" ]; then
        echo "发现LD_PRELOAD: $LD_PRELOAD" | tee -a $result_file
        unset LD_PRELOAD
        echo "已清除LD_PRELOAD环境变量" | tee -a $result_file
    else
        echo "LD_PRELOAD环境变量正常" | tee -a $result_file
    fi
    
    echo "" | tee -a $result_file
    echo "检查/etc/ld.so.preload文件:" | tee -a $result_file
    if [ -f "/etc/ld.so.preload" ]; then
        echo "发现/etc/ld.so.preload文件:" | tee -a $result_file
        cat /etc/ld.so.preload | tee -a $result_file
    else
        echo "/etc/ld.so.preload文件不存在" | tee -a $result_file
    fi
    echo "" | tee -a $result_file
}

check_shell_hijack() {
    echo "=== 3. 检查shell环境劫持 ===" | tee -a $result_file
    echo "检查/etc/profile.d/目录下可疑文件:" | tee -a $result_file
    ls -la /etc/profile.d/ | tee -a $result_file
    
    echo "" | tee -a $result_file
    echo "使用strace检查ls命令:" | tee -a $result_file
    strace -e trace=file -f /bin/ls / 2>> $result_file
    echo "" | tee -a $result_file
}

check_lkm_hijack() {
    echo "=== 4. 检查LKM劫持 ===" | tee -a $result_file
    
    echo "检查已加载模块:" | tee -a $result_file
    lsmod | tee -a $result_file
    
    echo "" | tee -a $result_file
    echo "检查内核日志中的模块信息:" | tee -a $result_file
    dmesg | grep -i 'module' | tee -a $result_file
    
    echo "" | tee -a $result_file
    echo "检查/sys/module目录:" | tee -a $result_file
    ls -la /sys/module | tee -a $result_file
    echo "" | tee -a $result_file
}

check_ebpf() {
    echo "=== 5. 检查eBPF相关进程 ===" | tee -a $result_file
    echo "检查可疑的eBPF进程:" | tee -a $result_file
    ps aux | grep -i "bpf" | grep -v grep | tee -a $result_file
    echo "" | tee -a $result_file
}

check_proc_mount
check_loader_hijack
check_shell_hijack
check_lkm_hijack
check_ebpf

cp $result_file $final_result

echo "检查完成！结果已保存到 $final_result" | tee -a $result_file
