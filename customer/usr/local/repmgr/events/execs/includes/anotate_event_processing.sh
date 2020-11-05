#!/bin/bash

# 设置 shell 执行参数，可使用'-'(打开）'+'（关闭）控制。常用：
# 	-e: 命令执行错误则报错; -u: 变量未定义则报错; -x: 打印实际待执行的命令行; -o pipefail: 设置管道中命令遇到失败则报错
set -eu
set -o pipefail

header="[REPMGR EVENT::$2]"
export header
LOG_D "$header Node id: $1; Event type: $2; Success [1|0]: $3; Time: $4;  Details: $5"

if [[ $3 -ne 1 ]];then
    LOG_W "$header The event failed! No need to do anything."
    exit 1
fi

if [[ $1 -ne $(repmgr_get_node_id) ]]; then
    LOG_D "$header The event did not happen on me! No need to do anything."
    exit 1
fi
