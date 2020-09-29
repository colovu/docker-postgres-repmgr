#!/bin/bash

# shellcheck disable=SC1091

# 设置 shell 执行参数，可使用'-'(打开）'+'（关闭）控制。常用：
# 	-e: 命令执行错误则报错; -u: 变量未定义则报错; -x: 打印实际待执行的命令行; -o pipefail: 设置管道中命令遇到失败则报错
set -eu
set -o pipefail

. /usr/local/bin/comm-postgresql.sh			# 应用专用函数库
. /usr/local/bin/comm-repmgr.sh			# 应用专用函数库

. /usr/local/bin/comm-env.sh 			# 设置环境变量

LOG_I "[REPMGR EVENT] Node id: $1; Event type: $2; Success [1|0]: $3; Time: $4;  Details: $5"
event_script="${REPMGR_EVENTS_DIR}/execs/$2.sh"
LOG_D "Looking for the script: ${event_script}"
if [[ -f "${event_script}" ]]; then
    LOG_D "[REPMGR EVENT] will execute script '${event_script}' for the event"
    . "$event_script"
else
    LOG_D "[REPMGR EVENT] no script '${event_script}' found. Skipping..."
fi
