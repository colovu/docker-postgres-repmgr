#!/bin/bash
#
# 当前节点初始化后，在主库注册当前节点

# 设置 shell 执行参数，可使用'-'(打开）'+'（关闭）控制。常用：
# 	-e: 命令执行错误则报错; -u: 变量未定义则报错; -x: 打印实际待执行的命令行; -o pipefail: 设置管道中命令遇到失败则报错
set -eu
set -o pipefail

. "${REPMGR_EVENTS_DIR}/execs/includes/anotate_event_processing.sh"
. "${REPMGR_EVENTS_DIR}/execs/includes/lock_standby.sh"
. "${REPMGR_EVENTS_DIR}/execs/includes/unlock_primary.sh"
