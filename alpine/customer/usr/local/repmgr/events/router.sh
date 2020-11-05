#!/bin/bash
#
# 接收事件，并使用对应的脚本响应事件消息
# 
# repmgr 生成的消息：
#   cluster_created
#   primary_register primary_unregister
#   standby_clone standby_register standby_register_sync standby_unregister 
#   standby_promote standby_follow standby_switchover
#   witness_register witness_unregister 
#   node_rejoin 
#   cluster_cleanup
# 
# repmgrd 生成的消息
#   repmgrd_start repmgrd_shutdown repmgrd_reload
#   repmgrd_failover_promote repmgrd_failover_follow repmgrd_failover_aborted
#   repmgrd_standby_reconnect repmgrd_promote_error
#   repmgrd_local_disconnect repmgrd_local_reconnect
#   repmgrd_upstream_disconnect repmgrd_upstream_reconnect
#   standby_disconnect_manual standby_failure standby_recovery
#   child_node_disconnect child_node_reconnect child_node_new_connect child_nodes_disconnect_command

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
