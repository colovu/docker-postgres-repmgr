#!/bin/bash

# 设置 shell 执行参数，可使用'-'(打开）'+'（关闭）控制。常用：
# 	-e: 命令执行错误则报错; -u: 变量未定义则报错; -x: 打印实际待执行的命令行; -o pipefail: 设置管道中命令遇到失败则报错
set -eu
set -o pipefail

readonly query="SELECT upstream_node_id FROM repmgr.nodes WHERE node_id=$(repmgr_get_node_id)"
readonly new_upstream_node_id="$(echo "$query" | ENV_DEBUG=true postgresql_execute "${REPMGR_DATABASE}" "${PG_REPLICATION_USER}" "${PG_REPLICATION_PASSWORD}" "" "" "-tA")"
if [[ -n "$new_upstream_node_id" ]]; then
    LOG_D "$header Locking standby (node_id=$new_upstream_node_id)..."
    echo "$new_upstream_node_id" > "${REPMGR_STANDBY_ROLE_LOCK_FILE}"
fi
