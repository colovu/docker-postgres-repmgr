#!/bin/bash
# Ver: 1.0 by Endial Fang (endial@126.com)
# 
# 应用启动脚本

# 设置 shell 执行参数，可使用'-'(打开）'+'（关闭）控制。常用：
# 	-e: 命令执行错误则报错; -u: 变量未定义则报错; -x: 打印实际待执行的命令行; -o pipefail: 设置管道中命令遇到失败则报错
set -eu
set -o pipefail

. /usr/local/bin/comm-postgresql.sh		# 应用专用函数库
. /usr/local/bin/comm-repmgr.sh			# 应用专用函数库

. /usr/local/bin/comm-env.sh 			# 设置环境变量

LOG_I "** Processing run.sh **"

flags=("--pid-file=${REPMGR_PID_FILE}" "-f" "${REPMGR_CONF_FILE}" "--daemonize=false")
[[ -z "${APP_EXTRA_FLAGS:-}" ]] || flags=("${flags[@]}" "${APP_EXTRA_FLAGS[@]}")
START_COMMAND=("repmgrd")

postgresql_start_server_bg

LOG_I "** Starting ${REPMGR_NAME} **"
if is_root; then
    exec gosu "${APP_USER}" tini -s -- "${START_COMMAND[@]}" "${flags[@]}"
else
    exec tini -s -- "${START_COMMAND[@]}" "${flags[@]}"
fi

