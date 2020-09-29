#!/bin/bash
# Ver: 1.0 by Endial Fang (endial@126.com)
# 
# 应用环境及依赖文件设置脚本

# 设置 shell 执行参数，可使用'-'(打开）'+'（关闭）控制。常用：
# 	-e: 命令执行错误则报错; -u: 变量未定义则报错; -x: 打印实际待执行的命令行; -o pipefail: 设置管道中命令遇到失败则报错
set -eu
set -o pipefail

. /usr/local/bin/comm-postgresql.sh		# 应用专用函数库
. /usr/local/bin/comm-repmgr.sh			# 应用专用函数库

. /usr/local/bin/comm-env.sh 			# 设置环境变量

LOG_I "** Processing setup.sh **"

APP_DIRS="${APP_CONF_DIR:-} ${APP_DATA_DIR:-} ${APP_LOG_DIR:-} ${APP_CERT_DIR:-} ${APP_DATA_LOG_DIR:-}"
APP_DIRS="${APP_DIRS} ${PG_DATA_DIR:-} ${PG_INITDB_WAL_DIR:-}"
APP_DIRS="${APP_DIRS} ${REPMGR_CONF_DIR:-} ${REPMGR_DATA_DIR:-} ${REPMGR_EVENTS_DIR:-} ${REPMGR_RUN_DIR:-} ${REPMGR_LOG_DIR:-}"

LOG_I "Ensure directory exists: ${APP_DIRS}"
for dir in ${APP_DIRS}; do
	ensure_dir_exists ${dir}
done

repmgr_verify_minimum_env
postgresql_verify_minimum_env

# 检测指定文件是否在配置文件存储目录存在，如果不存在则拷贝（新挂载数据卷、手动删除都会导致不存在）
# PG 将使用默认模板生成配置文件，并放置在PGDATA目录
#LOG_I "Check config files in: ${APP_CONF_DIR}"
#if [[ ! -z "$(ls -A "${APP_DEF_DIR}")" ]]; then
#	ensure_config_file_exist "${APP_DEF_DIR}" $(ls -A "${APP_DEF_DIR}")
#	:
#fi

LOG_I "Ensure directory ownership: ${APP_USER}"
for dir in ${APP_DIRS}; do
	configure_permissions_ownership "$dir" -u "${APP_USER}" -g "${APP_USER}"
done

# 解决 PostgreSQL 目录权限过于开放，无法初始化问题：FATAL:  data directory "/srv/data/postgresql" has group or world access
LOG_D "Lack of permissions on data directory: ${PG_DATA_DIR}"
chmod 0700 ${PG_DATA_DIR}

# 解决使用gosu后，nginx: [emerg] open() "/dev/stdout" failed (13: Permission denied)
LOG_D "Change permissions of stdout/stderr to 0622"
chmod 0622 /dev/stdout /dev/stderr

LOG_I "** Processing setup.sh finished! **"
