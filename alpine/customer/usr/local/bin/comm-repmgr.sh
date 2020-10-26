#!/bin/bash
# Ver: 1.0 by Endial Fang (endial@126.com)
# 
# 应用通用业务处理函数

# 加载依赖脚本
. /usr/local/scripts/libcommon.sh       # 通用函数库

. /usr/local/scripts/libfile.sh
. /usr/local/scripts/libfs.sh
. /usr/local/scripts/libos.sh
. /usr/local/scripts/libservice.sh
. /usr/local/scripts/libvalidations.sh

# 函数列表

# 生成当前节点的 ROLE 信息环境变量
# 返回值：
#   可以被 'eval' 使用的序列化输出
repmgr_role_env() {
    local role="standby"
    local primary_node
    local primary_host
    local primary_port

    readarray -t primary_node < <(repmgr_get_primary_node)
    primary_host=${primary_node[0]}
    primary_port=${primary_node[1]:-${REPMGR_PRIMARY_PORT}}

    if [[ -z "$primary_host" ]]; then
        LOG_I "There are no nodes with primary role. Assuming the primary role..."
        role="primary"
    fi

    cat << EOF
export REPMGR_ROLE="$role"
export REPMGR_CURRENT_PRIMARY_HOST="$primary_host"
export REPMGR_CURRENT_PRIMARY_PORT="$primary_port"
EOF
}

# 获取当前节点的 ID 信息
repmgr_get_node_id() {
    local num
    if [[ "${REPMGR_NODE_ID}" != "" ]]; then
        echo "${REPMGR_NODE_ID}"
    else
        num="${REPMGR_NODE_NAME##*-}"
        if [[ "$num" != "" ]]; then
            num=$((num+1000))
            echo "$num"
        fi
    fi
}

# 获取当前 Primary 节点信息
# 返回值：
#   字符串[] - (host port)
repmgr_get_primary_node() {
    local upstream_node
    local upstream_host
    local upstream_port
    local primary_host=""
    local primary_port="${REPMGR_PRIMARY_PORT}"

    readarray -t upstream_node < <(repmgr_get_upstream_node)
    upstream_host=${upstream_node[0]}
    upstream_port=${upstream_node[1]:-${REPMGR_PRIMARY_PORT}}
    [[ -n "$upstream_host" ]] && LOG_I "Auto-detected primary node: '${upstream_host}:${upstream_port}'"

    if [[ -f "${REPMGR_PRIMARY_ROLE_LOCK_FILE}" ]]; then
        LOG_I "This node was acting as a primary before restart!"

        if [[ -z "$upstream_host" ]] || [[ "${upstream_host}:${upstream_port}" = "${REPMGR_NODE_NETWORK_NAME}:${REPMGR_NODE_PORT_NUMBER}" ]]; then
            LOG_I "Can not find new primary. Starting PostgreSQL as primary..."
        else
            LOG_I "Current primary is '${upstream_host}:${upstream_port}'. Cloning/rewinding it and acting as a standby node..."
            rm -f "${REPMGR_PRIMARY_ROLE_LOCK_FILE}"
            export REPMGR_SWITCH_ROLE="yes"
            primary_host="$upstream_host"
            primary_port="$upstream_port"
        fi
    else
        if [[ -z "$upstream_host" ]]; then
            if [[ "${REPMGR_PRIMARY_HOST}:${REPMGR_PRIMARY_PORT}" != "${REPMGR_NODE_NETWORK_NAME}:${REPMGR_NODE_PORT_NUMBER}" ]]; then
              primary_host="${REPMGR_PRIMARY_HOST}"
              primary_port="${REPMGR_PRIMARY_PORT}"
            fi
        else
            primary_host="$upstream_host"
            primary_port="$upstream_port"
        fi
    fi

    [[ -n "$primary_host" ]] && LOG_D "Primary node: '${primary_host}:${primary_port}'"
    echo "$primary_host"
    echo "$primary_port"
}

parse_uri() {
    local uri="${1:?uri is missing}"
    local component="${2:?component is missing}"

    # Solution based on https://tools.ietf.org/html/rfc3986#appendix-B with
    # additional sub-expressions to split authority into userinfo, host and port
    # Credits to Patryk Obara (see https://stackoverflow.com/a/45977232/6694969)
    local -r URI_REGEX='^(([^:/?#]+):)?(//((([^@/?#]+)@)?([^:/?#]+)(:([0-9]+))?))?(/([^?#]*))?(\?([^#]*))?(#(.*))?'
    #                    ||            |  |||            |         | |            | |         |  |        | |
    #                    |2 scheme     |  ||6 userinfo   7 host    | 9 port       | 11 rpath  |  13 query | 15 fragment
    #                    1 scheme:     |  |5 userinfo@             8 :...         10 path     12 ?...     14 #...
    #                                  |  4 authority
    #                                  3 //...
    local index=0
    case "$component" in
        scheme)
            index=2
            ;;
        authority)
            index=4
            ;;
        userinfo)
            index=6
            ;;
        host)
            index=7
            ;;
        port)
            index=9
            ;;
        path)
            index=10
            ;;
        query)
            index=13
            ;;
        fragment)
            index=14
            ;;
        *)
            LOG_E "unrecognized component $component"
            return 1
            ;;
    esac
    [[ "$uri" =~ $URI_REGEX ]] && echo "${BASH_REMATCH[${index}]}"
}

# 从其他 Partner 节点中查询当前 Primary 节点信息
# 返回值：
#   字符串[] - (host port)
repmgr_get_upstream_node() {
    local primary_conninfo
    local pretending_primary_host=""
    local pretending_primary_port=""
    local host=""
    local port=""
    local suggested_primary_host=""
    local suggested_primary_port=""

    if [[ -n "${REPMGR_PARTNER_NODES}" ]]; then
        LOG_I "Querying all partner nodes for common upstream node..."
        read -r -a nodes <<< "$(tr ',;' ' ' <<< "${REPMGR_PARTNER_NODES}")"
        for node in "${nodes[@]}"; do
            # intentionally accept inncorect address (without [schema:]// )
            [[ "$node" =~ ^(([^:/?#]+):)?// ]] || node="tcp://${node}"
            host="$(parse_uri "$node" 'host')"
            port="$(parse_uri "$node" 'port')"
            port="${port:-${REPMGR_PRIMARY_PORT}}"
            LOG_D "Checking node '$host:$port'..."
            local query="SELECT conninfo FROM repmgr.show_nodes WHERE (upstream_node_name IS NULL OR upstream_node_name = '') AND active=true"
            if ! primary_conninfo="$(echo "$query" | NO_ERRORS=true postgresql_execute "${REPMGR_DATABASE}" "${REPMGR_USERNAME}" "${REPMGR_PASSWORD}" "$host" "$port" "-tA")"; then
                LOG_D "Skipping: failed to get primary from the node '$host:$port'!"
                continue
            elif [[ -z "$primary_conninfo" ]]; then
                LOG_D "Skipping: failed to get information about primary nodes!"
                continue
            elif [[ "$(echo "$primary_conninfo" | wc -l)" -eq 1 ]]; then
                suggested_primary_host="$(echo "$primary_conninfo" | awk -F 'host=' '{print $2}' | awk '{print $1}')"
                suggested_primary_port="$(echo "$primary_conninfo" | awk -F 'port=' '{print $2}' | awk '{print $1}')"
                LOG_D "Pretending primary role node - '${suggested_primary_host}:${suggested_primary_port}'"
                if [[ -n "$pretending_primary_host" ]]; then
                    if [[ "${pretending_primary_host}:${pretending_primary_port}" != "${suggested_primary_host}:${suggested_primary_port}" ]]; then
                        LOG_W "Conflict of pretending primary role nodes (previously: '${pretending_primary_host}:${pretending_primary_port}', now: '${suggested_primary_host}:${suggested_primary_port}')"
                        pretending_primary_host="" && pretending_primary_port="" && break
                    fi
                else
                    LOG_D "Pretending primary set to '${suggested_primary_host}:${suggested_primary_port}'!"
                    pretending_primary_host="$suggested_primary_host"
                    pretending_primary_port="$suggested_primary_port"
                fi
            else
                LOG_W "There were more than one primary when getting primary from node '$host:$port'"
                pretending_primary_host="" && pretending_primary_port="" && break
            fi
        done
    fi

    echo "$pretending_primary_host"
    echo "$pretending_primary_port"
}

# 生成应用配置文件
repmgr_generate_repmgr_config() {
    LOG_I "Generate repmgr configuration..."

    cat << EOF > "${REPMGR_CONF_FILE}"
event_notification_command='${REPMGR_EVENTS_DIR}/router.sh %n %e %s "%t" "%d"'
ssh_options='-o "StrictHostKeyChecking no" -v'
use_replication_slots='${REPMGR_USE_REPLICATION_SLOTS}'
pg_bindir='${APP_HOME_DIR}/bin'

node_id=$(repmgr_get_node_id)
node_name='${REPMGR_NODE_NAME}'
data_directory='${PG_DATA_DIR}'
conninfo='user=${REPMGR_USERNAME} password=${REPMGR_PASSWORD} host=${REPMGR_NODE_NETWORK_NAME} port=${REPMGR_NODE_PORT_NUMBER} dbname=${REPMGR_DATABASE} connect_timeout=${REPMGR_CONNECT_TIMEOUT}'
failover='automatic'
reconnect_attempts='${REPMGR_RECONNECT_ATTEMPTS}'
reconnect_interval='${REPMGR_RECONNECT_INTERVAL}'
log_level='${REPMGR_LOG_LEVEL}'
log_file='${REPMGR_LOG_DIR}/repmgr.log'
priority='${REPMGR_NODE_PRIORITY}'
degraded_monitoring_timeout='${REPMGR_DEGRADED_MONITORING_TIMEOUT}'
async_query_timeout='${REPMGR_ASYNC_QUERY_TIMEOUT}'
monitor_interval_secs='${REPMGR_MONITOR_INTERVAL_SECS}'
connection_check_type='${REPMGR_CONNECTION_CHECK_TYPE}'
promote_command ='PGPASSWORD=${REPMGR_PASSWORD} repmgr standby promote -f ${REPMGR_CONF_FILE} --log-to-file --verbose'
follow_command  ='PGPASSWORD=${REPMGR_PASSWORD} repmgr standby follow -f ${REPMGR_CONF_FILE} --log-to-file --verbose --upstream-node-id=%n'
service_start_command   ='pg_ctl start -w -D ${PG_DATA_DIR} -l ${PG_LOG_FILE} -o "--config-file=${PG_CONF_FILE} --external_pid_file=${PG_EXT_PID_FILE} --hba_file=${PG_HBA_FILE}"'
service_stop_command    ='pg_ctl stop -w -D ${PG_DATA_DIR} -m fast'
service_restart_command ='pg_ctl restart -w -D ${PG_DATA_DIR} -m fast -o "--config-file=${PG_CONF_FILE} --external_pid_file=${PG_EXT_PID_FILE} --hba_file=${PG_HBA_FILE}"'
service_reload_command  ='pg_ctl reload -w -D ${PG_DATA_DIR}'
EOF
}

# 更新默认配置文件
#   必须在配置文件中包含 shared_preload_libraries 以启动 repmgr
repmgr_update_postgresql_conf() {
    LOG_I "Update postgresql.conf for regmgr"
    postgresql_conf_set "shared_preload_libraries" "repmgr"
    postgresql_conf_set "max_replication_slots" "10"
    postgresql_conf_set "max_wal_senders" "16"
    postgresql_conf_set "hot_standby" "on"
    postgresql_conf_set "archive_mode" "on"
    postgresql_conf_set "archive_command" "/bin/true"
    postgresql_conf_set "wal_log_hints" "on"
    postgresql_conf_set "wal_level" "hot_standby"
    postgresql_conf_set "logging_collector" "on"
    postgresql_conf_set "log_directory" "${APP_LOG_DIR}"
    postgresql_conf_set "log_filename" "postgresql.log"
}

# 更新默认权限配置文件
repmgr_update_hba_conf() {
    LOG_I "Update pg_hba.conf for regmgr"
    local repmgr_auth="trust"
    if [[ -n "${REPMGR_PASSWORD}" ]]; then
        repmgr_auth="md5"
    fi

    local previous_content
    previous_content=$(cat "${PG_HBA_FILE}")

    cat >"${PG_HBA_FILE}" << EOF
host        all                 $REPMGR_USERNAME    0.0.0.0/0       $repmgr_auth
host        all                 $REPMGR_USERNAME    ::/0            $repmgr_auth
host        $REPMGR_DATABASE    $REPMGR_USERNAME    0.0.0.0/0       $repmgr_auth
host        $REPMGR_DATABASE    $REPMGR_USERNAME    ::/0            $repmgr_auth
host        replication         $REPMGR_USERNAME    0.0.0.0/0       $repmgr_auth
host        replication         $REPMGR_USERNAME    ::/0            $repmgr_auth
$previous_content
EOF
}

# 生成默认配置文件
repmgr_update_postgresql_configuration() {
    LOG_I "Update PostgreSQL configuration..."

    repmgr_update_postgresql_conf
    repmgr_update_hba_conf
}

# 检测并等待 Primary 节点就绪
repmgr_wait_primary_node() {
    local return_value=1
    local -i timeout=60
    local -i step=10
    local -i max_tries=$(( timeout / step ))
    local schemata
    LOG_I "Waiting for primary node..."
    LOG_I "Wait for schema ${REPMGR_DATABASE}.repmgr on '${REPMGR_CURRENT_PRIMARY_HOST}:${REPMGR_CURRENT_PRIMARY_PORT}', will try $max_tries times with $step delay seconds (TIMEOUT=$timeout)"
    for ((i = 0 ; i <= timeout ; i+=step )); do
        local query="SELECT 1 FROM information_schema.schemata WHERE catalog_name='${REPMGR_DATABASE}' AND schema_name='repmgr'"
        if ! schemata="$(echo "$query" | NO_ERRORS=true postgresql_execute "${REPMGR_DATABASE}" "${REPMGR_USERNAME}" "${REPMGR_PASSWORD}" "${REPMGR_CURRENT_PRIMARY_HOST}" "${REPMGR_CURRENT_PRIMARY_PORT}" "-tA")"; then
            LOG_D "Host '${REPMGR_CURRENT_PRIMARY_HOST}:${REPMGR_CURRENT_PRIMARY_PORT}' is not accessible ($i)"
        else
            if [[ $schemata -ne 1 ]]; then
                LOG_D "Schema ${REPMGR_DATABASE}.repmgr is still not accessible ($i)"
            else
                LOG_D "Schema ${REPMGR_DATABASE}.repmgr exists!"
                return_value=0 && break
            fi
        fi
        sleep "$step"
    done
    return $return_value
}

# 从主节点同步数据
repmgr_clone_primary() {
    LOG_I "Cloning data from primary node..."
    local -r flags=("-f" "${REPMGR_CONF_FILE}" "-h" "${REPMGR_CURRENT_PRIMARY_HOST}" "-p" "${REPMGR_CURRENT_PRIMARY_PORT}" "-U" "${REPMGR_USERNAME}" "-d" "${REPMGR_DATABASE}" "-D" "${PG_DATA_DIR}" "standby" "clone" "--fast-checkpoint" "--force")

    PGPASSWORD="${REPMGR_PASSWORD}" debug_execute "repmgr" "${flags[@]}"
}

# 将当前节点重新加入集群并同步数据
repmgr_rewind() {
    LOG_I "Rejoining node..."

    LOG_D "Deleting old data..."
    postgresql_clean_data

    LOG_D "Cloning data from primary node..."
    repmgr_clone_primary
}

# 为 primary-slave 复制模式创建用户
repmgr_create_repmgr_user() {
    local pg_password="${PG_PASSWORD}"
    local -r escaped_password="${REPMGR_PASSWORD//\'/\'\'}"
    LOG_I "Creating repmgr user: ${REPMGR_USERNAME}"

    [[ "${PG_USERNAME}" != "postgres" ]] && [[ -n "${PG_POSTGRES_PASSWORD}" ]] && pg_password="${PG_POSTGRES_PASSWORD}"
    echo "CREATE ROLE \"${REPMGR_USERNAME}\" WITH LOGIN CREATEDB PASSWORD '${escaped_password}';" | postgresql_execute "" "postgres" "$pg_password"
    echo "ALTER USER ${REPMGR_USERNAME} WITH SUPERUSER;" | postgresql_execute "" "postgres" "$pg_password"
    # set the repmgr user's search path to include the 'repmgr' schema name (ref: https://repmgr.org/docs/4.3/quickstart-repmgr-user-database.html)
    echo "ALTER USER ${REPMGR_USERNAME} SET search_path TO repmgr, \"\$user\", public;" | postgresql_execute "" "postgres" "$pg_password"
}

# 创建用户自定义数据库 $PG_DATABASE
repmgr_create_repmgr_db() {
    local pg_password="${PG_PASSWORD}"
    LOG_I "Creating repmgr database: ${REPMGR_DATABASE}"

    [[ "${PG_USERNAME}" != "postgres" ]] && [[ -n "${PG_POSTGRES_PASSWORD}" ]] && pg_password="${PG_POSTGRES_PASSWORD}"
    echo "CREATE DATABASE ${REPMGR_DATABASE};" | postgresql_execute "" "postgres" "$pg_password"
}

# 检测用户参数信息是否满足条件; 针对部分权限过于开放情况，打印提示信息
repmgr_verify_minimum_env() {
    LOG_I "Validating settings in REPMGR_* env vars..."
    local error_code=0

    # Auxiliary functions
    print_validation_error() {
        LOG_E "$1"
        error_code=1
    }

    if [[ -z "${REPMGR_PARTNER_NODES}" ]]; then
        print_validation_error "The list of partner nodes cannot be empty. Set the environment variable REPMGR_PARTNER_NODES with a comma separated list of partner nodes."
    fi
    if [[ -z "${REPMGR_PRIMARY_HOST}" ]]; then
        print_validation_error "The initial primary host is required. Set the environment variable REPMGR_PRIMARY_HOST with the initial primary host."
    fi
    if [[ -z "${REPMGR_NODE_NAME}" ]]; then
        print_validation_error "The node name is required. Set the environment variable REPMGR_NODE_NAME with the node name."
    elif [[ ! "${REPMGR_NODE_NAME}" =~ ^.*+-[0-9]+$ ]]; then
        print_validation_error "The node name does not follow the required format. Valid format: ^.*+-[0-9]+$"
    fi
    if [[ -z "$(repmgr_get_node_id)" ]]; then
        print_validation_error "The node id is required. Set the environment variable REPMGR_NODE_ID with the node id."
    fi
    if [[ -z "${REPMGR_NODE_NETWORK_NAME}" ]]; then
        print_validation_error "The node network name is required. Set the environment variable REPMGR_NODE_NETWORK_NAME with the node network name."
    fi
    # Credentials validations
    if [[ -z "${REPMGR_USERNAME}" ]] || [[ -z "${REPMGR_PASSWORD}" ]]; then
        print_validation_error "The repmgr credentials are mandatory. Set the environment variables REPMGR_USERNAME and REPMGR_PASSWORD with the repmgr credentials."
    fi

    if ! is_yes_no_value "${REPMGR_UPGRADE_EXTENSION}"; then
        print_validation_error "The allowed values for REPMGR_UPGRADE_EXTENSION are: yes or no."
    fi

    [[ "$error_code" -eq 0 ]] || exit "$error_code"
}

# 在集群中将当前节点注册为 primary 节点
repmgr_register_primary() {
    LOG_I "Registering Primary..."
    local -r flags=("primary" "register" "-f" "${REPMGR_CONF_FILE}" "--force")

    debug_execute "repmgr" "${flags[@]}"
}

# 在集群中取消当前节点的 standby 注册信息
repmgr_unregister_standby() {
    LOG_I "Unregistering standby node..."

    local -r flags=("standby" "unregister" "-f" "${REPMGR_CONF_FILE}" "--node-id=$(repmgr_get_node_id)")

    # 如果节点不存在，命令执行会失败；为了保证脚本正常执行，需要特殊处理
    debug_execute "repmgr" "${flags[@]}" || true
}

# 在集群中将当前节点注册为 standby 节点
repmgr_register_standby() {
    LOG_I "Registering Standby node..."
    local -r flags=("standby" "register" "-f" "${REPMGR_CONF_FILE}" "--force" "--verbose")

    debug_execute "repmgr" "${flags[@]}"
}

# 更新数据库中 repmgr 扩展信息
repmgr_upgrade_extension() {
    LOG_I "Upgrading repmgr extension..."

    echo "ALTER EXTENSION repmgr UPDATE" | postgresql_execute "${REPMGR_DATABASE}" "${REPMGR_USERNAME}" "${REPMGR_PASSWORD}"
}

# 应用默认初始化操作
# 执行完毕后，生成文件 ${APP_CONF_DIR}/.app_init_flag 及 ${APP_DATA_DIR}/.data_init_flag 文件
repmgr_default_init() {
    LOG_D "Node ID: '$(repmgr_get_node_id)', Rol: '${REPMGR_ROLE}', Primary Node: '${REPMGR_CURRENT_PRIMARY_HOST}:${REPMGR_CURRENT_PRIMARY_PORT}'"
    LOG_I "Check default init status of ${REPMGR_NAME}..."

    if is_boolean_yes "${REPMGR_SWITCH_ROLE}"; then
        postgresql_reset
    fi

    export PG_REPLICATION_MODE="${REPMGR_ROLE}"

    if [[ ! -f "${APP_CONF_DIR}/.app_init_flag" ]]; then
        LOG_I "Deploying postgresql with new configuration"
        postgresql_default_postgresql_config
        postgresql_default_hba_config
        postgresql_hba_allow_local_connection

        if [[ "${PG_REPLICATION_MODE}" = "primary" ]]; then
            [[ -n "${PG_REPLICATION_USER}" ]] && postgresql_hba_allow_replication_connection
        else
            postgresql_configure_recovery
        fi

        if is_boolean_yes "${PG_ENABLE_TLS}" ; then
            postgresql_configure_tls
            [[ -n "${PG_TLS_CA_FILE}" ]] && postgresql_hba_allow_tls_connection
        fi
        
        postgresql_configure_logging
        postgresql_configure_connections

        touch "${APP_CONF_DIR}/.app_init_flag"
        echo "$(date '+%Y-%m-%d %H:%M:%S') : Init success." >> "${APP_CONF_DIR}/.app_init_flag"
    else
        LOG_I "Deploying postgresql with persisted configuration"
    fi

    if [[ ! -f "${REPMGR_CONF_DIR}/.app_init_flag" ]]; then
        LOG_I "Deploying repmgr with new configuration"
        # 生成 repmgr 默认配置文件
        repmgr_generate_repmgr_config
        # 更新数据库默认配置文件
        repmgr_update_postgresql_configuration

        touch "${REPMGR_CONF_DIR}/.app_init_flag"
        echo "$(date '+%Y-%m-%d %H:%M:%S') : Init success." >> "${REPMGR_CONF_DIR}/.app_init_flag"
    else
        LOG_I "Deploying repmgr with persisted configuration"
    fi


    if [[ "${REPMGR_ROLE}" = "standby" ]]; then
        LOG_I "Run as standby, check and clone data from primary"
        repmgr_wait_primary_node || exit 1
        # 如果是 standby 模式，检测是否第一次启动；并从 primary 节点同步数据
        if is_boolean_yes "${REPMGR_SWITCH_ROLE}"; then
            repmgr_rewind
        else
            repmgr_clone_primary
        fi
        touch ${APP_DATA_DIR}/.data_init_flag
        echo "$(date '+%Y-%m-%d %H:%M:%S') : Init success." >> ${APP_DATA_DIR}/.data_init_flag
    fi

    postgresql_default_init
    postgresql_enable_remote_connections
    postgresql_conf_set "port" "${PG_PORT_NUMBER}"

    if [[ "${REPMGR_ROLE}" = "primary" ]]; then
        LOG_D "Run as primary, verify repmgr user and database"

        if is_boolean_yes "${PG_FIRST_BOOT}"; then
            postgresql_start_server_bg
            repmgr_create_repmgr_user
            repmgr_create_repmgr_db
            postgresql_stop_server

            # Restart PostgreSQL
            postgresql_start_server_bg
            repmgr_register_primary
            repmgr_custom_init
        elif is_boolean_yes "${REPMGR_UPGRADE_EXTENSION}"; then
            # Upgrade repmgr extension
            postgresql_start_server_bg
            repmgr_upgrade_extension
        else
            LOG_D "Skipping repmgr configuration..."
        fi
    else
        export PG_PRIMARY_PORT="${REPMGR_CURRENT_PRIMARY_PORT}"
        export PG_PRIMARY_HOST="${REPMGR_CURRENT_PRIMARY_HOST}"

        postgresql_configure_recovery
        postgresql_start_server_bg
        repmgr_unregister_standby
        repmgr_register_standby
    fi
}

# 用户自定义的前置初始化操作，依次执行目录 preinitdb.d 中的初始化脚本
# 执行完毕后，生成文件 ${REPMGR_DATA_DIR}/.custom_preinit_flag
repmgr_custom_preinit() {
    LOG_I "Check custom pre-init status of ${REPMGR_NAME}..."

    # 检测用户配置文件目录是否存在 preinitdb.d 文件夹，如果存在，尝试执行目录中的初始化脚本
    if [ -d "/srv/conf/${REPMGR_NAME}/preinitdb.d" ]; then
        # 检测数据存储目录是否存在已初始化标志文件；如果不存在，检索可执行脚本文件并进行初始化操作
        if [[ -n $(find "/srv/conf/${REPMGR_NAME}/preinitdb.d/" -type f -regex ".*\.\(sh\)") ]] && \
            [[ ! -f "${REPMGR_NAME}/.custom_preinit_flag" ]]; then
            LOG_I "Process custom pre-init scripts from /srv/conf/${REPMGR_NAME}/preinitdb.d..."

            # 检索所有可执行脚本，排序后执行
            find "/srv/conf/${REPMGR_NAME}/preinitdb.d/" -type f -regex ".*\.\(sh\)" | sort | process_init_files

            touch "${REPMGR_DATA_DIR}/.custom_preinit_flag"
            echo "$(date '+%Y-%m-%d %H:%M:%S') : Init success." >> "${REPMGR_DATA_DIR}/.custom_preinit_flag"
            LOG_I "Custom preinit for ${REPMGR_NAME} complete."
        else
            LOG_I "Custom preinit for ${REPMGR_NAME} already done before, skipping initialization."
        fi
    fi

    postgresql_custom_preinit

    # 检测依赖的服务是否就绪
    #for i in ${SERVICE_PRECONDITION[@]}; do
    #    app_wait_service "${i}"
    #done
}

# 用户自定义的应用初始化操作，依次执行目录initdb.d中的初始化脚本
# 执行完毕后，生成文件 ${REPMGR_DATA_DIR}/.custom_init_flag
repmgr_custom_init() {
    LOG_I "Check custom initdb status of ${REPMGR_NAME}..."

    # 检测用户配置文件目录是否存在 initdb.d 文件夹，如果存在，尝试执行目录中的初始化脚本
    if [ -d "/srv/conf/${REPMGR_NAME}/initdb.d" ]; then
    	# 检测数据存储目录是否存在已初始化标志文件；如果不存在，检索可执行脚本文件并进行初始化操作
    	if [[ -n $(find "/srv/conf/${REPMGR_NAME}/initdb.d/" -type f -regex ".*\.\(sh\|sql\|sql.gz\)") ]] && \
            [[ ! -f "${REPMGR_DATA_DIR}/.custom_init_flag" ]]; then
            LOG_I "Process custom init scripts from /srv/conf/${REPMGR_NAME}/initdb.d..."

            postgresql_start_server_bg

            # 检索所有可执行脚本，排序后执行
    		find "/srv/conf/${APP_NAME}/initdb.d/" -type f -regex ".*\.\(sh\|sql\|sql.gz\)" | sort | while read -r f; do
                case "$f" in
                    *.sh)
                        if [[ -x "$f" ]]; then
                            LOG_D "Executing $f"; "$f"
                        else
                            LOG_D "Sourcing $f"; . "$f"
                        fi
                        ;;
                    *.sql)    
                        LOG_D "Executing $f"; 
                        postgresql_execute "${PG_DATABASE}" "${PG_INITSCRIPTS_USERNAME}" "${PG_INITSCRIPTS_PASSWORD}" < "$f"
                        ;;
                    *.sql.gz) 
                        LOG_D "Executing $f"; 
                        gunzip -c "$f" | postgresql_execute "${PG_DATABASE}" "${PG_INITSCRIPTS_USERNAME}" "${PG_INITSCRIPTS_PASSWORD}"
                        ;;
                    *)        
                        LOG_D "Ignoring $f" ;;
                esac
            done

            touch "${REPMGR_DATA_DIR}/.custom_init_flag"
    		echo "$(date '+%Y-%m-%d %H:%M:%S') : Init success." >> "${REPMGR_DATA_DIR}/.custom_init_flag"
    		LOG_I "Custom init for ${REPMGR_NAME} complete."
    	else
    		LOG_I "Custom init for ${REPMGR_NAME} already done before, skipping initialization."
    	fi
    fi

    postgresql_custom_init
}

