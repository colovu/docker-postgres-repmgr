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

# 配置 libnss_wrapper 以使得 PostgreSQL 命令可以以任意用户身份执行
postgresql_enable_nss_wrapper() {
    if ! getent passwd "$(id -u)" &> /dev/null && [ -e /usr/lib/libnss_wrapper.so ]; then
        LOG_D "Configuring libnss_wrapper..."
        export LD_PRELOAD='/usr/lib/libnss_wrapper.so'
        export NSS_WRAPPER_PASSWD="$(mktemp)"
        export NSS_WRAPPER_GROUP="$(mktemp)"
        echo "postgres:x:$(id -u):$(id -g):PostgreSQL:${PG_DATA_DIR}:/bin/false" > "${NSS_WRAPPER_PASSWD}"
        echo "postgres:x:$(id -g):" > "${NSS_WRAPPER_GROUP}"
    fi
}

# 禁用 libnss_wrapper
postgresql_disable_nss_wrapper() {
    # unset/cleanup "nss_wrapper" bits
    if [ "${LD_PRELOAD:-}" = '/usr/lib/libnss_wrapper.so' ]; then
        rm -f "${NSS_WRAPPER_PASSWD}" "${NSS_WRAPPER_GROUP}"
        unset LD_PRELOAD NSS_WRAPPER_PASSWD NSS_WRAPPER_GROUP
    fi
}

# 将变量配置更新至配置文件
# 参数:
#   $1 - 文件
#   $2 - 变量
#   $3 - 值（列表）
postgresql_common_conf_set() {
    local file="${1:?missing file}"
    local key="${2:?missing key}"
    local value="${3:?missing value}"

    if grep -q "^#*\s*${key}" "$file" >/dev/null; then
        replace_in_file "$file" "^#*\s*${key}\s*=.*" "${key} = '${value}'" false
    else
        echo "${property} = '${value}'" >>"$file"
    fi
}

# 更新 postgresql.conf 配置文件中指定变量值
# 变量:
#   $1 - 变量
#   $2 - 值（列表）
postgresql_conf_set() {
    postgresql_common_conf_set "${PG_CONF_FILE}" "$@"
}

# 更新 pg_hba.conf 配置文件中指定变量值
# 变量:
#   $1 - 变量
#   $2 - 值（列表）
postgresql_hba_set() {
    replace_in_file "${PG_HBA_FILE}" "${1}" "${2}" false
}

# 更新 pg_ident.conf 配置文件中指定变量值
# 变量:
#   $1 - 变量
#   $2 - 值（列表）
postgresql_ident_set() {
    postgresql_common_conf_set "${PG_IDENT_FILE}" "$@"
}

# 更新 recover.conf 配置文件中指定变量值
# 变量:
#   $1 - 变量
#   $2 - 值（列表）
postgresql_recover_set() {
    postgresql_common_conf_set "${PG_RECOVERY_FILE}" "$@"
}

# 初始化 pg_hba.conf 文件，增加 LDAP 配置；同时保留本地认证
postgresql_hba_ldap_auth() {
    LOG_I "Enabling LDAP authentication"
    local ldap_configuration=""

    if [[ -n "${PG_LDAP_URL}" ]]; then
        ldap_configuration="ldapurl=\"${PG_LDAP_URL}\""
    else
        ldap_configuration="ldapserver=${PG_LDAP_SERVER}"

        [[ -n "${PG_LDAP_PREFIX}" ]] && ldap_configuration+=" ldapprefix=\"${PG_LDAP_PREFIX}\""
        [[ -n "${PG_LDAP_SUFFIX}" ]] && ldap_configuration+=" ldapsuffix=\"${PG_LDAP_SUFFIX}\""
        [[ -n "${PG_LDAP_PORT}" ]] && ldap_configuration+=" ldapport=${PG_LDAP_PORT}"
        [[ -n "${PG_LDAP_BASE_DN}" ]] && ldap_configuration+=" ldapbasedn=\"${PG_LDAP_BASE_DN}\""
        [[ -n "${PG_LDAP_BIND_DN}" ]] && ldap_configuration+=" ldapbinddn=\"${PG_LDAP_BIND_DN}\""
        [[ -n "${PG_LDAP_BIND_PASSWORD}" ]] && ldap_configuration+=" ldapbindpasswd=${PG_LDAP_BIND_PASSWORD}"
        [[ -n "${PG_LDAP_SEARCH_ATTR}" ]] && ldap_configuration+=" ldapsearchattribute=${PG_LDAP_SEARCH_ATTR}"
        [[ -n "${PG_LDAP_SEARCH_FILTER}" ]] && ldap_configuration+=" ldapsearchfilter=\"${PG_LDAP_SEARCH_FILTER}\""
        [[ -n "${PG_LDAP_TLS}" ]] && ldap_configuration+=" ldaptls=${PG_LDAP_TLS}"
        [[ -n "${PG_LDAP_SCHEME}" ]] && ldap_configuration+=" ldapscheme=${PG_LDAP_SCHEME}"
    fi

    cat <<EOF >"${PG_HBA_FILE}"
host        all             postgres        0.0.0.0/0               trust
host        all             postgres        ::/0                    trust
host        all             all             0.0.0.0/0               ldap ${ldap_configuration}
host        all             all             ::/0                    ldap ${ldap_configuration}
EOF
}

# 设置 pg_hba.conf 文件，增加 TLS 配置
postgresql_hba_allow_tls_connection() {
    LOG_I "Enabling TLS client authentication"

    cat <<EOF >>"${PG_HBA_FILE}"
hostssl     all             all             0.0.0.0/0               cert
hostssl     all             all             ::/0                    cert
EOF
}

# 设置 pg_hba.conf 文件，允许 replication 访问
postgresql_hba_allow_replication_connection() {
    LOG_I "Enabling replication client authentication"

    local replication_auth="trust"
    if [[ -n "${PG_REPLICATION_PASSWORD}" ]]; then
        replication_auth="md5"
    fi
    cat <<EOF >>"${PG_HBA_FILE}"
host        replication     all             0.0.0.0/0               ${replication_auth}
host        replication     all             ::/0                    ${replication_auth}
EOF
}

# 设置 pg_hba.conf，允许本地访问
postgresql_hba_allow_local_connection() {
    LOG_I "Enabling local client authentication"

    cat <<EOF >>"${PG_HBA_FILE}"
local       all             all                                     trust
host        all             all             127.0.0.1/0             trust
host        all             all             ::1/128                 trust
EOF
}

# 初始化 pg_hba.conf 文件
postgresql_hba_password_auth() {
    LOG_I "Enabling password client authentication"

    cat <<EOF >"${PG_HBA_FILE}"
host        all             all             0.0.0.0/0               trust
host        all             all             ::/0                    trust
EOF
}

# 使用运行中的 PostgreSQL 服务执行 SQL 操作
# 参数:
#   $1 - 需要操作的数据库名
#   $2 - 操作使用的用户名
#   $3 - 操作用户密码
#   $4 - 主机
#   $5 - 端口
#   $6 - 扩展参数 (如: -tA)
postgresql_execute() {
    local -r db="${1:-}"
    local -r user="${2:-postgres}"
    local -r pass="${3:-}"
    local -r host="${4:-localhost}"
    local -r port="${5:-${PG_PORT_NUMBER}}"
    local -r opts="${6:-}"

    local args=("-h" "$host" "-p" "$port" "-U" "$user")
    local cmd=("${APP_HOME_DIR}/bin/psql")
    [[ -n "$db" ]] && args+=("-d" "$db")
    [[ -n "$opts" ]] && args+=("$opts")
    LOG_D "Execute args: ${args[@]}"
    if is_boolean_yes "${ENV_DEBUG}"; then
        PGPASSWORD=$pass "${cmd[@]}" "${args[@]}"
    else
        PGPASSWORD=$pass "${cmd[@]}" "${args[@]}" >/dev/null 2>&1
    fi
}

# 使用环境变量中的配置值更新配置文件
postgresql_configure_from_environment_variables() {
    LOG_D "Modify postgresql.conf with PG_CFG_* values..."
    for var in "${!PG_CFG_@}"; do
        key="$(echo "$var" | sed -e 's/^PG_CFG_//g' | tr '[:upper:]' '[:lower:]')"
        value="${!var}"
        postgresql_conf_set "$key" "$value"
    done
}

# 生成初始 postgres.conf 配置
postgresql_default_postgresql_config() {
    LOG_I "Modify postgresql.conf with default values..."

    [ ! -e "${PG_CONF_FILE}" ] && cp -rf "${APP_HOME_DIR}/share/postgresql.conf.sample" "${PG_CONF_FILE}"

    postgresql_configure_from_environment_variables
    
    postgresql_conf_set "logging_collector" "on"
    postgresql_conf_set "wal_level" "hot_standby"
    postgresql_conf_set "max_wal_size" "400MB"
    postgresql_conf_set "max_wal_senders" "16"
    postgresql_conf_set "wal_keep_segments" "12"
    postgresql_conf_set "wal_log_hints" "on"
    postgresql_conf_set "hot_standby" "on"
    if (( PG_NUM_SYNCHRONOUS_REPLICAS > 0 )); then
        postgresql_conf_set "synchronous_commit" "${PG_SYNCHRONOUS_COMMIT_MODE}"
        postgresql_conf_set "synchronous_standby_names" "${PG_NUM_SYNCHRONOUS_REPLICAS} (\"${PG_CLUSTER_APP_NAME}\")"
    fi
    postgresql_conf_set "fsync" "${PG_FSYNC}"

    [[ -n "${PG_SHARED_PRELOAD_LIBRARIES}" ]] && postgresql_conf_set "shared_preload_libraries" "${PG_SHARED_PRELOAD_LIBRARIES}"

    # Update default value for 'include_dir' directive
    # ref: https://github.com/postgres/postgres/commit/fb9c475597c245562a28d1e916b575ac4ec5c19f#diff-f5544d9b6d218cc9677524b454b41c60
    if ! grep include_dir "${PG_CONF_FILE}" > /dev/null; then
        postgresql_error "include_dir line is not present in ${PG_CONF_FILE}. This may be due to a changes in a new version of PostgreSQL. Please check"
        exit 1
    fi
    postgresql_conf_set "include_dir" "conf.d"
    mkdir -p "${APP_CONF_DIR}/conf.d"
}

# 生成初始 pg_hba.conf 配置
postgresql_default_hba_config() {
    LOG_I "Modify pg_hba.conf with default values..."

    if is_boolean_yes "${PG_ENABLE_LDAP}"; then
        postgresql_hba_ldap_auth
    else
        postgresql_hba_password_auth
    fi
}

# 更新 pg_hba.conf 文件，仅允许基于密码认证的访问
postgresql_restrict_hba_config() {
    LOG_I "Check pg_hba.conf for restrict configs..."

    if [[ -n "${PG_PASSWORD}" ]]; then
        LOG_D "  Configuring md5 encrypt"
        postgresql_hba_set "trust" "md5"
    fi
}

# 获取软件主版本号
postgresql_get_major_version() {
    psql --version | grep -oE "[0-9]+\.[0-9]+" | grep -oE "^[0-9]+"
}

# 为 Slava 模式工作的节点创建 recovery.conf 文件
postgresql_configure_recovery() {
    LOG_I "Setting up streaming replication standby..."

    # Recover 配置信息在不同版本保存位置不一样：
    #   版本为12及以上时， Slave 节点配置保存在 postgresql.conf 文件中
    #   版本低于12时， Slave 节点配置保存在 recover.conf 文件中
    local -r psql_major_version="$(postgresql_get_major_version)"
    if (( psql_major_version >= 12 )); then
        postgresql_conf_set "primary_conninfo" "host=${PG_PRIMARY_HOST} port=${PG_PRIMARY_PORT} user=${PG_REPLICATION_USER} password=${PG_REPLICATION_PASSWORD} application_name=${PG_CLUSTER_APP_NAME}"
        postgresql_conf_set "promote_trigger_file" "/tmp/postgresql.trigger.${PG_PRIMARY_PORT}"
        touch "${PG_DATA_DIR}/standby.signal"
    else
        [ ! -e "${PG_RECOVERY_FILE}" ] && cp -f "${APP_HOME_DIR}/share/recovery.conf.sample" "${PG_RECOVERY_FILE}"
        chmod 600 "${PG_RECOVERY_FILE}"
        postgresql_recover_set "standby_mode" "on"
        postgresql_recover_set "primary_conninfo" "host=${PG_PRIMARY_HOST} port=${PG_PRIMARY_PORT} user=${PG_REPLICATION_USER} password=${PG_REPLICATION_PASSWORD} application_name=${PG_CLUSTER_APP_NAME}"
        postgresql_recover_set "trigger_file" "/tmp/postgresql.trigger.${PG_PRIMARY_PORT}"
    fi
}

# 配置应用日志参数
postgresql_configure_logging() {
    LOG_I "Update logging configuration..."

    [[ -n "${PG_PGAUDIT_LOG}" ]] && postgresql_conf_set "pgaudit.log" "${PG_PGAUDIT_LOG}"
    [[ -n "${PG_PGAUDIT_LOG_CATALOG}" ]] && postgresql_conf_set "pgaudit.log_catalog" "${PG_PGAUDIT_LOG_CATALOG}"
    [[ -n "${PG_LOG_CONNECTIONS}" ]] && postgresql_conf_set "log_connections" "${PG_LOG_CONNECTIONS}"
    [[ -n "${PG_LOG_DISCONNECTIONS}" ]] && postgresql_conf_set "log_disconnections" "${PG_LOG_DISCONNECTIONS}"
    [[ -n "${PG_LOG_HOSTNAME}" ]] && postgresql_conf_set "log_hostname" "${PG_LOG_HOSTNAME}"
    [[ -n "${PG_CLIENT_MIN_MESSAGES}" ]] && postgresql_conf_set "client_min_messages" "${PG_CLIENT_MIN_MESSAGES}"
    [[ -n "${PG_LOG_LINE_PREFIX}" ]] && postgresql_conf_set "log_line_prefix" "${PG_LOG_LINE_PREFIX}"
    ([[ -n "${PG_LOG_TIMEZONE}" ]] && postgresql_conf_set "log_timezone" "${PG_LOG_TIMEZONE}") || true
}

# 配置应用连接控制参数
postgresql_configure_connections() {
    LOG_I "Update TCP connection configuration..."

    [[ -n "${PG_MAX_CONNECTIONS}" ]] && postgresql_conf_set "max_connections" "${PG_MAX_CONNECTIONS}"
    [[ -n "${PG_TCP_KEEPALIVES_IDLE}" ]] && postgresql_conf_set "tcp_keepalives_idle" "${PG_TCP_KEEPALIVES_IDLE}"
    [[ -n "${PG_TCP_KEEPALIVES_INTERVAL}" ]] && postgresql_conf_set "tcp_keepalives_interval" "${PG_TCP_KEEPALIVES_INTERVAL}"
    [[ -n "${PG_TCP_KEEPALIVES_COUNT}" ]] && postgresql_conf_set "tcp_keepalives_count" "${PG_TCP_KEEPALIVES_COUNT}"
    ([[ -n "${PG_STATEMENT_TIMEOUT}" ]] && postgresql_conf_set "statement_timeout" "${PG_STATEMENT_TIMEOUT}") || true
}

# 配置应用 TLS 参数
postgresql_configure_tls() {
    LOG_I "Update TLS configuration..."

    chmod 600 "${PG_TLS_KEY_FILE}" || LOG_W "Could not set compulsory permissions (600) on file ${PG_TLS_KEY_FILE}"
    postgresql_conf_set "ssl" "on"
    ! is_boolean_yes "${PG_TLS_PREFER_SERVER_CIPHERS}" && postgresql_conf_set "ssl_prefer_server_ciphers" "off"
    [[ -n "${PG_TLS_CA_FILE}" ]] && postgresql_conf_set "ssl_ca_file" "${PG_TLS_CA_FILE}"
    [[ -n "${PG_TLS_CRL_FILE}" ]] && postgresql_conf_set "ssl_crl_file" "${PG_TLS_CRL_FILE}"
    postgresql_conf_set "ssl_cert_file" "${PG_TLS_CERT_FILE}"
    postgresql_conf_set "ssl_key_file" "${PG_TLS_KEY_FILE}"
}

# 为默认的数据库用户 postgres 设置密码
# 参数:
#   $1 - 用户密码
postgresql_alter_postgres_user() {
    local -r escaped_password="${1//\'/\'\'}"
    LOG_I "Changing password of postgres"

    echo "ALTER ROLE postgres WITH PASSWORD '$escaped_password';" | postgresql_execute
    if [[ -n "${PG_POSTGRES_CONNECTION_LIMIT}" ]]; then
        echo "ALTER ROLE postgres WITH CONNECTION LIMIT ${PG_POSTGRES_CONNECTION_LIMIT};" | postgresql_execute
    fi
}

# 为数据库 $PG_DATABASE 创建管理员账户
postgresql_create_admin_user() {
    local -r escaped_password="${PG_PASSWORD//\'/\'\'}"

    local connlimit_string=""
    if [[ -n "${PG_USERNAME_CONNECTION_LIMIT}" ]]; then
        connlimit_string="CONNECTION LIMIT ${PG_USERNAME_CONNECTION_LIMIT}"
    fi

    LOG_I "Creating user ${PG_USERNAME}"
    echo "CREATE ROLE \"${PG_USERNAME}\" WITH LOGIN ${connlimit_string} CREATEDB PASSWORD '${escaped_password}';" | postgresql_execute
    
    LOG_I "Granting access to \"${PG_USERNAME}\" to the database \"${PG_DATABASE}\""
    echo "GRANT ALL PRIVILEGES ON DATABASE \"${PG_DATABASE}\" TO \"${PG_USERNAME}\"\;" | postgresql_execute "" "postgres" "${PG_POSTGRES_PASSWORD}"
}

# 为 primary-standby 复制模式创建用户
postgresql_create_replication_user() {
    local -r escaped_password="${PG_REPLICATION_PASSWORD//\'/\'\'}"
    LOG_I "Creating replication user ${PG_REPLICATION_USER}"

    echo "CREATE ROLE \"${PG_REPLICATION_USER}\" WITH REPLICATION LOGIN ENCRYPTED PASSWORD '$escaped_password'" | postgresql_execute
}

# 创建用户自定义数据库 $PG_DATABASE
postgresql_create_custom_database() {
    LOG_I "Creating custom database ${PG_DATABASE}"

    echo "CREATE DATABASE \"${PG_DATABASE}\"" | postgresql_execute "" "postgres" "" "localhost"
}

# 检测用户参数信息是否满足条件; 针对部分权限过于开放情况，打印提示信息
postgresql_verify_minimum_env() {
    local error_code=0
    LOG_D "Validating settings in PG_* env vars..."

    print_validation_error() {
        LOG_E "$1"
        error_code=1
    }

    # 检测认证设置。如果不允许匿名登录，检测登录用户名及密码是否设置
    empty_password_warn() {
        LOG_W "You set the environment variable ALLOW_ANONYMOUS_LOGIN=${ALLOW_ANONYMOUS_LOGIN}. For safety reasons, do not use this flag in a production environment."
    }
    empty_password_error() {
        print_validation_error "The $1 environment variable is empty or not set. Set the environment variable ALLOW_ANONYMOUS_LOGIN=yes to allow the container to be started with blank passwords. This is recommended only for development."
    }

    if is_boolean_yes "${ALLOW_ANONYMOUS_LOGIN}"; then
        empty_password_warn
    else
        if [[ -z "${PG_PASSWORD}" ]]; then
            empty_password_error "{PG_PASSWORD}"
        fi
        if (( ${#PG_PASSWORD} > 100 )); then
            print_validation_error "The password cannot be longer than 100 characters. Set the environment variable PG_PASSWORD with a shorter value"
        fi
        if [[ -n "${PG_USERNAME}" ]] && [[ -z "${PG_PASSWORD}" ]]; then
            empty_password_error "{PG_PASSWORD}"
        fi
        if [[ -n "${PG_USERNAME}" ]] && [[ "${PG_USERNAME}" != "postgres" ]] && [[ -n "${PG_PASSWORD}" ]] && [[ -z "${PG_DATABASE}" ]]; then
            print_validation_error "In order to use a custom PostgreSQL user you need to set the environment variable PG_DATABASE as well"
        fi
    fi

    if [[ -n "${PG_REPLICATION_MODE}" ]]; then
        if [[ "${PG_REPLICATION_MODE}" = "primary" ]]; then
            if (( PG_NUM_SYNCHRONOUS_REPLICAS < 0 )); then
                print_validation_error "The number of synchronous replicas cannot be less than 0. Set the environment variable PG_NUM_SYNCHRONOUS_REPLICAS"
            fi
        elif [[ "${PG_REPLICATION_MODE}" = "standby" ]]; then
            if [[ -z "${PG_PRIMARY_HOST}" ]]; then
                print_validation_error "Slave replication mode chosen without setting the environment variable PG_PRIMARY_HOST. Use it to indicate where the Master node is running"
            fi
            if [[ -z "${PG_REPLICATION_USER}" ]]; then
                print_validation_error "Slave replication mode chosen without setting the environment variable PG_REPLICATION_USER. Make sure that the primary also has this parameter set"
            fi
        else
            print_validation_error "Invalid replication mode. Available options are 'primary/standby'"
        fi
        # Common replication checks
        if [[ -n "${PG_REPLICATION_USER}" ]] && [[ -z "${PG_REPLICATION_PASSWORD}" ]]; then
            empty_password_error "{PG_REPLICATION_PASSWORD}"
        fi
    else
        if is_boolean_yes "${ALLOW_ANONYMOUS_LOGIN}"; then
            empty_password_warn
        else
            if [[ -z "${PG_PASSWORD}" ]]; then
                empty_password_error "{PG_PASSWORD}"
            fi
            if [[ -n "${PG_USERNAME}" ]] && [[ -z "${PG_PASSWORD}" ]]; then
                empty_password_error "{PG_PASSWORD}"
            fi
        fi
    fi

    if ! is_yes_no_value "${PG_ENABLE_LDAP}"; then
        empty_password_error "The values allowed for PG_ENABLE_LDAP are: yes or no"
    fi

    if is_boolean_yes "${PG_ENABLE_LDAP}" && [[ -n "${PG_LDAP_URL}" ]] && [[ -n "${PG_LDAP_SERVER}" ]]; then
        empty_password_error "You can not set PG_LDAP_URL and PG_LDAP_SERVER at the same time. Check your LDAP configuration."
    fi

    if ! is_yes_no_value "${PG_ENABLE_TLS}"; then
        print_validation_error "The values allowed for PG_ENABLE_TLS are: yes or no"
    elif is_boolean_yes "${PG_ENABLE_TLS}"; then
        if [[ -z "${PG_TLS_CERT_FILE}" ]]; then
            print_validation_error "You must provide a X.509 certificate in order to use TLS"
        elif [[ ! -f "${PG_TLS_CERT_FILE}" ]]; then
            print_validation_error "The X.509 certificate file in the specified path ${PG_TLS_CERT_FILE} does not exist"
        fi
        if [[ -z "${PG_TLS_KEY_FILE}" ]]; then
            print_validation_error "You must provide a private key in order to use TLS"
        elif [[ ! -f "${PG_TLS_KEY_FILE}" ]]; then
            print_validation_error "The private key file in the specified path ${PG_TLS_KEY_FILE} does not exist"
        fi
        if [[ -z "${PG_TLS_CA_FILE}" ]]; then
            warn "A CA X.509 certificate was not provided. Client verification will not be performed in TLS connections"
        elif [[ ! -f "${PG_TLS_CA_FILE}" ]]; then
            print_validation_error "The CA X.509 certificate file in the specified path ${PG_TLS_CA_FILE} does not exist"
        fi
        if [[ -n "${PG_TLS_CRL_FILE}" ]] && [[ ! -f "${PG_TLS_CRL_FILE}" ]]; then
            print_validation_error "The CRL file in the specified path ${PG_TLS_CRL_FILE} does not exist"
        fi
        if ! is_yes_no_value "${PG_TLS_PREFER_SERVER_CIPHERS}"; then
            print_validation_error "The values allowed for PG_TLS_PREFER_SERVER_CIPHERS are: yes or no"
        fi
    fi

    [[ "$error_code" -eq 0 ]] || exit "$error_code"
}

# 更改默认监听地址为 "*" 或 "0.0.0.0"，以对容器外提供服务；默认配置文件应当为仅监听 localhost(127.0.0.1)
postgresql_enable_remote_connections() {
    LOG_I "Modify default config to enable all IP access"

    postgresql_conf_set "listen_addresses" "*"
}

# 以后台方式启动应用服务，并等待启动就绪
postgresql_start_server_bg() {
    postgresql_is_server_running && return
    LOG_I "Starting ${APP_NAME} in background..."

    # -w wait until operation completes (default)
    # -W don't wait until operation completes
    # -D location of the database storage area
    # -l write (or append) server log to FILENAME
    # -o command line options to pass to postgres or initdb
    # --config-file 指定配置文件
    # --external_pid_file 指定 PID 文件，在配置文件中已定义
    # --hba_file 指定 HBA 文件，在配置文件中已定义
    local -r pg_ctl_flags=("-w" "-D" "${PG_DATA_DIR}" "-l" "${PG_LOG_FILE}" "-o" "--config-file=${PG_CONF_FILE} --external_pid_file=${PG_EXT_PID_FILE} --hba_file=${PG_HBA_FILE}")    
    local pg_ctl_cmd=("${APP_HOME_DIR}/bin/pg_ctl")
    if is_boolean_yes "${ENV_DEBUG}"; then
        "${pg_ctl_cmd[@]}" "start" "${pg_ctl_flags[@]}"
    else
        "${pg_ctl_cmd[@]}" "start" "${pg_ctl_flags[@]}" "-s" >/dev/null 2>&1
    fi

    local -r check_args=("-U" "postgres")
    local check_cmd=("${APP_HOME_DIR}/bin/pg_isready")
    local counter=${PG_INIT_MAX_TIMEOUT}
	# 通过命令或特定端口检测应用是否就绪
    LOG_I "Checking ${APP_NAME} ready status..."
    while ! "${check_cmd[@]}" "${check_args[@]}" "-q" >/dev/null 2>&1; do
        sleep 1
        counter=$(( counter - 1 ))
        if (( counter <= 0 )); then
            LOG_E "PostgreSQL is not ready after ${PG_INIT_MAX_TIMEOUT} seconds"
            exit 1
        fi
        LOG_D "PostgreSQL is not ready now: ${counter}"
    done
    LOG_D "${APP_NAME} is ready for service"
}

# 停止应用服务
postgresql_stop_server() {
    if postgresql_is_server_running ; then
        LOG_I "Stopping background ${APP_NAME}..."
        
        if is_boolean_yes "${ENV_DEBUG}"; then
            PGUSER="postgres" pg_ctl -D "${PG_DATA_DIR}" -m fast -w stop "-s"
        else
            PGUSER="postgres" pg_ctl -D "${PG_DATA_DIR}" -m fast -w stop "-s" >/dev/null 2>&1
        fi
    fi

    # 使用 PID 文件 kill 进程
    #stop_service_using_pid "${PG_EXT_PID_FILE}"
}

# 检测应用服务是否在后台运行中
postgresql_is_server_running() {
    LOG_D "Check if ${APP_NAME} is running..."

    local pid
    pid="$(get_pid_from_file "${PG_EXT_PID_FILE}")"

    if [[ -z "${pid}" ]]; then
        false
    else
        is_service_running "${pid}"
    fi
}

# 清理数据文件
postgresql_clean_data() {
    LOG_D "Clean ${APP_NAME} data files..."

    rm -rf "${PG_DATA_DIR}/*" "${APP_DATA_DIR}/.data_init_flag"
}

# 在重新启动容器时，删除标志文件及必须删除的临时文件 (容器重新启动)
postgresql_clean_from_restart() {
    LOG_D "Clean ${APP_NAME} tmp files for restart..."

    local -r -a files=(
        "${PG_DATA_DIR}/postmaster.pid"
        "${PG_DATA_DIR}/standby.signal"
        "${PG_DATA_DIR}/recovery.signal"
        "${PG_EXT_PID_FILE}"
    )

    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            LOG_I "Remove file: $file"
            rm -rf "$file"
        fi
    done
}

# 清空数据库及配置文件
postgresql_reset() {
    LOG_I "Clean all configuration and database files..."
    rm -rf "${PG_DATA_DIR}/*"
    rm -rf "${APP_DATA_DIR}/.data_init_flag" "${APP_DATA_DIR}/.custom_preinit_flag"  "${APP_DATA_DIR}/.custom_init_flag" 
    rm -rf "${APP_CONF_DIR}/*"
    rm -rf "${APP_CONF_DIR}/.app_init_flag"
}

# 应用默认初始化操作
# 执行完毕后，生成文件 ${APP_CONF_DIR}/.app_init_flag 及 ${APP_DATA_DIR}/.data_init_flag 文件
postgresql_default_init() {
    LOG_D "Check default init status of ${APP_NAME}..."
    postgresql_clean_from_restart

    if is_dir_empty "${PG_DATA_DIR}"; then
        LOG_I "Deploying ${APP_NAME} from scratch..."
        [ ! -e "${PG_HBA_FILE}" ] && postgresql_default_hba_config && postgresql_hba_allow_local_connection
        [ ! -e "${PG_CONF_FILE}" ] && postgresql_default_postgresql_config

        if [[ "${PG_REPLICATION_MODE}" = "primary" ]]; then
            postgresql_primary_init_db

            postgresql_start_server_bg
            [[ "${PG_DATABASE}" != "postgres" ]] && postgresql_create_custom_database

            # 为数据库授权；默认用户不为 postgres 时，需要创建管理员账户
            LOG_D "Set password for postgres user"
            if [[ "${PG_USERNAME}" = "postgres" ]]; then
                [[ -n "${PG_PASSWORD}" ]] && postgresql_alter_postgres_user "${PG_PASSWORD}"
            else
                [[ -n "${PG_POSTGRES_PASSWORD}" ]] && postgresql_alter_postgres_user "${PG_POSTGRES_PASSWORD}"
                postgresql_create_admin_user
            fi
            [[ -n "${PG_REPLICATION_USER}" ]] && postgresql_create_replication_user
        else
            postgresql_standby_init_db
        fi
    else
        LOG_I "Deploying ${APP_NAME} with persisted data..."
        export PG_FIRST_BOOT="no"
    fi

    # 检测配置文件是否存在
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

    if [[ ! -f "${APP_DATA_DIR}/.data_init_flag" ]]; then
        touch ${APP_DATA_DIR}/.data_init_flag
        echo "$(date '+%Y-%m-%d %H:%M:%S') : Init success." >> ${APP_DATA_DIR}/.data_init_flag
    fi

    postgresql_restrict_hba_config

    # 删除第一次运行时生成的默认配置文件
    rm -f "${PG_DATA_DIR}"/postgresql.conf "${PG_DATA_DIR}"/pg_hba.conf
}

# 用户自定义的前置初始化操作，依次执行目录 preinitdb.d 中的初始化脚本
# 执行完毕后，生成文件 ${APP_DATA_DIR}/.custom_preinit_flag
postgresql_custom_preinit() {
    LOG_I "Check custom pre-init status of ${APP_NAME}..."

    # 检测用户配置文件目录是否存在 preinitdb.d 文件夹，如果存在，尝试执行目录中的初始化脚本
    if [ -d "/srv/conf/${APP_NAME}/preinitdb.d" ]; then
        # 检测数据存储目录是否存在已初始化标志文件；如果不存在，检索可执行脚本文件并进行初始化操作
        if [[ -n $(find "/srv/conf/${APP_NAME}/preinitdb.d/" -type f -regex ".*\.\(sh\)") ]] && \
            [[ ! -f "${APP_DATA_DIR}/.custom_preinit_flag" ]]; then
            LOG_I "Process custom pre-init scripts from /srv/conf/${APP_NAME}/preinitdb.d..."

            # 检索所有可执行脚本，排序后执行
            find "/srv/conf/${APP_NAME}/preinitdb.d/" -type f -regex ".*\.\(sh\)" | sort | process_init_files

            touch "${APP_DATA_DIR}/.custom_preinit_flag"
            echo "$(date '+%Y-%m-%d %H:%M:%S') : Init success." >> "${APP_DATA_DIR}/.custom_preinit_flag"
            LOG_I "Custom preinit for ${APP_NAME} complete."
        else
            LOG_I "Custom preinit for ${APP_NAME} already done before, skipping initialization."
        fi
    fi

    # 检测依赖的服务是否就绪
    #for i in ${SERVICE_PRECONDITION[@]}; do
    #    app_wait_service "${i}"
    #done
}

# 用户自定义的应用初始化操作，依次执行目录initdb.d中的初始化脚本
# 执行完毕后，生成文件 ${APP_DATA_DIR}/.custom_init_flag
postgresql_custom_init() {
    LOG_I "Check custom initdb status of ${APP_NAME}..."

    # 检测用户配置文件目录是否存在 initdb.d 文件夹，如果存在，尝试执行目录中的初始化脚本
    if [ -d "/srv/conf/${APP_NAME}/initdb.d" ]; then
    	# 检测数据存储目录是否存在已初始化标志文件；如果不存在，检索可执行脚本文件并进行初始化操作
    	if [[ -n $(find "/srv/conf/${APP_NAME}/initdb.d/" -type f -regex ".*\.\(sh\|sql\|sql.gz\)") ]] && \
            [[ ! -f "${APP_DATA_DIR}/.custom_init_flag" ]]; then
            LOG_I "Process custom init scripts from /srv/conf/${APP_NAME}/initdb.d..."

            # 启动后台服务
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

            touch "${APP_DATA_DIR}/.custom_init_flag"
    		echo "$(date '+%Y-%m-%d %H:%M:%S') : Init success." >> "${APP_DATA_DIR}/.custom_init_flag"
    		LOG_I "Custom init for ${APP_NAME} complete."
    	else
    		LOG_I "Custom init for ${APP_NAME} already done before, skipping initialization."
    	fi
    fi
}

# 初始化 Master 节点数据库
postgresql_primary_init_db() {
    LOG_I "Initializing PostgreSQL database"

    postgresql_enable_nss_wrapper

    local envExtraFlags=()
    local initdb_args=()
    if [[ -n "${PG_INITDB_ARGS}" ]]; then
        read -r -a envExtraFlags <<< "${PG_INITDB_ARGS}"
        initdb_args+=("${envExtraFlags[@]}")
    fi
    #initdb+=("-o" "--config-file=${PG_CONF_FILE} --external_pid_file=${PG_EXT_PID_FILE} --hba_file=${PG_HBA_FILE}")
    if [[ -n "${PG_INITDB_WAL_DIR:-}" ]]; then
        initdb_args+=("--waldir=${PG_INITDB_WAL_DIR}")
    fi

    local initdb_cmd=("${APP_HOME_DIR}/bin/initdb")

    if [[ -n "${initdb_args[*]}" ]]; then
        LOG_I "extra initdb arguments: ${initdb_args[*]}"
    fi

    if is_boolean_yes "${ENV_DEBUG}"; then
        "${initdb_cmd[@]}" -E UTF8 -D "${PG_DATA_DIR}" -U "postgres" "${initdb_args[@]}"
    else
        "${initdb_cmd[@]}" -E UTF8 -D "${PG_DATA_DIR}" -U "postgres" "${initdb_args[@]}" >/dev/null 2>&1
    fi

    postgresql_disable_nss_wrapper
}

# 初始化 Slave 节点数据库
postgresql_standby_init_db() {
    LOG_I "Waiting for replication primary to accept connections (${PG_INIT_MAX_TIMEOUT} seconds)..."
    local -r check_args=("-U" "${PG_REPLICATION_USER}" "-h" "${PG_PRIMARY_HOST}" "-p" "${PG_PRIMARY_PORT}" "-d" "${PG_DATABASE}")
    local check_cmd=("${APP_HOME_DIR}/bin/pg_isready")
    local ready_counter=${PG_INIT_MAX_TIMEOUT}

    while ! PGPASSWORD=${PG_REPLICATION_PASSWORD} "${check_cmd[@]}" "${check_args[@]}" >/dev/null 2>&1;do
        sleep 1
        ready_counter=$(( ready_counter - 1 ))
        if (( ready_counter <= 0 )); then
            LOG_E "PostgreSQL primary is not ready after ${PG_INIT_MAX_TIMEOUT} seconds"
            exit 1
        fi
    done

    LOG_I "Replicating the database from node primary..."
    #local -r backup_args=("-D" "$PG_DATA_DIR" -d "hostaddr=$PG_PRIMARY_HOST port=$PG_PRIMARY_PORT user=$PG_REPLICATION_USER password=$PG_REPLICATION_PASSWORD" -v -Fp -Xs
    local -r backup_args=("-D" "${PG_DATA_DIR}" "-U" "${PG_REPLICATION_USER}" "-h" "${PG_PRIMARY_HOST}" "-p" "${PG_PRIMARY_PORT}" "-X" "stream" "-w" "-v" "-P")
    local backup_cmd=("${APP_HOME_DIR}/bin/pg_basebackup")
    local replication_counter=${PG_INIT_MAX_TIMEOUT}

    while ! PGPASSWORD=${PG_REPLICATION_PASSWORD} "${backup_cmd[@]}" "${backup_args[@]}";do
        LOG_D "Backup command failed. Sleeping and trying again"
        sleep 1
        replication_counter=$(( replication_counter - 1 ))
        if (( replication_counter <= 0 )); then
            LOG_E "Slave replication failed after trying for ${PG_INIT_MAX_TIMEOUT} seconds"
            exit 1
        fi
    done
}

