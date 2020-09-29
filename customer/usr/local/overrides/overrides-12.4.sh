#!/bin/bash -ex

POSTGRESQL_CONF="${APP_HOME_DIR}/share/postgresql.conf.sample"

# 在安装完应用后，使用该脚本修改默认配置文件中部分配置项
# 如果相应的配置项已经定义整体环境变量，则不需要在这里修改
echo "Process overrides for default configs..."
#sed -i -E 's/^listeners=/d' "$KAFKA_HOME/config/server.properties"

# 设置默认监听地址为 localhost ，防止初始化操作期间外部链接，在容器初始化完成后修改为监听所有地址
sed -i -E "s/^#?(listen_addresses) .*/\1 = 'localhost'/g" ${POSTGRESQL_CONF}

sed -i -E "s/^#?data_directory .*/data_directory = '\/srv\/data\/${APP_NAME}\/data'/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?hba_file .*/hba_file = '\/srv\/conf\/${APP_NAME}\/pg_hba.conf'/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?ident_file .*/ident_file = '\/srv\/data\/${APP_NAME}\/data\/pg_ident.conf'/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?external_pid_file .*/external_pid_file = '\/var\/run\/${APP_NAME}\/postgresql.pid'/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?max_connections .*/max_connections = 2000/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?password_encryption .*/password_encryption = md5/g" ${POSTGRESQL_CONF}

sed -i -E "s/^#?log_destination .*/log_destination = 'stderr'/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?logging_collector .*/logging_collector = on/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?log_directory .*/log_directory = '\/var\/log\/${APP_NAME}'/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?log_filename .*/log_filename = 'postgresql-\%Y-\%m-\%d_\%H\%M\%S.log'/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?log_truncate_on_rotation .*/log_truncate_on_rotation = on/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?log_rotation_age .*/log_rotation_age = 1d/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?log_rotation_size .*/log_rotation_size = 0/g" ${POSTGRESQL_CONF}
sed -i -E "s/^#?log_timezone .*/log_timezone = 'Asia\/Shanghai'/g" ${POSTGRESQL_CONF}

#sed -i -E "s/^#?include_dir .*/include_dir = 'conf\.d'/g" ${POSTGRESQL_CONF}

# 修改 unix_socket_directories 与 PID 文件同目录，解决修改 PID 输出目录后 psql 不指定`-h`时 Unix Socket 无法找到问题：
#   psql: could not connect to server: No such file or directory
#   	Is the server running locally and accepting
# 		connections on Unix domain socket "/var/run/postgresql/.s.PGSQL.5432"?
sed -i -E "s/^unix_socket_directories .*/unix_socket_directories = '\/var\/run\/${APP_NAME}'/g" ${POSTGRESQL_CONF}
