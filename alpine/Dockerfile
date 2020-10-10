# Ver: 1.2 by Endial Fang (endial@126.com)
#

# 预处理 =========================================================================
FROM colovu/abuilder as builder

# sources.list 可使用版本：default / tencent / ustc / aliyun / huawei
ARG apt_source=default

# 编译镜像时指定用于加速的本地服务器地址
ARG local_url=""

ENV APP_NAME=postgresql \
	APP_VERSION=12.4

RUN select_source ${apt_source};
RUN install_pkg bison coreutils flex libedit-dev libxml2-dev libxslt-dev util-linux-dev zlib-dev icu-dev \
		openssl-dev openldap-dev krb5-dev linux-pam-dev libselinux-dev \
# configure: error: prove not found
		perl-utils \
# configure: error: Perl module IPC::Run is required to run TAP tests
		perl-ipc-run

# 下载并解压软件包
RUN set -eux; \
	appName="${APP_NAME}-${APP_VERSION}.tar.bz2"; \
	sha256="bee93fbe2c32f59419cb162bcc0145c58da9a8644ee154a30b9a5ce47de606cc"; \
	[ ! -z ${local_url} ] && localURL=${local_url}/${APP_NAME}; \
	appUrls="${localURL:-} \
		https://ftp.postgresql.org/pub/source/v${APP_VERSION} \
		"; \
	download_pkg unpack ${appName} "${appUrls}" -s "${sha256}";

# 源码编译: 编译后将配置文件模板拷贝至 /usr/local/${APP_NAME}/share/${APP_NAME} 中
RUN set -eux; \
	APP_SRC="/usr/local/${APP_NAME}-${APP_VERSION}"; \
	cd ${APP_SRC}; \
	\
# update "DEFAULT_PGSOCKET_DIR" to "/var/run/postgresql" (matching Debian)
# see https://anonscm.debian.org/git/pkg-postgresql/postgresql.git/tree/debian/patches/51-default-sockets-in-var.patch?id=8b539fcb3e093a521c095e70bdfa76887217b89f
	awk '$1 == "#define" && $2 == "DEFAULT_PGSOCKET_DIR" && $3 == "\"/tmp\"" { $3 = "\"/var/run/postgresql\""; print; next } { print }' src/include/pg_config_manual.h > src/include/pg_config_manual.h.new; \
	grep '/var/run/postgresql' src/include/pg_config_manual.h.new; \
	mv src/include/pg_config_manual.h.new src/include/pg_config_manual.h; \
	gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
# explicitly update autoconf config.guess and config.sub so they support more arches/libcs
	wget -O config/config.guess 'https://git.savannah.gnu.org/cgit/config.git/plain/config.guess?id=7d3d27baf8107b630586c962c057e22149653deb'; \
	wget -O config/config.sub 'https://git.savannah.gnu.org/cgit/config.git/plain/config.sub?id=7d3d27baf8107b630586c962c057e22149653deb'; \
	\
# configure options taken from:
# https://anonscm.debian.org/cgit/pkg-postgresql/postgresql.git/tree/debian/rules?h=9.5
	./configure \
		--prefix=/usr/local/${APP_NAME} \
		--build="$gnuArch" \
		--enable-integer-datetimes \
		--enable-thread-safety \
		--disable-rpath \
		--with-uuid=e2fs \
		--with-gnu-ld \
		--with-pgport=5432 \
		--with-system-tzdata=/usr/share/zoneinfo \
		--with-includes=/usr/local/include \
		--with-libraries=/usr/local/lib \
		--with-openssl \
		--with-libxml \
		--with-libxslt \
		--with-icu \
		--with-krb5 \
		--with-ldap \
		--enable-tap-tests \
# "/usr/src/postgresql/src/backend/access/common/tupconvert.c:105: undefined reference to `libintl_gettext'"
#		--enable-nls \
# these make our image abnormally large (at least 100MB larger), which seems uncouth for an "Alpine" (ie, "small") variant :)
#		--enable-debug \
#		--with-gssapi \
#		--with-tcl \
#		--with-perl \
#		--with-python \
#		--with-pam \
	; \
	make -j "$(nproc)" world; \
	make install-world; \
	make -C contrib install;

# repmgr 编译时需要保证在系统搜索路径中能找到 pg_config
ENV PATH="/usr/local/${APP_NAME}/bin:${PATH}" \
	LD_LIBRARY_PATH="/usr/local/${APP_NAME}/lib"

ENV REPMGR_NAME=repmgr \
	REPMGR_VERSION=5.1.0

# 下载并解压软件包
RUN set -eux; \
	appName="${REPMGR_NAME}-${REPMGR_VERSION}.tar.gz"; \
	sha256="79e71bc0aa68a7ae9d263127e4a451749c120e55504bea1f1bc9b0baeb49e0d5"; \
	[ ! -z ${local_url} ] && localURL=${local_url}/${REPMGR_NAME}; \
	appUrls="${localURL:-} \
		https://repmgr.org/download \
		"; \
	download_pkg unpack ${appName} "${appUrls}" -s "${sha256}";

# 源码编译: 编译后将配置文件模板拷贝至 /usr/local/${APP_NAME}/share/${APP_NAME} 中
RUN set -eux; \
	APP_SRC="/usr/local/${REPMGR_NAME}-${REPMGR_VERSION}"; \
	cd ${APP_SRC}; \
	./configure ; \
	make -j "$(nproc)" all; \
	make install; 

# 删除编译生成的多余文件
RUN set -eux; \
	find /usr/local -name '*.a' -delete; \
	rm -rf /usr/local/${APP_NAME}/include;

# 检测并生成依赖文件记录；repmgr 相关资源也是放置在 ${APP_NAME} 路径下
RUN set -eux; \
	scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/${APP_NAME} | \
		tr ',' '\n' | \
		sort -u | \
		awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } \
		{ print "so:" $1 }' >/usr/local/${APP_NAME}/runDeps;

# 镜像生成 ========================================================================
FROM colovu/alpine:3.12

ARG apt_source=default
ARG local_url=""

ENV APP_NAME=postgresql \
	APP_USER=postgres \
	APP_EXEC=run.sh \
	APP_VERSION=12.4

ENV REPMGR_NAME=repmgr \
	REPMGR_VERSION=5.1.0

ENV	APP_HOME_DIR=/usr/local/${APP_NAME} \
	APP_DEF_DIR=/etc/${APP_NAME}

ENV PATH="${APP_HOME_DIR}/bin:${PATH}" \
	LD_LIBRARY_PATH="${APP_HOME_DIR}/lib"

LABEL \
	"Version"="v${APP_VERSION}" \
	"Description"="Docker image for ${APP_NAME}(v${APP_VERSION}) with repmgr(v${REPMGR_VERSION})." \
	"Dockerfile"="https://github.com/colovu/docker-${APP_NAME}-${REPMGR_NAME}" \
	"Vendor"="Endial Fang (endial@126.com)"



# 选择软件包源
RUN select_source ${apt_source}

# 从预处理过程中拷贝软件包(Optional)
COPY --from=builder /usr/local/${APP_NAME}/ /usr/local/${APP_NAME}

# 安装依赖的软件包及库(Optional)
RUN install_pkg `cat /usr/local/${APP_NAME}/runDeps`; 

COPY customer /
RUN create_user && prepare_env

# 执行预处理脚本，并验证安装的软件包
RUN set -eux; \
	override_file="/usr/local/overrides/overrides-${APP_VERSION}.sh"; \
	[ -e "${override_file}" ] && /bin/bash "${override_file}"; \
	gosu ${APP_USER} postgres --version ; \
	gosu ${APP_USER} repmgr --version ; \
	gosu --version;

# 默认提供的数据卷
VOLUME ["/srv/conf", "/srv/data", "/srv/datalog", "/srv/cert", "/var/log"]

# 默认使用gosu切换为新建用户启动，必须保证端口在1024之上
EXPOSE 5432

# 应用健康状态检查
HEALTHCHECK CMD PGPASSWORD="${PG_POSTGRES_PASSWORD:-${PG_PASSWORD}}" psql -h 127.0.0.1 -d postgres -U postgres -At -c "select version();" || exit 1

# 容器初始化命令，默认存放在：/usr/local/bin/entry.sh
ENTRYPOINT ["entry.sh"]

# 应用程序的服务命令，必须使用非守护进程方式运行。如果使用变量，则该变量必须在运行环境中存在（ENV可以获取）
CMD ["${APP_EXEC}"]

