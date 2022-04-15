#!/bin/bash
set -euo pipefail

## TEMP File
TFILE=`mktemp --tmpdir tfile.XXXX`
trap "rm -f $TFILE" 0 1 2 3 15
## trap Deletes TFILE on Exit

# usage: file_env VAR [DEFAULT]
#    ie: file_env 'XYZ_DB_PASSWORD' 'example'
# (will allow for "$XYZ_DB_PASSWORD_FILE" to fill in the value of
#  "$XYZ_DB_PASSWORD" from a file, especially for Docker's secrets feature)
file_env() {
	local var="$1"
	local fileVar="${var}_FILE"
	local def="${2:-}"
	if [ "${!var:-}" ] && [ "${!fileVar:-}" ]; then
		echo >&2 "error: both $var and $fileVar are set (but are exclusive)"
		exit 1
	fi
	local val="$def"
	if [ "${!var:-}" ]; then
		val="${!var}"
	elif [ "${!fileVar:-}" ]; then
		val="$(< "${!fileVar}")"
	fi
	export "$var"="$val"
	unset "$fileVar"
}

if [ -n "${RUN_GID:-}" ]; then
	echo "Changing process GID to ${RUN_GID}."
	if [ ! $(getent group ${RUN_GID}) ]; then
		export RUN_GROUP=custom-group
		addgroup -gid ${RUN_GID} ${RUN_GROUP}
	else
		export RUN_GROUP=$(getent group ${RUN_GID} | awk -F ":" '{ print $1 }')
	fi
	if [[ "$1" == apache2* ]]; then
		sed -ri -e "s/^Group.*$/Group ${RUN_GROUP}/" /etc/apache2/apache2.conf
	elif [ "$1" == php-fpm ]; then
		sed -ri -e "s/^group.*$/group = ${RUN_GROUP}/" /usr/local/etc/php-fpm.d/www.conf
	fi
fi

if [ -n "${RUN_UID:-}" ]; then
	echo "Changing process UID to ${RUN_UID}."
	if [ ! $(getent passwd ${RUN_UID}) ]; then
		export RUN_USER=custom-user
		adduser --gecos "" --home /var/www --ingroup ${RUN_GROUP} --no-create-home --disabled-password --disabled-login --uid ${RUN_UID} ${RUN_USER}
	else
		export RUN_USER=$(getent passwd ${RUN_UID} | awk -F ":" '{ print $1 }')
	fi
	if [[ "$1" == apache2* ]]; then
		sed -ri -e "s/^User.*$/User ${RUN_USER}/" /etc/apache2/apache2.conf
	elif [ "$1" == php-fpm ]; then
		sed -ri -e "s/^user.*$/user = ${RUN_USER}/" /usr/local/etc/php-fpm.d/www.conf
	fi
fi

if [[ "$1" == apache2* ]]; then
    : ${HTTPS_ENABLED:=true}
    hostname="${APACHE_HOSTNAME:-localhost}"

    if [[ $HTTPS_ENABLED == "true" ]]; then
        if [ ! -e /etc/apache2/ssl/${hostname}.crt ] || [ ! -e /etc/apache2/ssl/${hostname}.key ]; then
            # if the certificates don't exist then make them
            mkdir -p /etc/apache2/ssl
            openssl req -days 356 -x509 -out /etc/apache2/ssl/${hostname}.crt -keyout /etc/apache2/ssl/${hostname}.key \
                -newkey rsa:2048 -nodes -sha256 \
                -subj '/CN='${hostname} -extensions EXT -config <( \
            printf "[dn]\nCN=${hostname}\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:${hostname}\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
        fi
        cat > /etc/apache2/sites-available/${hostname}-ssl.conf <<EOL
        <IfModule mod_ssl.c>
            <VirtualHost *:443>
                ServerName ${hostname}
                DocumentRoot /var/www/html
                ErrorLog \${APACHE_LOG_DIR}/error.log
                CustomLog \${APACHE_LOG_DIR}/access.log combined
                SSLEngine on
                SSLCertificateFile /etc/apache2/ssl/${hostname}.crt
                SSLCertificateKeyFile /etc/apache2/ssl/${hostname}.key
            </VirtualHost>
        </IfModule>
EOL
        a2enmod ssl
        a2ensite ${hostname}-ssl
    fi
fi

if [[ "$1" == apache2* ]] || [ "$1" == php-fpm ]; then
	if [ "$(id -u)" = '0' ]; then
		user="${RUN_USER:-www-data}"
		group="${RUN_GROUP:-www-data}"

		if [[ "$1" == apache2* ]]; then
			# strip off any '#' symbol ('#1000' is valid syntax for Apache)
			pound='#'
			user="${user#$pound}"
			group="${group#$pound}"
		fi
	else
		user="$(id -u)"
		group="$(id -g)"
	fi

	if [ ! -e index.php ] && [ ! -e wp-includes/version.php ]; then
		# if the directory exists and WordPress doesn't appear to be installed AND the permissions of it are root:root, let's chown it (likely a Docker-created directory)
		if [ "$(id -u)" = '0' ] && [ "$(stat -c '%u:%g' .)" = '0:0' ]; then
			chown "$user:$group" .
		fi

		echo >&2 "WordPress not found in $PWD - copying now..."
		if [ -n "$(ls -A)" ]; then
			echo >&2 "WARNING: $PWD is not empty! (copying anyhow)"
		fi
		sourceTarArgs=(
			--create
			--file -
			--directory /usr/src/wordpress
			--owner "$user" --group "$group"
		)
		targetTarArgs=(
			--extract
			--file -
		)
		if [ "$user" != '0' ]; then
			# avoid "tar: .: Cannot utime: Operation not permitted" and "tar: .: Cannot change mode to rwxr-xr-x: Operation not permitted"
			targetTarArgs+=( --no-overwrite-dir )
		fi
		tar "${sourceTarArgs[@]}" . | tar "${targetTarArgs[@]}"
		echo >&2 "Complete! WordPress has been successfully copied to $PWD"
		if [ ! -e .htaccess ]; then
			# NOTE: The "Indexes" option is disabled in the php:apache base image
			cat > .htaccess <<-'EOF'
				# BEGIN WordPress
				<IfModule mod_rewrite.c>
				RewriteEngine On
				RewriteBase /
				RewriteRule ^index\.php$ - [L]
				RewriteCond %{REQUEST_FILENAME} !-f
				RewriteCond %{REQUEST_FILENAME} !-d
				RewriteRule . /index.php [L]
				</IfModule>
				# END WordPress
			EOF
			chown "$user:$group" .htaccess
		fi

    	: ${HTTPS_ENABLED:=false}
    	hostname="${APACHE_HOSTNAME:-localhost}"
        if [ ! -e /etc/cron.d/wordpress ]; then
            if [[ $HTTPS_ENABLED != "false" ]]; then
                proto="https"
            else
                proto="http"
            fi
            cronurl="${proto}://${hostname}/wp-cron.php?doing_wp_cron"
            echo >&2 "Installing wordpress cron tasks into /etc/cron.d/wordpress"
            echo "*/10 * * * * curl -fk ${cronurl} > /dev/null 2>&1" > /etc/cron.d/wordpress
        fi
	fi

	# allow any of these "Authentication Unique Keys and Salts." to be specified via
	# environment variables with a "WORDPRESS_" prefix (ie, "WORDPRESS_AUTH_KEY")
	uniqueEnvs=(
		AUTH_KEY
		SECURE_AUTH_KEY
		LOGGED_IN_KEY
		NONCE_KEY
		AUTH_SALT
		SECURE_AUTH_SALT
		LOGGED_IN_SALT
		NONCE_SALT
	)
	envs=(
		WORDPRESS_DB_HOST
		WORDPRESS_DB_USER
		WORDPRESS_DB_PASSWORD
		WORDPRESS_DB_NAME
		WORDPRESS_DB_CHARSET
		WORDPRESS_DB_COLLATE
		"${uniqueEnvs[@]/#/WORDPRESS_}"
		WORDPRESS_TABLE_PREFIX
		WORDPRESS_DEBUG
		WORDPRESS_CONFIG_EXTRA
	)
	haveConfig=
	for e in "${envs[@]}"; do
		file_env "$e"
		if [ -z "$haveConfig" ] && [ -n "${!e}" ]; then
			haveConfig=1
		fi
	done

	# linking backwards-compatibility
	if [ -n "${!MYSQL_ENV_MYSQL_*}" ]; then
		haveConfig=1
		# host defaults to "mysql" below if unspecified
		: "${WORDPRESS_DB_USER:=${MYSQL_ENV_MYSQL_USER:-root}}"
		if [ "$WORDPRESS_DB_USER" = 'root' ]; then
			: "${WORDPRESS_DB_PASSWORD:=${MYSQL_ENV_MYSQL_ROOT_PASSWORD:-}}"
		else
			: "${WORDPRESS_DB_PASSWORD:=${MYSQL_ENV_MYSQL_PASSWORD:-}}"
		fi
		: "${WORDPRESS_DB_NAME:=${MYSQL_ENV_MYSQL_DATABASE:-}}"
	fi

	# only touch "wp-config.php" if we have environment-supplied configuration values
	if [ "$haveConfig" ]; then
		: "${WORDPRESS_DB_HOST:=mysql}"
		: "${WORDPRESS_DB_USER:=root}"
		: "${WORDPRESS_DB_PASSWORD:=}"
		: "${WORDPRESS_DB_NAME:=wordpress}"
		: "${WORDPRESS_DB_CHARSET:=utf8}"
		: "${WORDPRESS_DB_COLLATE:=}"

		# version 4.4.1 decided to switch to windows line endings, that breaks our seds and awks
		# https://github.com/docker-library/wordpress/issues/116
		# https://github.com/WordPress/WordPress/commit/1acedc542fba2482bab88ec70d4bea4b997a92e4
        unix_line_ends() {
            if [ -e "$1" ]; then
                sed -r -e 's/\r$//' "$1" > "$TFILE"
                cat "$TFILE" > $1
            fi
        }
        unix_line_ends "wp-config-sample.php"
        unix_line_ends "wp-config.php"

		if [ ! -e wp-config.php ]; then
			awk '
				/^\/\*.*stop editing.*\*\/$/ && c == 0 {
					c = 1
					system("cat")
					if (ENVIRON["WORDPRESS_CONFIG_EXTRA"]) {
						print "// WORDPRESS_CONFIG_EXTRA"
						print ENVIRON["WORDPRESS_CONFIG_EXTRA"] "\n"
					}
				}
				{ print }
			' wp-config-sample.php > wp-config.php <<'EOPHP'
// If we're behind a proxy server and using HTTPS, we need to alert WordPress of that fact
// see also http://codex.wordpress.org/Administration_Over_SSL#Using_a_Reverse_Proxy
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
	$_SERVER['HTTPS'] = 'on';
}

EOPHP
			chown "$user:$group" wp-config.php
		elif [ -e wp-config.php ] && [ -n "$WORDPRESS_CONFIG_EXTRA" ] && [[ "$(< wp-config.php)" != *"$WORDPRESS_CONFIG_EXTRA"* ]]; then
			# (if the config file already contains the requested PHP code, don't print a warning)
			echo >&2
			echo >&2 'WARNING: environment variable "WORDPRESS_CONFIG_EXTRA" is set, but "wp-config.php" already exists'
			echo >&2 '  The contents of this variable will _not_ be inserted into the existing "wp-config.php" file.'
			echo >&2 '  (see https://github.com/docker-library/wordpress/issues/333 for more details)'
			echo >&2
		fi

		# see http://stackoverflow.com/a/2705678/433558
		sed_escape_lhs() {
			echo "$@" | sed -e 's/[]\/$*.^|[]/\\&/g'
		}
		sed_escape_rhs() {
			echo "$@" | sed -e 's/[\/&]/\\&/g'
		}
		php_escape() {
			local escaped="$(php -r 'var_export(('"$2"') $argv[1]);' -- "$1")"
			if [ "$2" = 'string' ] && [ "${escaped:0:1}" = "'" ]; then
				escaped="${escaped//$'\n'/"' + \"\\n\" + '"}"
			fi
			echo "$escaped"
		}
		set_config() {
			key="$1"
			value="$2"
			var_type="${3:-string}"
			start="(['\"])$(sed_escape_lhs "$key")\2\s*,"
			end="\);"
			if [ "${key:0:1}" = '$' ]; then
				start="^(\s*)$(sed_escape_lhs "$key")\s*="
				end=";"
			fi
			sed -r -e "s/($start\s*).*($end)$/\1$(sed_escape_rhs "$(php_escape "$value" "$var_type")")\3/" wp-config.php > "$TFILE"
            cat "$TFILE" > wp-config.php
		}

		set_config 'DB_HOST' "$WORDPRESS_DB_HOST"
		set_config 'DB_USER' "$WORDPRESS_DB_USER"
		set_config 'DB_PASSWORD' "$WORDPRESS_DB_PASSWORD"
		set_config 'DB_NAME' "$WORDPRESS_DB_NAME"
		set_config 'DB_CHARSET' "$WORDPRESS_DB_CHARSET"
		set_config 'DB_COLLATE' "$WORDPRESS_DB_COLLATE"

		for unique in "${uniqueEnvs[@]}"; do
			uniqVar="WORDPRESS_$unique"
			if [ -n "${!uniqVar}" ]; then
				set_config "$unique" "${!uniqVar}"
			else
				# if not specified, let's generate a random value
				currentVal="$(sed -rn -e "s/define\(\s*(([\'\"])$unique\2\s*,\s*)(['\"])(.*)\3\s*\);/\4/p" wp-config.php)"
				if [ "$currentVal" = 'put your unique phrase here' ]; then
					set_config "$unique" "$(head -c1m /dev/urandom | sha1sum | cut -d' ' -f1)"
				fi
			fi
		done

		if [ "$WORDPRESS_TABLE_PREFIX" ]; then
			set_config '$table_prefix' "$WORDPRESS_TABLE_PREFIX"
		fi

		if [ "$WORDPRESS_DEBUG" ]; then
			set_config 'WP_DEBUG' 1 boolean
		fi

		if ! TERM=dumb php -- <<'EOPHP'
<?php
// database might not exist, so let's try creating it (just to be safe)

$stderr = fopen('php://stderr', 'w');

// https://codex.wordpress.org/Editing_wp-config.php#MySQL_Alternate_Port
//   "hostname:port"
// https://codex.wordpress.org/Editing_wp-config.php#MySQL_Sockets_or_Pipes
//   "hostname:unix-socket-path"
list($host, $socket) = explode(':', getenv('WORDPRESS_DB_HOST'), 2);
$port = 0;
if (is_numeric($socket)) {
	$port = (int) $socket;
	$socket = null;
}
$user = getenv('WORDPRESS_DB_USER');
$pass = getenv('WORDPRESS_DB_PASSWORD');
$dbName = getenv('WORDPRESS_DB_NAME');

$maxTries = 10;
do {
	$mysql = new mysqli($host, $user, $pass, '', $port, $socket);
	if ($mysql->connect_error) {
		fwrite($stderr, "\n" . 'MySQL Connection Error: (' . $mysql->connect_errno . ') ' . $mysql->connect_error . "\n");
		--$maxTries;
		if ($maxTries <= 0) {
			exit(1);
		}
		sleep(3);
	}
} while ($mysql->connect_error);

if (!$mysql->query('CREATE DATABASE IF NOT EXISTS `' . $mysql->real_escape_string($dbName) . '`')) {
	fwrite($stderr, "\n" . 'MySQL "CREATE DATABASE" Error: ' . $mysql->error . "\n");
	$mysql->close();
	exit(1);
}

$mysql->close();
EOPHP
		then
			echo >&2
			echo >&2 "WARNING: unable to establish a database connection to '$WORDPRESS_DB_HOST'"
			echo >&2 '  continuing anyways (which might have unexpected results)'
			echo >&2
		fi
	fi

	# now that we're definitely done writing configuration, let's clear out the relevant envrionment variables (so that stray "phpinfo()" calls don't leak secrets from our code)
	for e in "${envs[@]}"; do
		unset "$e"
	done
fi

exec "$@"
