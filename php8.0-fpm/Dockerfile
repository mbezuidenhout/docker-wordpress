#
# WordPress Dockerfile
#

FROM wordpress:php8.0-fpm
LABEL maintainer="Marius Bezuidenhout <marius.bezuidenhout@gmail.com>"

RUN apt-get update &&\
    apt-get install --no-install-recommends --assume-yes --quiet \
        curl git libxml2-dev imagemagick libmagickwand-dev systemd-cron libssl-dev &&\
    apt-get clean &&\
    rm -rf /var/lib/apt/lists/* &&\
    ldconfig &&\
    docker-php-ext-install soap intl pdo_mysql

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini \
    && sed -i -e 's/expose_php = On/expose_php = Off/' /usr/local/etc/php/php.ini \
    && sed -i -e 's/pm.max_children = 5/pm.max_children = 8/' /usr/local/etc/php-fpm.d/www.conf \
    && sed -i -e 's/pm.max_spare_servers = 3/pm.max_spare_servers = 6/' /usr/local/etc/php-fpm.d/www.conf \
    && echo "opcache.interned_strings_buffer=16\nopcache.max_accelerated_files=5000\nopcache.memory_consumption=192\nopcache.jit_buffer_size=256M" > /usr/local/etc/php/conf.d/opcache-zzz.ini
ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["php-fpm"]
