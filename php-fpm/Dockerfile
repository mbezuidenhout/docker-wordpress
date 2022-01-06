#
# WordPress Dockerfile
#

FROM wordpress:php7.4-fpm
LABEL maintainer="Marius Bezuidenhout <marius.bezuidenhout@gmail.com>"

RUN apt-get update &&\
    apt-get install --no-install-recommends --assume-yes --quiet \
        curl git libxml2-dev imagemagick libmagickwand-dev systemd-cron libssl-dev &&\
    apt-get clean &&\
    rm -rf /var/lib/apt/lists/* &&\
    ldconfig &&\
    docker-php-ext-install soap intl

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini \
    && sed -i -e 's/expose_php = On/expose_php = Off/' /usr/local/etc/php/php.ini \
    && echo -e "opcache.interned_strings_buffer=16\nopcache.max_accelerated_files=5000\nopcache.memory_consumption=192" > /usr/local/etc/php/conf.d/opcache-zzz.ini
ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["php-fpm"]
