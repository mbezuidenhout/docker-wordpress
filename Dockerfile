#
# WordPress Dockerfile
#

FROM wordpress:php7.4
LABEL maintainer="Marius Bezuidenhout <marius.bezuidenhout@gmail.com>"

RUN apt-get update &&\
    apt-get install --no-install-recommends --assume-yes --quiet \
        ca-certificates curl git libxml2-dev imagemagick libmagickwand-dev systemd-cron libssl-dev &&\
    apt-get clean &&\
    rm -rf /var/lib/apt/lists/* &&\
    ldconfig &&\
    docker-php-ext-install soap

COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["apache2-foreground"]
