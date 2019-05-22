FROM wordpress:php7.3
MAINTAINER Marius Bezuidenhout "marius.bezuidenhout@gmail.com"

RUN apt-get update &&\
    apt-get install --no-install-recommends --assume-yes --quiet ca-certificates curl git libxml2-dev imagemagick libmagickwand-dev &&\
    apt-get clean &&\
    rm -rf /var/lib/apt/lists/* &&\
    ldconfig &&\
    docker-php-ext-install soap bcmath exif

# Install imagick
RUN yes | pecl install imagick \
    && echo "extension=$(find /usr/local/lib/php/extensions/ -name imagick.so)" > /usr/local/etc/php/conf.d/imagick.ini

COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["apache2-foreground"]
