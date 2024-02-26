#
# WordPress Dockerfile
#

ARG GO_IMAGE=golang:alpine

FROM ${GO_IMAGE} as step-builder

COPY step-builder.sh /usr/local/bin/step-builder.sh

RUN apk add curl git make \
    && git clone https://github.com/smallstep/cli.git step-cli \
    && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/local/bin latest \
    && chmod +x /usr/local/bin/step-builder.sh \
    && cd step-cli \
    && make bootstrap \
    && /usr/local/bin/step-builder.sh

FROM wordpress:php8.0
LABEL maintainer="Marius Bezuidenhout <marius.bezuidenhout@gmail.com>"

RUN apt-get update &&\
    apt-get install --no-install-recommends --assume-yes --quiet \
        ca-certificates curl git libxml2-dev imagemagick libmagickwand-dev systemd-cron libssl-dev &&\
    apt-get clean &&\
    rm -rf /var/lib/apt/lists/* &&\
    ldconfig &&\
    docker-php-ext-install soap intl pdo_mysql

COPY --from=step-builder /usr/local/bin/step /usr/local/bin

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini \
    && sed -i -e 's/expose_php = On/expose_php = Off/' /usr/local/etc/php/php.ini \
    && echo "opcache.interned_strings_buffer=16\nopcache.max_accelerated_files=5000\nopcache.memory_consumption=192\nopcache.jit_buffer_size=256M" > /usr/local/etc/php/conf.d/opcache-zzz.ini
ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["apache2-foreground"]
