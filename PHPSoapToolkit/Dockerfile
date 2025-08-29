FROM php:5.6-cli
#COPY . app
COPY debian-stretch/sources.list /etc/apt/sources.list
RUN apt-get update && apt-get install -y vim less procps
RUN apt-get install -y --no-install-recommends libxml2-dev \
 && docker-php-ext-install -j$(nproc) soap

CMD ["bash"]
