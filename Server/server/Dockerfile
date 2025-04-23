FROM php:7.2-apache

RUN apt-get update && apt-get install -y zip wget

WORKDIR /var/www/html
COPY ./src .
# Copy profile firefox


# config permission
RUN chown -R root:www-data /var/www/html
RUN chmod 750 /var/www/html
RUN find . -type f -exec chmod 640 {} \;
RUN find . -type d -exec chmod 750 {} \;

RUN chmod +t -R /var/www/html/