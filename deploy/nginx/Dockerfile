FROM nginx:alpine

COPY public/ /var/www/html/public/
COPY deploy/nginx/default.conf /etc/nginx/conf.d/default.conf

RUN mkdir -p /var/www/html/storage/app/public

EXPOSE 80
