FROM php:8.3-cli

# The php:8.3-cli base image does not ship the SQLite dev headers, so building
# the pdo_sqlite extension fails without libsqlite3-dev. Install it first.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libsqlite3-dev \
 && docker-php-ext-install pdo_sqlite \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN mkdir -p /app/data && chmod 777 /app/data

ENV PORT=3000
ENV DATABASE_PATH=/app/data/locker.db
EXPOSE 3000

CMD ["sh", "-c", "php -S 0.0.0.0:${PORT} -t public public/router.php"]
