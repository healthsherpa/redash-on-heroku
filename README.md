# Redash on Heroku

Dockerfiles for hosting redash on heroku

## How to create

```sh
git clone git@github.com:willnet/redash-on-heroku.git
cd redash-on-heroku
heroku create --stack=container your_app_name
```

## How to setup

### Add Addons

Add following addons on heroku dashboard.

- heroku postgres
- Redis Cloud(or something)
- sendgrid (or something)

Choose redis addon allow more than or equal 30 connections. Otherwise you will get connection errors frequently.

### Add environment variables

Add environment variables like following.

```sh
heroku config:set PYTHONUNBUFFERED=0
heroku config:set QUEUES=queries,scheduled_queries,celery
heroku config:set REDASH_COOKIE_SECRET=YOUR_SECRET_TOKEN
heroku config:set REDASH_SECRET_KEY=YOUR_SECRET_KEY
heroku config:set REDASH_DATABASE_URL=YOUR_POSTGRES_URL
heroku config:set REDASH_LOG_LEVEL=INFO
heroku config:set REDASH_REDIS_URL=YOUR_REDIS_URL
heroku config:set REDASH_HOST=YOUR_DOMAIN_URL
heroku config:set REDASH_MAIL_PASSWORD=YOUR_ADDON_PASSWORD
heroku config:set REDASH_MAIL_PORT=587
heroku config:set REDASH_MAIL_SERVER=YOUR_ADDON_DOMAIN
heroku config:set REDASH_MAIL_USERNAME=YOUR_ADDON_USERNAME
heroku config:set REDASH_MAIL_USE_TLS=true
heroku config:set REDASH_MAIL_DEFAULT_SENDER=YOUR_MAIL_ADDRESS
```

See also https://redash.io/help/open-source/setup#-setup

### `wsgi_heroku.py`

The web dyno loads `wsgi_heroku.py` instead of Redash's default `redash.wsgi`.
It wraps the normal Flask app and runs before Redash's `ProxyFix` middleware,
which otherwise trusts `X-Forwarded-Host` and can reflect a spoofed hostname in
redirect URLs.

On each request it:

1. Strips `X-Forwarded-Host` when it fails the allowlist check (`REDASH_HOST` +
   `REDASH_ALLOWED_HOSTS`). Allowlisted values are kept.
2. Rewrites `Host` to `REDASH_HOST` on every request when `REDASH_HOST` is set
3. Sets Flask `SERVER_NAME` and `PREFERRED_URL_SCHEME` from `REDASH_HOST`

If `REDASH_HOST` is unset, the allowlist is empty, `Host` is not rewritten, and
the `X-Forwarded-Host` strip is skipped.

Environment variables read by `wsgi_heroku.py`:

| Variable                        | Default   | Description                                                                                                                                                    |
| ------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REDASH_HOST`                   | _(unset)_ | Canonical URL for the app (e.g. `https://redash.example.com`). Used for Flask `SERVER_NAME` and to rewrite `Host` on every request.                          |
| `REDASH_ALLOWED_HOSTS`          | _(unset)_ | Comma-separated extra hostnames allowed in `X-Forwarded-Host` (e.g. a Heroku default domain during migration).                                                 |
| `REDASH_STRIP_X_FORWARDED_HOST` | `true`    | Strip `X-Forwarded-Host` when it fails the allowlist check.                                                                                                    |

Example:

```sh
heroku config:set REDASH_HOST=https://redash.example.com
heroku config:set REDASH_ALLOWED_HOSTS=your-app.herokuapp.com
```

### Release container

```sh
git push heroku master
```

### Create database

After deploy and add postgres addon, create database like following.

```sh
heroku run /app/manage.py database create_tables
```

### Enable worker dyno

```sh
heroku ps:scale worker=1
```

## How to upgrade

```sh
heroku ps:scale web=0 worker=0
git push heroku master
heroku run /app/manage.py db upgrade
heroku ps:scale web=1 worker=1
```

See also https://redash.io/help/open-source/admin-guide/how-to-upgrade
