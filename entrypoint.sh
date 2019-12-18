#!/bin/sh

# Require environment variables.
if [ -z "${SOUNDSCAPE_HTTP_HOST-}" ] ; then
    echo "Environment variable SOUNDSCAPE_HTTP_HOST required. Exiting."
    exit 1
fi
# Optional environment variables.
if [ -z "${SOUNDSCAPE_BACKLINK-}" ] ; then
    export SOUNDSCAPE_BACKLINK=""
fi

if [ -z "${SOUNDSCAPE_LETSENCRYPT-}" ] ; then
    export SOUNDSCAPE_LETSENCRYPT="true"
fi

if [ -z "${SOUNDSCAPE_HTTP_ADDR-}" ] ; then
    export SOUNDSCAPE_HTTP_ADDR=":80"
fi

if [ -z "${SOUNDSCAPE_HTTP_PREFIX-}" ] ; then
    export SOUNDSCAPE_HTTP_PREFIX="/app"
fi

if [ -z "${SOUNDSCAPE_HTTP_USER-}" ] ; then
    export SOUNDSCAPE_HTTP_USER="soundscape"
fi

if [ -z "${SOUNDSCAPE_HTTP_ADMIN-}" ] ; then
    export SOUNDSCAPE_HTTP_ADMIN="admin:passwd"
fi

if [ -z "${SOUNDSCAPE_HTTP_READ_ONLY-}" ] ; then
    export SOUNDSCAPE_HTTP_READ_ONLY="user:user"
fi

if [ -z "${DEBUG-}" ] ; then
    export DEBUG="false"
fi

exec /usr/local/bin/soundscape \
    "--http-host=${SOUNDSCAPE_HTTP_HOST}" \
    "--http-addr=${SOUNDSCAPE_HTTP_ADDR}" \
    "--http-prefix=${SOUNDSCAPE_HTTP_PREFIX}" \
    "--backlink=${SOUNDSCAPE_BACKLINK}" \
    "--http-username=${SOUNDSCAPE_HTTP_USER}" \
    "--http-admin=${SOUNDSCAPE_HTTP_ADMIN}" \
    "--http-read-only=${SOUNDSCAPE_HTTP_READ_ONLY}" \
    "--letsencrypt=${SOUNDSCAPE_LETSENCRYPT}" \
    "--debug=${DEBUG}"
