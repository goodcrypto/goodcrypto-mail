#! /bin/bash
#   GoodCrypto Mail
#   Copyright 2014-2016 GoodCrypto
#   Last modified: 2016-09-05

logdir=/var/local/log/goodcrypto
goodcrypto_server=/var/local/projects/goodcrypto/server
goodcrypto_mail_tools=$goodcrypto_server/src/mail/tools
goodcrypto_oce_tools=$goodcrypto_server/src/oce/tools
goodcrypto_system_tools=$goodcrypto_server/src/system/tools

function start() {
    redis-server /etc/redis/redis_message.conf >/var/log/redis.log &
    redis-server /etc/redis/redis_gpg.conf >/var/log/redis.log &
    redis-server /etc/redis/redis_crypto.conf >/var/log/redis.log &
    redis-server /etc/redis/redis_special.conf >/var/log/redis.log &

    /usr/local/bin/supervisord -c $goodcrypto_system_tools/supervisord.special.conf
    sudo -u goodcrypto /usr/local/bin/supervisord -c $goodcrypto_oce_tools/supervisord.gpg.conf
    sudo -u goodcrypto /usr/local/bin/supervisord -c $goodcrypto_oce_tools/supervisord.crypto.conf
    sudo -u goodcrypto /usr/local/bin/supervisord -c $goodcrypto_mail_tools/supervisord.message.conf
    sudo -u goodcrypto /usr/local/bin/supervisord -c $goodcrypto_mail_tools/supervisord.bundle.conf
}

function stop() {
    # remove any jobs that were in rq but didn't finish
    sudo -u goodcrypto python3 $goodcrypto_mail_tools/clear_failed_mail_queues.py
    sudo -u goodcrypto python3 $goodcrypto_oce_tools/clear_failed_crypto_queue.py GPG

    # remove the redis files
    rm -fr $goodcrypto_server/data/redis/*

    killmatch supervisord.special.conf
    killmatch supervisord.message.conf
    killmatch supervisord.gpg.conf
    killmatch supervisord.crypto.conf
    killmatch supervisord.bundle.conf
    sudoifnot goodcrypto killmatch supervisord &>/dev/null
    sudoifnot goodcrypto killmatch rqworker
    killmatch redis
}

function restart() {
    stop
    start
}

function status() {
    if (psgrep rqworker > /dev/nul) ; then
        echo "goodcrypto mail is running"
        true
    else
        echo "goodcrypto mail is not running"
        false
    fi
}

function usage() {
    echo "usage: goodcrypto-mail [start | stop | restart | status]"
}


command=$1
shift

case $command in

    start)
        start "$@"
        ;;

    stop)
        stop "$@"
        ;;

    restart)
        restart "$@"
        ;;

    status)
        status "$@"
        ;;

    *)
        usage
        ;;

esac

