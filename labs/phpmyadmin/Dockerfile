FROM phpmyadmin:latest

# PHP 8.4.26 mod_php ayarları — vulnerable sürüm
RUN echo "session.upload_progress.enabled = 1" >> /usr/local/etc/php/conf.d/php2shell-lab.ini && \
    echo "session.upload_progress.cleanup = 1" >> /usr/local/etc/php/conf.d/php2shell-lab.ini && \
    echo "memory_limit = 128M"                 >> /usr/local/etc/php/conf.d/php2shell-lab.ini && \
    echo "file_uploads = On"                   >> /usr/local/etc/php/conf.d/php2shell-lab.ini

EXPOSE 80
