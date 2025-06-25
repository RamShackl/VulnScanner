# Apache 2.4.49 - Vulnerable to CVE-2021-41773
FROM httpd:2.4.49

RUN echo 'Vulnerable Apache 2.4.49' > /usr/local/apache2/htdocs/index.html

# Ensure required modules and permissions are set
RUN sed -i '/mod_cgid.so/s/^#//g' /usr/local/apache2/conf/httpd.conf && \
    echo 'IncludeOptional conf/extra/httpd-default.conf' >> /usr/local/apache2/conf/httpd.conf && \
    echo 'Options Indexes FollowSymLinks' >> /usr/local/apache2/conf/httpd.conf && \
    echo 'Require all granted' >> /usr/local/apache2/conf/httpd.conf

EXPOSE 80
