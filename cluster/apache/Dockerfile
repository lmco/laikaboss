FROM httpd:2.4

COPY proxy-laikaboss.conf /usr/local/apache2/conf/extra/proxy-laikaboss.conf

RUN sed -i \
        -e 's/^#\(Include .*httpd-ssl.conf\)/\1/' \
        -e 's/^#\(LoadModule .*mod_ssl.so\)/\1/' \
        -e 's/^#\(LoadModule .*mod_socache_shmcb.so\)/\1/' \
        -e "\$aInclude conf\/extra\/proxy-laikaboss.conf" \
        conf/httpd.conf

RUN sed -i \
        -e 's/^#\(SSLCertificateChainFile .*server-ca.crt"\)/\1/' \
        conf/extra/httpd-ssl.conf
