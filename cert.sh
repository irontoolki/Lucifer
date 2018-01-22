OPENSSL=/usr/bin/openssl
SSLDIR=/etc/cert/ssl
mkdir -p $SSLDIR || exit 1
rm -rf $SSLDIR/*
[ -e $SSLDIR/private.pem ] || $OPENSSL genrsa 4096 > $SSLDIR/private.pem
[ -e $SSLDIR/public.pem ] || (echo -e "US\nCalifornia\nTechnologis\nLucifer Inc\nLucifer\n*\nsupport@lucifer.com\n"| $OPENSSL req -new -x509 -days 3650 -key $SSLDIR/private.pem -out $SSLDIR/public.pem)
[ -e $SSLDIR/user.der ] || $OPENSSL x509 -in $SSLDIR/public.pem -outform DER -out $SSLDIR/user.der


SQUIDSSLCRTDDIR=/var/lib/ssl_db/
SSLCRTD=/etc/sq/libexec//ssl_crtd
$SSLCRTD -c -s $SQUIDSSLCRTDDIR
[ -d $SQUIDSSLCRTDDIR ] && chown proxy.proxy -R $SQUIDSSLCRTDDIR
