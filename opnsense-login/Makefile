PROG=	opnsense-login
MAN=	opnsense-login.8

WARNS=	6

LDADD+=	-lpam

LOCALBASE?=${DESTDIR}/usr/local
PREFIX?=${LOCALBASE}

BINDIR=	${PREFIX}/sbin
MANDIR=	${PREFIX}/man/man

.include <bsd.prog.mk>
