LIB=	pam_opnsense
SRCS=	${LIB}.c

SHLIB_NAME=${LIB}.so

WARNS=	3

LDADD+=	-lpam

LOCALBASE?=${DESTDIR}/usr/local
PREFIX?=${LOCALBASE}

LIBDIR=	${PREFIX}/lib

.include <bsd.lib.mk>
