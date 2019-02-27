FILES=	opnsense-login
DIR=	${PREFIX}/etc/pam.d

LOCALBASE?=${DESTDIR}/usr/local
PREFIX?=${LOCALBASE}

all:	# nothing to do
clean:	# nothing to do

upgrade: install

install:
	@cp -v ${FILES} ${DESTDIR}${PREFIX}${DIR}
