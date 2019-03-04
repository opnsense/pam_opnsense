/*
 * Copyright (C) 2016 Deciso B.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <security/pam_appl.h>
#include <security/openpam.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *service = "opnsense-login";
static const char *user = "root";
static int quiet = 0;

static void
usage(void)
{
	fprintf(stderr, "usage: man opnsense-login\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	pam_handle_t *pamh = NULL;
	char pass[PASS_MAX + 1];
	struct pam_conv pamc;
	int pam_err, c;
        int fd = -1;

	while ((c = getopt(argc, argv, "h:qs:u:")) != -1) {
		switch (c) {
		case 'h': {
			const char *errstr = NULL;

			fd = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr) {
				/* ignore faulty value */
				fd = -1;
			}
			break;
		}
		case 'q':
			quiet = 1;
			break;
		case 's':
			service = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		usage();
		/* NOTREACHED */
	}

	if (fd != -1) {
		char *p;
		int b;

		b = read(fd, pass, sizeof(pass) - 1);
		if (b < 0) {
			if (!quiet) {
				fprintf(stderr, "File descriptor read "
				    "failed.\n");
			}
			exit(EXIT_FAILURE);
		}

		pass[b] = '\0';

		if ((p = strpbrk(pass, "\r\n")) != NULL) {
			*p = '\0';
		}
	}

	memset(&pamc, 0, sizeof(pamc));
	pamc.conv = &openpam_ttyconv;

	pam_err = pam_start(service, user, &pamc, &pamh);
	if (pam_err == PAM_SUCCESS) {
		if (fd != -1) {
			/* this could fail and falls through to interactive */
			pam_set_item(pamh, PAM_AUTHTOK, pass);
		}
		pam_err = pam_authenticate(pamh, 0);
		if (pam_err == PAM_SUCCESS) {
			pam_err = pam_acct_mgmt(pamh, 0);
			if (pam_err == PAM_SUCCESS && !quiet) {
				fprintf(stderr, "User %s successfully "
				    "authenticated for service %s\n",
				    user, service);
			}
		}
	}

	if (pam_err != PAM_SUCCESS && !quiet) {
		fprintf(stderr, "User %s NOT authenticated for service %s\n",
		    user, service);
	}

	if (pam_end(pamh, pam_err) != PAM_SUCCESS) {
		exit(EXIT_FAILURE);
	}

	return (pam_err != PAM_SUCCESS);
}
