/*
 * Copyright (C) 2019 Deciso B.V.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *auth_cmd = "/usr/local/sbin/opnsense-auth";


/**
 * simple wrapper for our authentication script to allow root execution on opnsense-auth via the setuid bit
 * called from pam_opnsense.so as a stepping stone.
 * forwards all data received on stdin via popen
 */
int main()
{
	int ch;
	int script_response = 255;
	FILE *fp;
	FILE *fp_stdin;

	fp = popen(auth_cmd, "w");
	if (!fp) {
		exit(3);
	} else {
		fp_stdin = fdopen(STDIN_FILENO, "r");
		if (!fp_stdin) {
			exit(3);
		}
		if (fp_stdin == stdin && feof(stdin)) {
				clearerr(stdin);
		}
		while ((ch = getc(fp_stdin)) != EOF) {
				putc(ch, fp);
		}
		fclose(fp_stdin);
		script_response = pclose(fp);
	}

	return 0;
}
