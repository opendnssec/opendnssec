/*
 * Copyright (c) 2014-2018 NLNet Labs
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "log.h"
#include "file.h"
#include "str.h"

#include "clientpipe.h"

/**
 * Create a message header
 * \param buf: buffer to write in, MUST be at least 3 octets.
 * \param opc: type of message
 * \param datalen: length of payload, MUST be in range 0..2^16-1
 * */
static void
header(char *buf, enum msg_type opc, uint16_t datalen) {
	assert(buf);
	buf[0] = opc;

	/* Do a memcpy instead of a cast in order to not break memory alignment
	 * requirements on some targets. */
	datalen = htons(datalen);
	memcpy(&buf[1], &datalen, 2);
}

/* 1 on succes, 0 on fail */
int
client_exit(int sockfd, char exitcode)
{
	char ctrl[4];
	header(ctrl, CLIENT_OPC_EXIT, 1);
	ctrl[3] = exitcode;
	return (ods_writen(sockfd, ctrl, 4) != -1);
}

/* 1 on succes, 0 on fail */
static int
client_msg(int sockfd, char opc, const char *cmd, uint16_t count)
{
	char ctrl[3];
	if (sockfd == -1) return 0;
	header(ctrl, opc, count);
	if (ods_writen(sockfd, ctrl, 3) == -1)
		return 0;
	return (ods_writen(sockfd, cmd, (size_t)count) != -1);
}

int
client_stdin(int sockfd, const char *cmd, uint16_t count)
{
	return client_msg(sockfd, CLIENT_OPC_STDIN, cmd, count);
}
int
client_stdout(int sockfd, const char *cmd, uint16_t count)
{
	return client_msg(sockfd, CLIENT_OPC_STDOUT, cmd, count);
}
int
client_stderr(int sockfd, const char *cmd, uint16_t count)
{
	return client_msg(sockfd, CLIENT_OPC_STDERR, cmd, count);
}

int
client_printf(int sockfd, const char * format, ...)
{
	char buf[ODS_SE_MAXLINE];
	int msglen; /* len w/o \0 */
	va_list ap;

	va_start(ap, format);
		msglen = vsnprintf(buf, ODS_SE_MAXLINE, format, ap);
	va_end(ap);
	if (msglen < 0) {
		ods_log_error("Failed parsing vsnprintf format.");
		return 0;
	}

	if (msglen >= ODS_SE_MAXLINE) {
		ods_log_error("[file] vsnprintf buffer too small. "
			"Want to write %d bytes but only %d available.", 
			msglen+1, ODS_SE_MAXLINE);
		msglen = ODS_SE_MAXLINE;
	}
	return client_stdout(sockfd, buf, msglen);
}

int
client_printf_err(int sockfd, const char * format, ...)
{
	char buf[ODS_SE_MAXLINE];
	int msglen;
	va_list ap;

	va_start(ap, format);
		msglen = vsnprintf(buf, ODS_SE_MAXLINE, format, ap);
	va_end(ap);
	if (msglen < 0) {
		ods_log_error("Failed parsing vsnprintf format.");
		return 0;
	}

	if (msglen >= ODS_SE_MAXLINE) {
		ods_log_error("[file] vsnprintf buffer too small. "
			"Want to write %d bytes but only %d available.", 
			msglen+1, ODS_SE_MAXLINE);
		msglen = ODS_SE_MAXLINE;
	}
	return client_stderr(sockfd, buf, msglen);
}

/**
 * Combined error logging and writing to a file descriptor.
 *
 */
void 
ods_log_error_and_printf(int fd, const char *mod, const char *format, ...)
{
	va_list ap;
	char fmt[128];
    char buf[ODS_SE_MAXLINE];
	int ok;
	
	/* first perform the ods_log_error */
	ok = (snprintf(fmt, sizeof(fmt), "[%s] %s", mod, format) < (int)sizeof(fmt));
	if (!ok) {
		ods_log_error("snprintf buffer too small");
		client_printf_err(fd, "error: snprintf buffer too small\n"); 
		return;
	}
	va_start(ap, format);
	ods_log_verror(fmt, ap);
	va_end(ap);


	/* then perform the ods_printf */
	ok = (snprintf(fmt, sizeof(fmt), "error: %s\n", format) < (int)sizeof(fmt));
	if (!ok) {
		ods_log_error("snprintf buffer too small");
		client_printf_err(fd, "error: snprintf buffer too small\n"); 
		return;
	}
	
	va_start(ap, format);
	ok = (vsnprintf(buf, ODS_SE_MAXLINE, fmt,ap) < ODS_SE_MAXLINE);
	va_end(ap);
	if (!ok) {
		ods_log_error("vsnprintf buffer too small");
		client_printf_err(fd, "error: vsnprintf buffer too small\n"); 
		return;
	}
	client_printf(fd, "%s", buf); 
}

int
client_handleprompt(int sockfd)
{
	char data[ODS_SE_MAXLINE];
	int n = read(fileno(stdin), data, ODS_SE_MAXLINE);
	if (n == -1) return 0;
	if (n == 0) return 0;
	if (!client_stdin(sockfd, data, n)) return 0;
	return 1;
}
