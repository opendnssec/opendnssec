#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "shared/log.h"
#include "shared/file.h"
#include "shared/str.h"

#include "clientpipe.h"

/**
 * Create a message header
 * \param buf: buffer to write in, must be at least 3 octets.
 * \param opc: type of message
 * \param datalen: length of payload
 * */
static void
header(char *buf, enum msg_type opc, int datalen) {
	buf[0] = opc;
	buf[1] = (datalen>>8) & 0xFF;
	buf[2] = datalen & 0xFF;
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
client_msg(int sockfd, char opc, const char *cmd, int count)
{
	char ctrl[3];
	header(ctrl, opc, count);
	if (ods_writen(sockfd, ctrl, 3) == -1)
		return 0;
	return (ods_writen(sockfd, cmd, count) != -1);
}

int
client_stdin(int sockfd, const char *cmd, int count)
{
	return client_msg(sockfd, CLIENT_OPC_STDIN, cmd, count);
}
int
client_stdout(int sockfd, const char *cmd, int count)
{
	return client_msg(sockfd, CLIENT_OPC_STDOUT, cmd, count);
}
int
client_stderr(int sockfd, const char *cmd, int count)
{
	return client_msg(sockfd, CLIENT_OPC_STDERR, cmd, count);
}
int
client_prompt(int sockfd, const char *cmd, int count)
{
	return client_msg(sockfd, CLIENT_OPC_PROMPT, cmd, count);
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

	if (msglen >= ODS_SE_MAXLINE) {
		ods_log_error("[file] vsnprintf buffer too small. "
			"Want to write %d bytes but only %d available.", 
			msglen+1, ODS_SE_MAXLINE);
		msglen = ODS_SE_MAXLINE;
	}
	return client_stderr(sockfd, buf, msglen);
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

/*  TODO: don't let it fail on partial read. */
int
client_prompt_user(int sockfd, char *question, char *answer)
{
	char buf[ODS_SE_MAXLINE];
	int n, datalen;
	
	if (!question) return 0;
	if (!client_prompt(sockfd, question, strlen(question))) return 0;
	n = read(sockfd, buf, ODS_SE_MAXLINE);
	if (n == 0) {
		ods_log_error("[clientpipe] client closed pipe before answering.");
		return 0;/* eof */
	} else if (n == -1) { /* Error */
		ods_log_error("[clientpipe] Error processing user input.");
		return 0;
	} else if (n > ODS_SE_MAXLINE) {
		ods_log_error("[clientpipe] User input exceeds buffer.");
		return 0;
	} else if (n < 3) {
		/* partial msg */
		ods_log_info("[clientpipe] partial message.");
		return 0;
	} else if (buf[0] != CLIENT_OPC_STDIN) {
		ods_log_info("[clientpipe] unhandled message.");
		return 0;
	}
	datalen = (buf[1]<<8) | (buf[2]&0xFF);
	if (datalen >= ODS_SE_MAXLINE) { /* leave an octet for /0 */
		ods_log_error("[clientpipe] message to big.");
		return 0;
	} else if (datalen+3 > n) {
		ods_log_info("[clientpipe] partial message.");
		return 0;
	}
	strncpy(answer, buf+3, datalen);
	answer[datalen] = 0;
	ods_str_trim(answer);
	return 1;
}
