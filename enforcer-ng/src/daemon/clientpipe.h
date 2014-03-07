#ifndef DAEMON_CLIENTPIPE_H
#define DAEMON_CLIENTPIPE_H

#ifdef __cplusplus
extern "C" {
#endif

int client_printf(int sockfd, const char * format, ...);
int client_printf_err(int sockfd, const char * format, ...);

/**
 * Client part of prompt handling
 * 
 * Block on stdin and send to daemon
 * 
 * \param sockfd, pipe to daemon.
 * \return 1 success, 0 error
 */
int client_handleprompt(int sockfd);

/**
 * Daemon part of prompt handling
 * 
 * Send question to client and block on getting an answer
 * 
 * \param sockfd, pipe to client
 * \param question, string to prompt the client with
 * \param[out] answer, client response
 * \return 0 on failure, 1 on success and answer will be set
 * 
 *  TODO: don't let it fail on partial read. */
int client_prompt_user(int sockfd, char *question, char *answer);

enum msg_type {
	CLIENT_OPC_STDOUT = 0, 
	CLIENT_OPC_STDERR, 
	CLIENT_OPC_STDIN, 
	CLIENT_OPC_PROMPT, 
	CLIENT_OPC_EXIT
};

/* 1 on succes, 0 on fail */
int client_exit(int sockfd, char exitcode);
int client_stdin(int sockfd, const char *cmd, int count);
int client_stdout(int sockfd, const char *cmd, int count);
int client_stderr(int sockfd, const char *cmd, int count);
int client_prompt(int sockfd, const char *cmd, int count);

#ifdef __cplusplus
}
#endif

#endif /* DAEMON_CLIENTPIPE_H */
