#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "gpgsetup.h"
#include "parse.h"
#include "util.h"

#ifndef CRYPTSETUP_BIN
#define CRYPTSETUP_BIN "/sbin/cryptsetup"
#endif

int open_cryptdev(const struct gpgsetup_config *conf, const struct gpgsetup_blob *blob, char *name)
{
	(void)conf;
	// cryptsetup open --type plain DEV NAME --key-file --cipher CIPHER --key-size LEN --offset OFFSET --skip SKIP
	char *argv[19] = {CRYPTSETUP_BIN, "open", "--type", "plain", "--hash", "plain"};
	char keysize[8], offset[8], skip[8];
	int pos = 6;
	argv[pos++] = blob->dev;
	argv[pos++] = name;
	argv[pos++] = "--key-file";
	argv[pos++] = "-";
	argv[pos++] = "--cipher";
	argv[pos++] = blob->cipher;
	argv[pos++] = "--key-size";
	snprintf(keysize, sizeof(keysize), "%zu", blob->key_len * 8);
	argv[pos++] = keysize;
	if (blob->offset) {
		argv[pos++] = "--offset";
		snprintf(offset, sizeof(offset), "%zu", blob->offset);
		argv[pos++] = offset;
	}
	if (blob->skip) {
		argv[pos++] = "--skip";
		snprintf(skip, sizeof(skip), "%zu", blob->skip);
		argv[pos++] = skip;
	}
	argv[pos] = NULL;


	int pipes[2];
	if (pipe(pipes)) {
		perror("pipe");
		return -1;
	}

	pid_t chld = fork();
	if (!chld) {
		dup2(pipes[0], STDIN_FILENO);
		close(pipes[0]);
		close(pipes[1]);
		execv(argv[0], argv);
		exit(255);
	} else if (chld == -1) {
		perror("fork");
		close(pipes[0]);
		close(pipes[1]);
		return -1;
	}
	close(pipes[0]);

	ssize_t wr = full_write(pipes[1], blob->key, blob->key_len);
	if (wr == -1) {
		perror("write");
		close(pipes[1]);
		kill(chld, SIGTERM);
		waitpid(chld, NULL, 0);
		return -1;
	}
	if ((size_t)wr != blob->key_len) {
		fputs("failed to write to pipe\n", stderr);
		close(pipes[1]);
		kill(chld, SIGTERM);
		waitpid(chld, NULL, 0);
		return -1;
	}

	close(pipes[1]);

	int wstatus;
	// TODO: Fix ugly code
	waitpid(chld, &wstatus, 0);

	if (!WIFEXITED(wstatus)) {
		fputs("cryptsetup exited abnormally\n", stderr);
		return -1;
	}
	int status = WEXITSTATUS(wstatus);
	if (status) {
		fprintf(stderr, "cryptsetup exited with status %d\n", status);
		return -1;
	}
	return 0;
}

int close_cryptdev(const struct gpgsetup_config *conf, char *name)
{
	(void)conf;
	char *argv[] = {CRYPTSETUP_BIN, "close", name, NULL};
	pid_t chld = fork();
	if (!chld) {
		execv(argv[0], argv);
		exit(255);
	} else if (chld == -1) {
		perror("fork");
		return -1;
	}

	int wstatus;
	// TODO: Fix ugly code
	if (waitpid(chld, &wstatus, 0) == (pid_t)-1) {
		perror("waitpid");
		kill(chld, SIGTERM);
		return -1;
	}
	if (!WIFEXITED(wstatus)) {
		fputs("cryptsetup exited due to a signal\n", stderr);
		return -1;
	}
	int status = WEXITSTATUS(wstatus);
	if (status) {
		fprintf(stderr, "cryptsetup exited with status %d\n", status);
		return -1;
	}
	return 0;
}
