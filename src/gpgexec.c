#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#include "gpgsetup.h"

int decrypt_blob(int fd, const struct gpgsetup_config *conf, struct gpgsetup_blob *blob)
{
	int pipes[2];
	if (pipe(pipes)) {
		fprintf(stderr, "failed to open pipe: %m\n");
		return -1;
	}
	pid_t chld = fork();
	if (chld == -1) {
		fprintf(stderr, "failed to fork: %m\n");
		return -1;
	}

	if (!chld) {
		dup2(fd, 0);
		dup2(pipes[1], 1);
		close(fd);
		close(pipes[0]);
		close(pipes[1]);
		if (!(conf->flags & CONFIG_GSTDERR)) {
			int nullfd = open("/dev/null", O_WRONLY);
			if (nullfd != -1) {
				dup2(nullfd, 2);
				close(nullfd);
			}
		}

		/*
		 * gpg
		 * --homedir [homedir]
		 * --decrypt
		 * NULL
		 */
		char *argv[5];
		int pos = 0;
		argv[pos++] = "gpg";
		if (conf->homedir) {
			argv[pos++] = "--homedir";
			argv[pos++] = conf->homedir;
		}
		argv[pos++] = "--decrypt";
		argv[pos++] = NULL;

		execvp("gpg", argv);
		exit(255);

	}
	close(pipes[1]);
	int wstatus;
	waitpid(chld, &wstatus, 0);
	if (!WIFEXITED(wstatus)) {
		fprintf(stderr, "gpg exited abnormally\n");
		close(pipes[0]);
		return -1;
	}
	int estatus = WEXITSTATUS(wstatus);
	if (estatus) {
		fprintf(stderr, "gpg exited with code %d\n", estatus);
		close(pipes[0]);
		return -1;
	}
	FILE *fp = fdopen(pipes[0], "r");
	if (!fp) {
		fprintf(stderr, "failed to allocate memory (fdopen): %m\n");
		close(pipes[0]);
		return -1;
	}
	estatus = read_config_file(fp, blob_callback, blob);
	fclose(fp);
	return estatus;
}

int encrypt_blob(int fd, const struct gpgsetup_config *conf, const struct gpgsetup_blob *blob)
{
	int pipes[2];
	if (pipe(pipes)) {
		fprintf(stderr, "failed to open pipe: %m\n");
		return -1;
	}
	pid_t chld = fork();
	if (chld == -1) {
		fprintf(stderr, "failed to fork: %m\n");
		return -1;
	}

	if (!chld) {
		dup2(fd, 1);
		dup2(pipes[0], 0);
		close(fd);
		close(pipes[0]);
		close(pipes[1]);
		if (!(conf->flags & CONFIG_GSTDERR)) {
			int nullfd = open("/dev/null", O_WRONLY);
			if (nullfd != -1) {
				dup2(nullfd, 2);
				close(nullfd);
			}
		}

		/*
		 * gpg
		 * --homedir [homedir]
		 * --recipient [recipient]
		 * --armour
		 * --encrypt
		 * NULL
		 */
		char *argv[8];
		int pos = 0;
		argv[pos++] = "gpg";
		if (conf->homedir) {
			argv[pos++] = "--homedir";
			argv[pos++] = conf->homedir;
		}
		if (conf->recipient) {
			argv[pos++] = "--recipient";
			argv[pos++] = conf->recipient;
		} else {
			argv[pos++] = "--default-recipient-self";
		}
		if (conf->flags & CONFIG_ARMOUR)
			argv[pos++] = "--armour";
		argv[pos++] = "--encrypt";
		argv[pos++] = NULL;

		execvp("gpg", argv);
		exit(255);
	}
	close(pipes[0]);

	FILE *fp = fdopen(pipes[1], "w");
	if (!fp) {
		fprintf(stderr, "failed to allocate memory (fdopen): %m\n");
		close(pipes[1]);
		kill(chld, SIGTERM);
		waitpid(chld, NULL, 0);
		return -1;
	}
	// TODO Fails?
	print_blob(blob, fp, 1);
	if (ferror(fp)) {
		fprintf(stderr, "failed to print blob (fdopen): %m\n");
		fclose(fp);
		kill(chld, SIGTERM);
		waitpid(chld, NULL, 0);
		return -1;
	}
	fclose(fp);
	int wstatus;
	waitpid(chld, &wstatus, 0);
	if (!WIFEXITED(wstatus)) {
		fprintf(stderr, "gpg exited abnormally\n");
		return -1;
	}
	int estatus = WEXITSTATUS(wstatus);
	if (estatus) {
		fprintf(stderr, "gpg exited with code %d\n", estatus);
		return -1;
	}
	return 0;
}
