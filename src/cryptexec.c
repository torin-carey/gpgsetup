#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "gpgsetup.h"
#include "parse.h"
#include "util.h"

#ifdef LIBCRYPTSETUP

#include <libcryptsetup.h>
#include <string.h>
#include <errno.h>

// This code is from libcryptsetup, replace it when possible
static int crypt_parse_name_and_mode(const char *s, char *cipher, int *key_nums, char *cipher_mode)
{
	if (!s || !cipher || !cipher_mode)
		return -EINVAL;

	if (sscanf(s, "%31[^-]-%31s",
		   cipher, cipher_mode) == 2) {
		if (!strcmp(cipher_mode, "plain"))
			strcpy(cipher_mode, "cbc-plain");
		if (key_nums) {
			char *tmp = strchr(cipher, ':');
			*key_nums = tmp ? atoi(++tmp) : 1;
			if (!*key_nums)
				return -EINVAL;
		}

		return 0;
	}

	/* Short version for "empty" cipher */
	if (!strcmp(s, "null") || !strcmp(s, "cipher_null")) {
		strcpy(cipher, "cipher_null");
		strcpy(cipher_mode, "ecb");
		if (key_nums)
			*key_nums = 0;
		return 0;
	}

	if (sscanf(s, "%31[^-]", cipher) == 1) {
		strcpy(cipher_mode, "cbc-plain");
		if (key_nums)
			*key_nums = 1;
		return 0;
	}

	return -EINVAL;
}

int open_cryptdev(const struct gpgsetup_config *conf, const struct gpgsetup_blob *blob, char *name)
{
	(void)conf;
	int r;

	struct crypt_device *cd;
	struct crypt_params_plain params = {
		.hash = "plain",
		.offset = blob->offset,
		.skip = blob->skip,
		.size = 0,
		.sector_size = 0,
	};

	r = crypt_init(&cd, blob->dev);
	if (r < 0) {
		fprintf(stderr, "crypt_init() failed for %s\n", blob->dev);
		return r;
	}

	char cipher[32], mode[32];
	r = crypt_parse_name_and_mode(blob->cipher ? blob->cipher : "aes-xts-plain64",
			cipher, NULL, mode);
	if (r) {
		fprintf(stderr, "crypt_parse_name_and_mode() failed on %s\n", blob->cipher);
		goto free_crypt;
	}

	r = crypt_format(cd, CRYPT_PLAIN, cipher, mode, NULL, NULL, blob->key_len, &params);
	if (r < 0) {
		fputs("crypt_format() failed\n", stderr);
		goto free_crypt;
	}

	r = crypt_activate_by_passphrase(cd, name, CRYPT_ANY_SLOT, (const char *)blob->key,
			blob->key_len, 0);

	if (r < 0) {
		fputs("crypt_activate_by_passphrase() failed\n", stderr);
		goto free_crypt;
	}

	r = 0;

free_crypt:
	crypt_free(cd);
	return r;
}

int close_cryptdev(const struct gpgsetup_config *conf, char *name)
{
	(void)conf;
	struct crypt_device *cd;
	int r;

	r = crypt_init_by_name(&cd, name);
	if (r < 0) {
		fprintf(stderr, "could not find mapping %s\n", name);
		return r;
	}

	int flags = 0;
	if (conf->flags & CONFIG_DEFER)
		flags |= CRYPT_DEACTIVATE_DEFERRED;
	else if (conf->flags & CONFIG_FORCE)
		flags |= CRYPT_DEACTIVATE_FORCE;

	r = crypt_deactivate_by_name(cd, name, flags);

	if (r < 0) {
		fputs("crypt_deactivate_by_name() failed\n", stderr);
	}

	crypt_free(cd);
	return r;
}

#else // LIBCRYPTSETUP

#ifndef CRYPTSETUP_BIN
#define CRYPTSETUP_BIN "/sbin/cryptsetup"
#endif

int open_cryptdev(const struct gpgsetup_config *conf, const struct gpgsetup_blob *blob, char *name)
{
	(void)conf;
	// cryptsetup open --type plain DEV NAME --key-file --cipher CIPHER
	// --key-size LEN --offset OFFSET --skip SKIP
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
	// cryptsetup close name --deferred
	char *argv[5] = {CRYPTSETUP_BIN, "close", name};
	int pos = 3;
	if (conf->specified & CONFIG_DEFER)
		argv[pos++] = "--deferred";
	else if (conf->specified & CONFIG_FORCE)
		fputs("cryptsetup does not supply a force flag, ignoring...\n", stderr);
	argv[pos] = NULL;
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

#endif // LIBCRYPTSETUP
