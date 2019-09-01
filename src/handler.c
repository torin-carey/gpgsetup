#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/random.h>

#include "gpgsetup.h"
#include "gpgexec.h"
#include "cryptexec.h"
#include "util.h"

void main_log(int level, const char *msg);
static int write_blob(struct gpgsetup_config *conf, struct gpgsetup_param *param);

int handle_mode_list(struct gpgsetup_config *conf, struct gpgsetup_param *param)
{
	(void)param;
	DIR *dir;
	struct dirent *ent;
	dir = opendir(conf->materialdir);
	if (!dir) {
		fprintf(stderr, "failed to open directory %s: %m\n",
				conf->materialdir);
		return -1;
	}

	errno = 0;
	while ((ent = readdir(dir))) {
		// This doesn't address the entry being a link to something bad
		if (ent->d_type != DT_REG && ent->d_type != DT_LNK)
			continue;
		size_t len = strlen(ent->d_name);
		// Must be more than 4 characters (".gpg")
		if (len <= 4)
			continue;
		// Must end in .gpg "a.gpg"
		if (memcmp(ent->d_name + len - 4, ".gpg", 4))
			continue;
		// Potential candidate
		ent->d_name[len - 4] = '\0';
		puts(ent->d_name);
		errno = 0;
	}
	if (errno) {
		fprintf(stderr, "error reading directory: %m\n");
		closedir(dir);
		return -1;
	}
	closedir(dir);
	return 0;
}

int handle_mode_open(struct gpgsetup_config *conf, struct gpgsetup_param *param)
{
	struct gpgsetup_blob blob = GPGSETUP_BLOB_INITIALISER;
	char path[PATH_MAX];
	snprintf(path, PATH_MAX, "%s/%s.gpg", conf->materialdir, param->name);
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		switch (errno) {
		case ENOENT:
			fprintf(stderr, "device %s does not exist\n", param->name);
			break;
		case EPERM:
			fprintf(stderr, "permission denied opening %s\n", param->name);
			break;
		default:
			perror("open");
		}
		return -1;
	}

	if (decrypt_blob(fd, conf, &blob)) {
		close(fd);
		return -1;
	}
	close(fd);

	int ret = 0;

	if (!blob.dev) {
		fputs("blob is missing the 'dev' parameter\n", stderr);
		fprintf(stderr, "update with `gpgsetup update %s --device [DEVICE]`\n", param->name);
		ret = -1;
	}
	if (!blob.cipher) {
		fputs("blob is missing the 'cipher' parameter\n", stderr);
		ret = -1;
	}
	if (!blob.key) {
		fputs("blob is missing the 'key' parameter\n", stderr);
		ret = -1;
	}
	if (ret) {
		free_blob(&blob);
		return ret;
	}

	ret = open_cryptdev(conf, &blob, param->name);
	if (ret) {
		free_blob(&blob);
		return ret;
	}

	// Lets see if we can create a tmpfile
	unsigned int old_specified = blob.specified;
	snprintf(path, PATH_MAX, "%s/.gpgsetup.%s", conf->tmp, param->name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		perror("failed to create tmpfile (open)");
		free_blob(&blob);
		return 1;
	}
	FILE *fp = fdopen(fd, "w");
	if (!fp) {
		perror("failed to create tmpfile (fdopen)");
		close(fd);
		free_blob(&blob);
		return 1;
	}
	blob.specified &= BLOB_PRERM;

	print_blob(&blob, fp, 0);
	fclose(fp);
	blob.specified = old_specified;

	if (blob.postadd) {
		fprintf(stderr, "+%s\n", blob.postadd);
		fflush(stderr);
		int estatus = system(blob.postadd);

		if (estatus) {
			fprintf(stderr, "postadd exited with status %d\n", estatus);
			free_blob(&blob);
			return -1;
		}
	}

	free_blob(&blob);
	return 0;
}

int handle_mode_close(struct gpgsetup_config *conf, struct gpgsetup_param *param)
{
	struct gpgsetup_blob blob = GPGSETUP_BLOB_INITIALISER;
	char path[PATH_MAX];
	snprintf(path, PATH_MAX, "%s/.gpgsetup.%s", conf->tmp, param->name);
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		switch (errno) {
		case ENOENT:
			fputs("warning: failed to find tmpfile\n", stderr);
			break;
		case EPERM:
			fputs("permission denied opening tmpfile\n", stderr);
			return -1;
		default:
			perror("open");
			return -1;
		}
	} else {
		FILE *fp = fdopen(fd, "r");
		if (!fp) {
			perror("warning: failed to open tmpfile");
			close(fd);
		} else {
			read_config_file(fp, blob_callback, &blob);
			fclose(fp);
		}
	}

	if (blob.prerm) {
		fprintf(stderr, "+%s\n", blob.prerm);
		fflush(stderr);
		int estatus = system(blob.prerm);

		if (estatus && !(conf->flags & CONFIG_FORCE)) {
			fprintf(stderr, "prerm exited with status %d\n", estatus);
			free_blob(&blob);
			return -1;
		} else if (estatus) {
			fprintf(stderr, "prerm exited with status %d, forcing close...\n", estatus);
		}
	}
	free_blob(&blob);
	unlink(path);

	return close_cryptdev(conf, param->name);
}

int handle_mode_generate(struct gpgsetup_config *conf, struct gpgsetup_param *param)
{
	//TODO: Check key size
	struct gpgsetup_blob *const blob = param->blob;
	blob->key = malloc(conf->keysize);
	if (!blob->key) {
		perror("failed to allocate key");
		return -1;
	}
	blob->key_len = conf->keysize;
	blob->specified |= BLOB_KEY | BLOB_EXPORTS;
	blob->alloc |= BLOB_KEY;
	//TODO: Check fail
	if (getrandom(blob->key, blob->key_len, 0) != (ssize_t)blob->key_len) {
		fprintf(stderr, "failed to generate key: %m\n");
		return -1;
	}
	return write_blob(conf, param);
}

static int write_blob(struct gpgsetup_config *conf, struct gpgsetup_param *param)
{
	char path[PATH_MAX];
	snprintf(path, PATH_MAX, "%s/%s.gpg", conf->materialdir, param->name);
	int blobfd = open(path, O_WRONLY | O_CREAT |
		(conf->flags & CONFIG_FORCE ? O_TRUNC : O_EXCL), 0600);
	if (blobfd == -1) {
		switch (errno) {
		case EEXIST:
			fprintf(stderr, "device %s already exists, "
					"refusing to overwrite\n", param->name);
			break;
		case EACCES:
		case EPERM:
		case EROFS:
			fprintf(stderr, "failed to write to directory %s: %m\n",
					conf->materialdir);
			break;
		default:
			perror("open");
		}
		return -1;
	}
	if (encrypt_blob(blobfd, conf, param->blob)) {
		close(blobfd);
	}
	return 0;
}


int handle_mode_update(struct gpgsetup_config *conf, struct gpgsetup_param *param)
{
	struct gpgsetup_blob blob = GPGSETUP_BLOB_INITIALISER;
	char path[PATH_MAX], tmppath[PATH_MAX];
	snprintf(path, PATH_MAX, "%s/%s.gpg", conf->materialdir, param->name);
	snprintf(tmppath, PATH_MAX, "%s/.%s", conf->materialdir, param->name);
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		switch (fd) {
		case ENOENT:
			fprintf(stderr, "device %s does not exist\n", param->name);
			break;
		case EPERM:
			fprintf(stderr, "permission denied opening %s\n", param->name);
			break;
		default:
			perror("open");
		}
		return -1;
	}

	if (decrypt_blob(fd, conf, &blob)) {
		close(fd);
		return -1;
	}
	close(fd);

	apply_blob_right(&blob, param->blob);

	fd = open(tmppath, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -1) {
		switch (errno) {
		case EEXIST:
			fprintf(stderr, "device %s already exists, "
					"refusing to overwrite\n", param->name);
			break;
		case EACCES:
		case EPERM:
		case EROFS:
			fprintf(stderr, "failed to write to directory %s: %m\n",
					conf->materialdir);
			break;
		default:
			perror("open");
		}
		free_blob(&blob);
		return -1;
	}
	if (encrypt_blob(fd, conf, &blob)) {
		close(fd);
		free_blob(&blob);
	}
	close(fd);
	free_blob(&blob);

	if (rename(tmppath, path)) {
		perror("rename");
		unlink(tmppath);
		return -1;
	}

	return 0;
}

int handle_mode_show(struct gpgsetup_config *conf, struct gpgsetup_param *param)
{
	if (conf->flags & CONFIG_SHOWRAW) {
		fputs("the --show-raw flag currently isn't supported\n", stderr);
		return -1;
	}
	struct gpgsetup_blob blob = GPGSETUP_BLOB_INITIALISER;
	char path[PATH_MAX];
	snprintf(path, PATH_MAX, "%s/%s.gpg", conf->materialdir, param->name);
	int fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;
	if (decrypt_blob(fd, conf, &blob)) {
		close(fd);
		return -1;
	}
	close(fd);
	print_blob(&blob, stdout, conf->flags & CONFIG_SHOWKEY);
	return 0;
}

int handle_mode_create(struct gpgsetup_config *conf, struct gpgsetup_param *param)
{
	//struct gpgsetup_blob blob = GPGSETUP_BLOB_INITIALISER;
	int r = extract_from_luks(conf, param->blob, param->dev);
	if (r)
		return r;
	return write_blob(conf, param);
}
