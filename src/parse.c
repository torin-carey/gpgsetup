#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"

extern char **environ;

int read_config_file(FILE *file, config_entry callback, void *ptr)
{
	char *buf = NULL;
	size_t buflen = 0;
	ssize_t r;
	int ret = 0;
	while ((r = getline(&buf, &buflen, file)) != -1) {
		if (!*buf || *buf == '#')
			continue;
		char *eq = strchr(buf, '=');
		if (!eq)
			continue;
		*eq = '\0';
		if (buf[r - 1] == '\n')
			buf[--r] = '\0';
		if ((ret = callback(buf, eq + 1, ptr))) {
			free(buf);
			return ret;
		}
	}
	if (ferror(file)) {
		fprintf(stderr, "failed to read config: %m\n");
		free(buf);
		return -1;
	}
	free(buf);
	return ret;
}

int read_config_env(config_entry callback, void *ptr)
{
	int ret;
	for (int i = 0; environ[i]; i++) {
		char *eq = strchr(environ[i], '=');
		if (!eq)
			continue;
		char buf[eq - environ[i] + 1];
		memcpy(buf, environ[i], eq - environ[i]);
		buf[eq - environ[i]] = '\0';
		if ((ret = callback(buf, eq + 1, ptr)))
			return ret;
	}
	return 0;
}

int parse_bool(const char *value, int *flags, int bit)
{
	if (!strcasecmp(value, "true") || !strcasecmp(value, "yes")) {
		*flags |= bit;
		return 0;
	} else if (!strcasecmp(value, "false") || !strcasecmp(value, "no")) {
		*flags &= ~bit;
		return 0;
	}
	return -1;
}

int parse_long(const char *value, long *l)
{
	char *endptr;
	*l = strtol(value, &endptr, 0);
	return *endptr != '\0';
}

static inline int char_to_int(char c) {
	if ('0' <= c && c <= '9') {
		return c - '0';
	} else if ('a' <= c && c <= 'f') {
		return c + 10 - 'a';
	} else {
		return -1;
	}
}

int parse_hex(const char *value, unsigned char *dst, size_t len)
{
	int f, s;
	for (size_t i = 0; i < len; i+=2) {
		if ((f = char_to_int(value[i])) == -1 ||
				(s = char_to_int(value[i+1])) == -1) {
			fprintf(stderr, "bad hex: %s\n", value);
			return -1;
		}
		dst[i/2] = (f<<4) | s;
	}
	return 0;
}

int config_callback(const char *name, const char *value, void *ptr)
{
	struct gpgsetup_config *conf = ptr;
	char **wptr = NULL;
	long l;
	if (!strcmp(name, "RECIPIENT")) {
		wptr = &conf->recipient;
		conf->specified |= CONFIG_RECIPIENT;
	} else if (!strcmp(name, "HOMEDIR")) {
		wptr = &conf->homedir;
		conf->specified |= CONFIG_HOMEDIR;
	} else if (!strcmp(name, "MATERIALDIR")) {
		wptr = &conf->materialdir;
		conf->specified |= CONFIG_MATERIAL;
	} else if (!strcmp(name, "TMP")) {
		wptr = &conf->tmp;
		conf->specified |= CONFIG_TMP;
	} else if (!strcmp(name, "ARMOUR")) {
		if (parse_bool(value, &conf->flags, CONFIG_ARMOUR)) {
			fprintf(stderr, "failed to parse \"%s\", invalid bool\n",
				name);
		}
		conf->specified |= CONFIG_ARMOUR;
		return 0;
	} else if (!strcmp(name, "KEYSIZE")) {
		if (parse_long(value, &l)) {
			fprintf(stderr, "failed to parse \"%s\", invalid int\n",
				name);
		} else {
			conf->keysize = l;
		}
		conf->specified |= CONFIG_KEYSIZE;
		return 0;
	} else if (!strcmp(name, "GPGSTDERR")) {
		if (parse_bool(value, &conf->flags, CONFIG_GSTDERR)) {
			fprintf(stderr, "failed to parse \"%s\", invalid bool\n",
				name);
		}
		conf->specified |= CONFIG_GSTDERR;
		return 0;
	} else if (!strcmp(name, "VERBOSE")) {
		if (parse_bool(value, &conf->flags, CONFIG_VERBOSE)) {
			fprintf(stderr, "failed to parse \"%s\", invalid bool\n",
				name);
		}
		conf->specified |= CONFIG_VERBOSE;
		return 0;
	} else if (!strcmp(name, "FORCE")) {
		if (parse_bool(value, &conf->flags, CONFIG_FORCE)) {
			fprintf(stderr, "failed to parse \"%s\", invalid bool\n",
				name);
		}
		conf->specified |= CONFIG_FORCE;
		return 0;
	}
	// TODO Do we really need this?
	if (wptr) {
		size_t len = strlen(value);
		if (len == 0) {
			*wptr = NULL;
			return 0;
		}
		char *buf = malloc(len + 1);
		if (!buf) {
			fprintf(stderr, "failed to allocate memory: %m\n");
			return -1;
		}
		strcpy(buf, value);
		*wptr = buf;
	}
	return 0;
}

int blob_callback(const char *name, const char *value, void *ptr)
{
	struct gpgsetup_blob *const blob = ptr;
	char **wptr = NULL;
	long l;
	if (!strcmp(name, "DEV")) {
		wptr = &blob->dev;
		blob->specified |= BLOB_DEV;
		blob->alloc |= BLOB_DEV;
	} else if (!strcmp(name, "CIPHER")) {
		wptr = &blob->cipher;
		blob->specified |= BLOB_CIPHER;
		blob->alloc |= BLOB_CIPHER;
	} else if (!strcmp(name, "HASH")) {
		wptr = &blob->hash;
		blob->specified |= BLOB_HASH;
		blob->alloc |= BLOB_HASH;
	} else if (!strcmp(name, "POSTADD")) {
		wptr = &blob->postadd;
		blob->specified |= BLOB_POSTADD;
		blob->alloc |= BLOB_POSTADD;
	} else if (!strcmp(name, "PRERM")) {
		wptr = &blob->prerm;
		blob->specified |= BLOB_PRERM;
		blob->alloc |= BLOB_PRERM;
	} else if (!strcmp(name, "KEY")) {
		size_t len = strlen(value);
		if (len & 1) {
			fprintf(stderr, "invalid hex length: %s (%zu)\n", name, len);
		}
		unsigned char *key = malloc(len / 2);
		if (!key) {
			fprintf(stderr, "failed to allocate memory: %m\n");
			return -1;
		}
		if (parse_hex(value, key, len)) {
			// Bad key
			return -1;
		}
		blob->key = key;
		blob->key_len = len / 2;
		blob->specified |= BLOB_KEY;
		return 0;
	} else if (!strcmp(name, "OFFSET")) {
		if (parse_long(value, &l)) {
			fprintf(stderr, "failed to parse \"%s\", invalid int\n",
				name);
		} else {
			blob->offset = l;
		}
		blob->specified |= BLOB_OFFSET;
		return 0;
	} else if (!strcmp(name, "SKIP")) {
		if (parse_long(value, &l)) {
			fprintf(stderr, "failed to parse \"%s\", invalid int\n",
				name);
		} else {
			blob->skip = l;
		}
		blob->specified |= BLOB_SKIP;
		return 0;
	}
	// TODO Do we really need this?
	if (wptr) {
		size_t len = strlen(value);
		if (len == 0) {
			*wptr = NULL;
			return 0;
		}
		char *buf = malloc(len + 1);
		if (!buf) {
			fprintf(stderr, "failed to allocate memory: %m\n");
			return -1;
		}
		strcpy(buf, value);
		*wptr = buf;
	}
	return 0;
}

void print_config(const struct gpgsetup_config *conf, FILE *stream)
{
	flockfile(stream);
	if (conf->specified & CONFIG_RECIPIENT)
		fprintf(stream, "RECIPIENT=%s\n",
			conf->recipient ? conf->recipient : "");
	if (conf->specified & CONFIG_HOMEDIR)
		fprintf(stream, "HOMEDIR=%s\n",
			conf->homedir ? conf->homedir : "");
	if (conf->specified & CONFIG_MATERIAL)
		fprintf(stream, "MATERIALDIR=%s\n",
			conf->materialdir ? conf->materialdir : "");
	if (conf->specified & CONFIG_TMP)
		fprintf(stream, "TMP=%s\n", conf->tmp ? conf->tmp : "");
	if (conf->specified & CONFIG_TEMPLATE)
		fprintf(stream, "TEMPLATE=%s\n",
			conf->templ ? conf->templ : "");
	if (conf->specified & CONFIG_ARMOUR)
		fprintf(stream, "ARMOUR=%s\n",
			conf->flags & CONFIG_ARMOUR ? "yes" : "no");
	if (conf->specified & CONFIG_KEYSIZE)
		fprintf(stream, "KEYSIZE=%zu\n", conf->keysize);
	if (conf->specified & CONFIG_GSTDERR)
		fprintf(stream, "GPGSTDERR=%s\n",
			conf->flags & CONFIG_GSTDERR ? "yes" : "no");
	if (conf->specified & CONFIG_GSTDERR)
		fprintf(stream, "VERBOSE=%s\n",
			conf->flags & CONFIG_VERBOSE ? "yes" : "no");
	if (conf->specified & CONFIG_FORCE)
		fprintf(stream, "FORCE=%s\n",
			conf->flags & CONFIG_FORCE ? "yes" : "no");
	if (conf->specified & CONFIG_TMP)
		fprintf(stream, "TMP=%s\n", conf->tmp ? conf->tmp : "");
	funlockfile(stream);
}

void print_blob(const struct gpgsetup_blob *blob, FILE *stream, int showkey)
{
	flockfile(stream);
	if (blob->specified & BLOB_DEV)
		fprintf(stream, "DEV=%s\n",
			blob->dev ? blob->dev : "");
	if (blob->specified & BLOB_CIPHER)
		fprintf(stream, "CIPHER=%s\n",
			blob->cipher ? blob->cipher : "");
	if (blob->specified & BLOB_HASH)
		fprintf(stream, "HASH=%s\n",
			blob->hash ? blob->hash : "");
	if (blob->specified & BLOB_POSTADD)
		fprintf(stream, "POSTADD=%s\n",
			blob->postadd ? blob->postadd : "");
	if (blob->specified & BLOB_PRERM)
		fprintf(stream, "PRERM=%s\n",
			blob->prerm ? blob->prerm : "");
	if (showkey && (blob->specified & BLOB_KEY)) {
		fputs("KEY=", stream);
		for (size_t i = 0; i < blob->key_len; i++) {
			fprintf(stream, "%02x", blob->key[i]);
		}
		putc('\n', stream);
	}
	if (blob->specified & BLOB_OFFSET)
		fprintf(stream, "OFFSET=%zu\n", blob->offset);
	if (blob->specified & BLOB_SKIP)
		fprintf(stream, "SKIP=%zu\n", blob->skip);
	funlockfile(stream);
}

#define TRANSFER_FREE(dst, src, param, bit) if (src->specified & bit) { \
	if (dst->alloc & bit) \
		free(dst->param); \
	dst->param = src->param; \
}

#define TRANSFER_PRIMITIVE(dst, src, param, bit) if (src->specified & bit) { \
	dst->param = src->param; \
}

void apply_config_left(struct gpgsetup_config *dst, struct gpgsetup_config *src)
{
	TRANSFER_FREE(dst, src, recipient, CONFIG_RECIPIENT);
	TRANSFER_FREE(dst, src, homedir, CONFIG_HOMEDIR);
	TRANSFER_FREE(dst, src, materialdir, CONFIG_MATERIAL);
	TRANSFER_FREE(dst, src, tmp, CONFIG_TMP);
	TRANSFER_FREE(dst, src, templ, CONFIG_TEMPLATE);
	TRANSFER_PRIMITIVE(dst, src, keysize, CONFIG_KEYSIZE);
	dst->flags &= ~src->specified;
	dst->flags |= src->specified & src->flags;
	dst->specified |= src->specified;
	dst->alloc &= ~src->specified;
	dst->alloc |= src->alloc & src->specified;
	src->alloc &= ~src->specified;
}

void apply_config_right(struct gpgsetup_config *dst, struct gpgsetup_config *src)
{
	TRANSFER_FREE(dst, src, recipient, CONFIG_RECIPIENT);
	TRANSFER_FREE(dst, src, homedir, CONFIG_HOMEDIR);
	TRANSFER_FREE(dst, src, materialdir, CONFIG_MATERIAL);
	TRANSFER_FREE(dst, src, tmp, CONFIG_TMP);
	TRANSFER_FREE(dst, src, templ, CONFIG_TEMPLATE);
	TRANSFER_PRIMITIVE(dst, src, keysize, CONFIG_KEYSIZE);
	dst->flags &= ~src->specified;
	dst->flags |= src->specified & src->flags;
	dst->specified |= src->specified;
	dst->alloc &= ~src->specified;
}

void apply_blob_left(struct gpgsetup_blob *dst, struct gpgsetup_blob *src)
{
	TRANSFER_FREE(dst, src, dev, BLOB_DEV);
	TRANSFER_FREE(dst, src, cipher, BLOB_CIPHER);
	TRANSFER_FREE(dst, src, hash, BLOB_HASH);
	TRANSFER_FREE(dst, src, postadd, BLOB_POSTADD);
	TRANSFER_FREE(dst, src, prerm, BLOB_PRERM);
	TRANSFER_FREE(dst, src, key, BLOB_KEY);
	TRANSFER_PRIMITIVE(dst, src, key_len, BLOB_KEY);
	TRANSFER_PRIMITIVE(dst, src, offset, BLOB_OFFSET);
	TRANSFER_PRIMITIVE(dst, src, skip, BLOB_SKIP);
	dst->specified |= src->specified;
	dst->alloc &= ~src->specified;
	dst->alloc |= src->alloc & src->specified;
	src->alloc &= ~src->specified;
}

void apply_blob_right(struct gpgsetup_blob *dst, struct gpgsetup_blob *src)
{
	TRANSFER_FREE(dst, src, dev, BLOB_DEV);
	TRANSFER_FREE(dst, src, cipher, BLOB_CIPHER);
	TRANSFER_FREE(dst, src, hash, BLOB_HASH);
	TRANSFER_FREE(dst, src, postadd, BLOB_POSTADD);
	TRANSFER_FREE(dst, src, prerm, BLOB_PRERM);
	TRANSFER_FREE(dst, src, key, BLOB_KEY);
	TRANSFER_PRIMITIVE(dst, src, key_len, BLOB_KEY);
	TRANSFER_PRIMITIVE(dst, src, offset, BLOB_OFFSET);
	TRANSFER_PRIMITIVE(dst, src, skip, BLOB_SKIP);
	dst->specified |= src->specified;
	dst->alloc &= ~src->specified;
}

void init_config(struct gpgsetup_config *conf)
{
	static const struct gpgsetup_config defaults = GPGSETUP_CONF_INITIALISER;
	conf->recipient = defaults.recipient;
	conf->homedir = defaults.homedir;
	conf->materialdir = defaults.materialdir;
	conf->tmp = defaults.tmp;
	conf->keysize = defaults.keysize;
	conf->flags = defaults.flags;
	conf->specified = 0;
	conf->alloc = 0;
}

void init_blob(struct gpgsetup_blob *blob)
{
	static const struct gpgsetup_blob defaults = GPGSETUP_BLOB_INITIALISER;
	blob->dev = defaults.dev;
	blob->cipher = defaults.cipher;
	blob->hash = defaults.hash;
	blob->postadd = defaults.postadd;
	blob->prerm = defaults.prerm;
	blob->key = NULL;
	blob->key_len = 0;
	blob->offset = defaults.offset;
	blob->skip = defaults.skip;
	blob->specified = 0;
	blob->alloc = 0;
}

#define FREE_ALLOC(obj, param, bit) if (obj->alloc & bit) { \
	free(obj->param); \
}

void free_config(struct gpgsetup_config *conf)
{
	FREE_ALLOC(conf, recipient, CONFIG_RECIPIENT);
	FREE_ALLOC(conf, homedir, CONFIG_HOMEDIR);
	FREE_ALLOC(conf, materialdir, CONFIG_MATERIAL);
	FREE_ALLOC(conf, tmp, CONFIG_TMP);
	FREE_ALLOC(conf, templ, CONFIG_TEMPLATE);
	conf->alloc = 0;
}

void free_blob(struct gpgsetup_blob *blob)
{
	FREE_ALLOC(blob, dev, BLOB_DEV);
	FREE_ALLOC(blob, cipher, BLOB_CIPHER);
	FREE_ALLOC(blob, hash, BLOB_HASH);
	FREE_ALLOC(blob, postadd, BLOB_POSTADD);
	FREE_ALLOC(blob, prerm, BLOB_PRERM);
	FREE_ALLOC(blob, key, BLOB_KEY);
	blob->alloc = 0;
}
