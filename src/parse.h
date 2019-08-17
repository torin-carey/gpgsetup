#ifndef H_GPGSETUP_PARSE
#define H_GPGSETUP_PARSE

#include <sys/types.h>
#include "defaults.h"

/*
 * If editing the config or blob structures, remember to update the apply_*
 * functions as well as the parsing/printing functions.
*/

typedef int (*config_entry)(const char *name, const char *value, void *ptr);

#define CONFIG_RECIPIENT 1
#define CONFIG_HOMEDIR (1<<1)
#define CONFIG_MATERIAL (1<<2)
#define CONFIG_TMP (1<3)
#define CONFIG_TEMPLATE (1<<4)
#define CONFIG_ARMOUR (1<<5)
#define CONFIG_KEYSIZE (1<<6)
#define CONFIG_GSTDERR (1<<7)
#define CONFIG_VERBOSE (1<<8)
#define CONFIG_SHOWKEY (1<<9) // This isn't handled by config_callback,
// since we want it to be an option that needs explicitly stated
#define CONFIG_SHOWRAW (1<<10)
#define CONFIG_FORCE (1<<11)
#define CONFIG_DEFER (1<<12)

struct gpgsetup_config {
	char *recipient, *homedir, *materialdir, *tmp, *templ;
	size_t keysize;
	int flags;
	unsigned int specified, alloc;
};

#define BLOB_DEV 1
#define BLOB_CIPHER (1<<1)
#define BLOB_HASH (1<<2)
#define BLOB_POSTADD (1<<3)
#define BLOB_PRERM (1<<4)
#define BLOB_KEY (1<<5)
#define BLOB_OFFSET (1<<6)
#define BLOB_SKIP (1<<7)

#define CONFIG_BOOL(confp, bit) (confp->flags & bit);

struct gpgsetup_blob {
	char *dev, *cipher, *hash, *postadd, *prerm;
	unsigned char *key;
	size_t key_len;
	size_t offset, skip;
	unsigned int specified, alloc;
};

// Default configuration parameters, see defaults.h for values
#define GPGSETUP_CONF_INITIALISER { \
	.recipient = CONFIG_RECIPIENT_DEFAULT, \
	.homedir = CONFIG_HOMEDIR_DEFAULT, \
	.materialdir = CONFIG_MATERIALDIR_DEFAULT, \
	.tmp = CONFIG_TMP_DEFAULT, \
	.templ = CONFIG_TEMPLATE_DEFAULT, \
	.keysize = CONFIG_KEYSIZE_DEFAULT, \
	.flags = CONFIG_FLAGS_DEFAULT, \
	.specified = 0, \
	.alloc = 0, \
}

#define GPGSETUP_BLOB_INITIALISER { \
	.dev = NULL, \
	.cipher = BLOB_CIPHER_DEFAULT, \
	.hash = BLOB_HASH_DEFAULT, \
	.postadd = BLOB_POSTADD_DEFAULT, \
	.prerm = BLOB_PRERM_DEFAULT, \
	.key = NULL, \
	.key_len = 0, \
	.offset = 0, \
	.skip = 0, \
	.specified = 0, \
	.alloc = 0, \
}

int read_config_file(FILE *file, config_entry callback, void *ptr);
int read_config_env(config_entry callback, void *ptr);
int parse_bool(const char *value, int *flags, int bit);
int parse_long(const char *value, long *l);
int parse_hex(const char *value, unsigned char *dst, size_t len);

int config_callback(const char *name, const char *value, void *ptr);
int blob_callback(const char *name, const char *value, void *ptr);
int dual_callback(const char *name, const char *value, void *ptr);

void print_config(const struct gpgsetup_config *conf, FILE *stream);
void print_blob(const struct gpgsetup_blob *blob, FILE *stream, int showkey);

/*
 * The apply_*_left and apply_*_right functions indicate that the allocations will
 * be held by the destination and source respectively. This should therefore be the
 * longer living struct as freeing this one may cause the other struct to hold
 * invalid pointers.
 * If the same struct will be applied to multiple structs, then probably use
 * apply_*_right, otherwise if it's a oneshot operation to merge sources, then
 * use apply_*_left, which then allows the source to be immediately free'd.
 */
void apply_config_left(struct gpgsetup_config *dst, struct gpgsetup_config *src);
void apply_config_right(struct gpgsetup_config *dst, struct gpgsetup_config *src);
void apply_blob_left(struct gpgsetup_blob *dst, struct gpgsetup_blob *src);
void apply_blob_right(struct gpgsetup_blob *dst, struct gpgsetup_blob *src);
#define apply_config(dst, src) apply_config_left(dst, src)
#define apply_blob(dst, src) apply_blob_left(dst, src)

void init_config(struct gpgsetup_config *conf);
void init_blob(struct gpgsetup_blob *blob);
void free_config(struct gpgsetup_config *conf);
void free_blob(struct gpgsetup_blob *blob);

#endif // H_GPGSETUP_PARSE
