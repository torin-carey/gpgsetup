#ifndef H_GPGSETUP
#define H_GPGSETUP

#include "parse.h"

#define DEFAULT_GPGSETUP_DIR "./fskeys"
#define BLOB_SIZE 4096

enum gpgsetup_mode {
	LIST,
	OPEN,
	CLOSE,
	GENERATE,
	UPDATE,
	SHOW,
	CONFIG,
	CREATE,
};

struct gpgsetup_param {
	char *name, *dev;
	struct gpgsetup_blob *blob;
};

int handle_mode_list(struct gpgsetup_config *, struct gpgsetup_param *);
int handle_mode_open(struct gpgsetup_config *, struct gpgsetup_param *);
int handle_mode_close(struct gpgsetup_config *, struct gpgsetup_param *);
int handle_mode_generate(struct gpgsetup_config *, struct gpgsetup_param *);
int handle_mode_update(struct gpgsetup_config *, struct gpgsetup_param *);
int handle_mode_show(struct gpgsetup_config *, struct gpgsetup_param *);
int handle_mode_create(struct gpgsetup_config *, struct gpgsetup_param *);

#endif // H_GPGSETUP
