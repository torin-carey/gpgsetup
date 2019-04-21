#ifndef H_GPGSETUP_CRYPTEXEC
#define H_GPGSETUP_CRYPTEXEC

#include "gpgsetup.h"
#include "parse.h"

int open_cryptdev(const struct gpgsetup_config *conf, const struct gpgsetup_blob *blob, char *name);
int close_cryptdev(const struct gpgsetup_config *conf, char *name);

#endif // H_GPGSETUP_CRYPTEXEC
