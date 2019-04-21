#ifndef H_GPGSETUP_GPGEXEC
#define H_GPGSETUP_GPGEXEC

#include "gpgsetup.h"
#include "parse.h"


int decrypt_blob(int fd, const struct gpgsetup_config *conf, struct gpgsetup_blob *blob);
int encrypt_blob(int fd, const struct gpgsetup_config *conf, const struct gpgsetup_blob *blob);

#endif // H_GPGSETUP_GPGEXEC
