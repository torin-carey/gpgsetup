#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

#include "gpgsetup.h"
#include "gpgexec.h"
#include "parse.h"

#ifndef CONFIGLOC
#define CONFIGLOC "/etc/gpgsetup.conf"
#endif

const char *usage = // TODO: Update this
"gpgsetup - open LUKS encrypted volumes with GnuPG\n"
"\n"
"gpgsetup [-aAkKgG] [-r name] [-h dir] [-c file] [-m dir] [-t template] [operation...]\n"
"gpgsetup [...] [list]\n"
"gpgsetup [...] open name\n"
"gpgsetup [...] generate name dev [keyslot]\n"
"gpgsetup [...] insert name dev [keyslot]\n"
"gpgsetup [...] [--show-key|--show-raw] show name\n"
"\n"
"-r, --recipient name\n"
"  encrypt for name. defaults to --default-recipient-self in\n"
"  gpg(1).\n"
"\n"
"-h, --homedir dir\n"
"  use dir as the homedir for gpg(1).\n"
"\n"
"-c, --config file\n"
"  use file as the configuration file for gpgsetup instead of the\n"
"  default value of '/etc/gpgsetup.conf'.\n"
"\n"
"-m, --material-dir dir\n"
"  use dir as the directory containing the key material files.\n"
"\n"
"-t, --template template\n"
"  use template as a template for the generated blob file.\n"
"\n"
"-a, --armour, --armor\n"
"  use armour on blob (default).\n"
"\n"
"-A, --no-armour, --no-armor\n"
"  do not use armour on blob.\n"
"\n"
"-k, --add-key\n"
"  add key to the luks header (default).\n"
"\n"
"-K, --no-add-key\n"
"  do not add key to luks header.\n"
"\n"
"-g, --gpg-stderr\n"
"  show stderr of gpg(1) (default).\n"
"\n"
"-G, --no-gpg-stderr\n"
"  do not show stderr of gpg(1).\n"
"\n"
"--show-key\n"
"  show the key when running show. this has no additional effect\n"
"  when using --show-raw.\n"
"\n"
"--show-raw\n"
"  do not parse the blob file, simply print it when running show.\n"
"  this shows all, including unknown options, but also includes the\n"
"  key.\n";



void print_usage(void)
{
	fputs(usage, stderr);
	exit(-1);
}

#define LONG_CIPHER 0
#define LONG_OFFSET 1
#define LONG_SKIP 2
#define LONG_POSTADD 3
#define LONG_PRERM 4
#define LONG_SHOWKEY 5
#define LONG_SHOWRAW 6
#define LONG_TMP 7
#define LONG_SHOWBLOB 8

const struct option optlong[] = {
	{"cipher", required_argument, NULL, 0},
	{"offset", required_argument, NULL, 0},
	{"skip", required_argument, NULL, 0},
	{"postadd", required_argument, NULL, 0},
	{"prerm", required_argument, NULL, 0},
	{"show-key", no_argument, NULL, 0},
	{"show-raw", no_argument, NULL, 0},
	{"tmp", required_argument, NULL, 0},
	{"show-blob", no_argument, NULL, 0},

	{"recipient", required_argument, NULL, 'r'},
	{"homedir", required_argument, NULL, 'h'},
	{"armour", no_argument, NULL, 'a'},
	{"armor", no_argument, NULL, 'a'},
	{"no-armour", no_argument, NULL, 'A'},
	{"no-armor", no_argument, NULL, 'A'},
	{"gpg-stderr", no_argument, NULL, 'g'},
	{"no-gpg-stderr", no_argument, NULL, 'G'},
	{"verbose", no_argument, NULL, 'v'},
	{"device", required_argument, NULL, 'd'},
	{"size", required_argument, NULL, 's'},
	{"force", no_argument, NULL, 'f'},
	{NULL, 0, NULL, 0}
};
const char *optstring = "r:h:c:m:t:aAgGvd:s:f";

#define FLAG_SHOWBLOB 1

int main(int argc, char **argv)
{
	struct gpgsetup_config gpgsetup_opt = GPGSETUP_CONF_INITIALISER;
	struct gpgsetup_config gpgsetup_env = GPGSETUP_CONF_INITIALISER;
	struct gpgsetup_config gpgsetup_conf = GPGSETUP_CONF_INITIALISER;

	struct gpgsetup_blob blob_opt = GPGSETUP_BLOB_INITIALISER;
	const char *config_loc = CONFIGLOC;
	int config_spec = 0;
	int flags = 0;

	int r, longind;
	while ((r = getopt_long(argc, argv, optstring, optlong, &longind)) != -1) {
		switch (r) {
		case 0:
			switch (longind) {
			case LONG_CIPHER:
				blob_opt.cipher = optarg;
				blob_opt.specified |= BLOB_CIPHER;
				break;
			case LONG_OFFSET:
				sscanf(optarg, "%zu", &blob_opt.offset);
				blob_opt.specified |= BLOB_OFFSET;
				break;
			case LONG_SKIP:
				sscanf(optarg, "%zu", &blob_opt.skip);
				blob_opt.specified |= BLOB_SKIP;
				break;
			case LONG_POSTADD:
				blob_opt.postadd = optarg;
				blob_opt.specified |= BLOB_POSTADD;
				break;
			case LONG_PRERM:
				blob_opt.prerm = optarg;
				blob_opt.specified |= BLOB_PRERM;
				break;
			case LONG_SHOWKEY:
				gpgsetup_opt.flags |= CONFIG_SHOWKEY;
				gpgsetup_opt.specified |= CONFIG_SHOWKEY;
				break;
			case LONG_SHOWRAW:
				gpgsetup_opt.flags |= CONFIG_SHOWRAW;
				gpgsetup_opt.specified |= CONFIG_SHOWRAW;
				break;
			case LONG_TMP:
				gpgsetup_opt.tmp = optarg;
				gpgsetup_opt.specified |= CONFIG_TMP;
				break;
			case LONG_SHOWBLOB:
				flags |= FLAG_SHOWBLOB;
				break;
			}
			break;
		case 'r':
			gpgsetup_opt.recipient = optarg;
			gpgsetup_opt.specified |= CONFIG_RECIPIENT;
			break;
		case 'h':
			gpgsetup_opt.homedir = optarg;
			gpgsetup_opt.specified |= CONFIG_HOMEDIR;
			break;
		case 'c':
			config_loc = optarg;
			config_spec = 1;
			break;
		case 'm':
			gpgsetup_opt.materialdir = optarg;
			gpgsetup_opt.specified |= CONFIG_MATERIAL;
			break;
		case 't':
			gpgsetup_opt.templ = optarg;
			gpgsetup_opt.specified |= CONFIG_TEMPLATE;
			break;
		case 'a':
			gpgsetup_opt.flags |= CONFIG_ARMOUR;
			gpgsetup_opt.specified |= CONFIG_ARMOUR;
			break;
		case 'A':
			gpgsetup_opt.flags &= ~CONFIG_ARMOUR;
			gpgsetup_opt.specified |= CONFIG_ARMOUR;
			break;
		case 'g':
			gpgsetup_opt.flags |= CONFIG_GSTDERR;
			gpgsetup_opt.specified |= CONFIG_GSTDERR;
			break;
		case 'G':
			gpgsetup_opt.flags &= ~CONFIG_GSTDERR;
			gpgsetup_opt.specified |= CONFIG_GSTDERR;
			break;
		case 'v':
			gpgsetup_opt.flags |= CONFIG_VERBOSE;
			gpgsetup_opt.specified |= CONFIG_VERBOSE;
			break;
		case 'd':
			blob_opt.dev = optarg;
			blob_opt.specified |= BLOB_DEV;
			break;
		case 's':
			sscanf(optarg, "%zu", &gpgsetup_opt.keysize);
			gpgsetup_opt.specified |= CONFIG_KEYSIZE;
			break;
		case 'f':
			gpgsetup_opt.flags |= CONFIG_FORCE;
			gpgsetup_opt.specified |= CONFIG_FORCE;
			break;
		default:
			print_usage();
			continue;
		}
	}

	enum gpgsetup_mode mode = LIST;
	struct gpgsetup_param param = {NULL, &blob_opt};

	if (argc > optind) {
		if (!strcmp(argv[optind], "list")) {
//			mode = LIST;
			if (argc - optind != 1)
				print_usage();
		} else if (!strcmp(argv[optind], "open")) {
			mode = OPEN;
			if (argc - optind != 2) {
				fputs("open requires a name\n", stderr);
				print_usage();
			}
		} else if (!strcmp(argv[optind], "close")) {
			mode = CLOSE;
			if (argc - optind != 2) {
				fputs("close requires a name\n", stderr);
				print_usage();
			}
		} else if (!strcmp(argv[optind], "generate")
				|| !strcmp(argv[optind], "gen")) {
			mode = GENERATE;
			if (argc - optind != 2) {
				fputs("generate requires a name\n", stderr);
				print_usage();
			}
		} else if (!strcmp(argv[optind], "update")) {
			mode = UPDATE;
			if (argc - optind != 2) {
				fputs("update requires a name\n", stderr);
				print_usage();
			}
		} else if (!strcmp(argv[optind], "show")) {
			mode = SHOW;
			if (argc - optind != 2) {
				fputs("show requires a name\n", stderr);
				print_usage();
			}
		} else if (!strcmp(argv[optind], "config")) {
			mode = CONFIG;
		} else {
			print_usage();
		}
	}
	++optind;

	FILE *conf = fopen(config_loc, "r");
	if (!conf) {
		if (!config_spec)
			goto post_config_load;
		fprintf(stderr, "failed to open configuration file: %m\n");
		return -1;
	}

	if (read_config_file(conf, config_callback, &gpgsetup_conf)) {
		fprintf(stderr, "failed to read configuration file\n");
		return -1;
	}
	fclose(conf);

post_config_load:

	if (read_config_env(config_callback, &gpgsetup_env)) {
		fprintf(stderr, "failed to read environment variables\n");
		return -1;
	}
	apply_config(&gpgsetup_conf, &gpgsetup_env);
	apply_config(&gpgsetup_conf, &gpgsetup_opt);

	switch (mode) {
	case LIST:
		r = handle_mode_list(&gpgsetup_conf, &param);
		break;
	case OPEN:
		param.name = argv[optind++];
		r = handle_mode_open(&gpgsetup_conf, &param);
		break;
	case CLOSE:
		param.name = argv[optind++];
		r = handle_mode_close(&gpgsetup_conf, &param);
		break;
	case GENERATE:
		param.name = argv[optind++];
		r = handle_mode_generate(&gpgsetup_conf, &param);
		break;
	case UPDATE:
		param.name = argv[optind++];
		r = handle_mode_update(&gpgsetup_conf, &param);
		break;
	case SHOW:
		param.name = argv[optind++];
		r = handle_mode_show(&gpgsetup_conf, &param);
		break;
	case CONFIG:
		if (flags & FLAG_SHOWBLOB) {
			struct gpgsetup_blob defaults = GPGSETUP_BLOB_INITIALISER;
			apply_blob_right(&defaults, &blob_opt);
			defaults.specified = -1;
			print_blob(&defaults, stdout, 0);
			//free_blob(&defaults); // Not actually necessary
		} else {
			gpgsetup_conf.specified = -1;
			print_config(&gpgsetup_conf, stdout);
		}
		r = 0;
		break;
	}

	return r;
}
