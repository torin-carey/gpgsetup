SRCDIR := src
SOURCEFILES := gpgsetup.c gpgexec.c handler.c parse.c cryptexec.c
TARGETS := gpgsetup gpgsetup.8.gz
SOURCES = $(addprefix $(SRCDIR)/,$(SOURCEFILES))
CFLAGS := -Wall -Wextra -std=gnu99

ifdef configloc
	CFLAGS += -DCONFIGLOC=\"$(configloc)\"
endif
ifdef recipient
	CFLAGS += -DCONFIG_RECIPIENT_DEFAULT=\"$(recipient)\"
endif
ifdef homedir
	CFLAGS += -DCONFIG_HOMEDIR_DEFAULT=\"$(recipient)\"
endif
ifdef materialdir
	CFLAGS += -DCONFIG_MATERIALDIR_DEFAULT=\"$(materialdir)\"
endif
ifdef template
	CFLAGS += -DCONFIG_TEMPLATE_DEFAULT=\"$(recipient)\"
endif
ifdef keysize
	CFLAGS += -DCONFIG_KEYSIZE_DEFAULT=\"$(recipient)\"
endif
ifdef cipher
	CFLAGS += -DBLOB_CIPHER_DEFAULT=\"$(recipient)\"
endif
ifdef hash
	CFLAGS += -DBLOB_HASH_DEFAULT=\"$(hash)\"
endif
ifdef postadd
	CFLAGS += -DBLOB_POSTADD_DEFAULT=\"$(recipient)\"
endif
ifdef prerm
	CFLAGS += -DBLOB_PRERM_DEFAULT=\"$(recipient)\"
endif
ifeq ($(libcryptsetup),1)
	CFLAGS += -DLIBCRYPTSETUP -lcryptsetup
endif

.PHONY: all clean install

all: $(TARGETS)

install: all
	install gpgsetup /usr/local/sbin/
	mkdir -p /usr/local/share/man/man8
	install -m 644 -T gpgsetup.8.gz /usr/local/share/man/man8/gpgsetup.8.gz
	install -m 644 gpgsetup@.service /etc/systemd/system/

gpgsetup: $(SOURCES)
	gcc -g $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGETS)

%.gz: %
	gzip -fk $<
