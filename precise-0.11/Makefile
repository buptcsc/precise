top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin

CC = gcc
CFLAGS  = -O3 -Wall \
	-I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
	 \
	-I/usr/include/pbc -I/usr/local/include/pbc \
	 \
	-DPACKAGE_NAME=\"precise\" -DPACKAGE_TARNAME=\"precise\" -DPACKAGE_VERSION=\"0.11\" -DPACKAGE_STRING=\"precise\ 0.11\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_FCNTL_H=1 -DHAVE_STDDEF_H=1 -DHAVE_STRING_H=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DLSTAT_FOLLOWS_SLASHED_SYMLINK=1 -DHAVE_VPRINTF=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_STRCHR=1 -DHAVE_STRDUP=1 -DHAVE_MEMSET=1 -DHAVE_GMP=1 -DHAVE_PBC=1 -DHAVE_BSWABE=1
LDFLAGS = -O3 -Wall \
	-lglib-2.0 \
	-Wl,-rpath /usr/local/lib -lgmp \
	-Wl,-rpath /usr/local/lib -lpbc \
	-lbswabe \
	-lcrypto -lcrypto \
	-lgmp

DISTNAME = precise-0.11

TARGETS  = precise-setup   precise-keygen   precise-enc   precise-rekeygen   precise-reenc   precise-dec1   precise-dec2
DEVTARGS = test-lang TAGS

all: $(TARGETS) $(DEVTARGS)

# user-level compilation

precise-setup: setup.o common.o
	$(CC) -o $@ $^ $(LDFLAGS)

precise-keygen: keygen.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

precise-enc: enc.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

precise-rekeygen: rekeygen.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

precise-reenc: reenc.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

precise-dec1: dec1.o common.o
	$(CC) -o $@ $^ $(LDFLAGS)

precise-dec2: dec2.o common.o
	$(CC) -o $@ $^ $(LDFLAGS)

test-lang: test-lang.o common.o policy_lang.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c *.h Makefile
	$(CC) -c -o $@ $< $(CFLAGS)

# installation

dist: *.y policy_lang.c *.c *.h *.more-man \
	INSTALL \
	aclocal.m4 acinclude.m4 configure configure.ac install-sh Makefile.in \
	missing mkinstalldirs
	rm -rf $(DISTNAME)
	mkdir $(DISTNAME)
	cp $^ $(DISTNAME)
	tar zc $(DISTNAME) > $(DISTNAME).tar.gz
	rm -rf $(DISTNAME)

install: $(TARGETS) $(MANUALS)
	$(top_srcdir)/mkinstalldirs -m 755 $(DESTDIR)$(bindir)
	for PROG in $(TARGETS); \
	do \
	  $(top_srcdir)/install-sh -m 755 $$PROG   $(DESTDIR)$(bindir); \
	done

uninstall:
	for PROG in $(TARGETS); \
	do \
	  /bin/rm -f $(DESTDIR)$(bindir)/$$PROG; \
	done

# developer-level processing and meta stuff

%.c: %.y *.h Makefile
	if which bison 2> /dev/null; then \
	   bison -o $@ $<; \
	fi

TAGS: *.c *.h *.y
	@(etags $^ || true) 2> /dev/null

Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck

configure: configure.ac aclocal.m4 acinclude.m4
	autoconf

# cleanup

# remove everything an installing user can rebuild
clean:
	rm -f *.o $(TARGETS) $(DEVTARGS) *.tar.gz pub_key master_key priv_key *~

# remove everything a package developer can rebuild
distclean: clean
	rm -rf policy_lang.c autom4te.cache Makefile config.status config.log config.cache \
		configure configure.scan autoscan*.log *.1 *.html *.lineno
