# Makefile for PQ-Zip - post-quantum compressing archiver (GTK3 + CLI).
#
#   make                build the ./pqzip binary
#   sudo make install   install globally (binary, icon, menu entry)
#   sudo make uninstall remove all installed files
#   make icons          regenerate raster icons from the SVG (needs rsvg-convert)
#   make clean          remove build artifacts

VERSION := 1.0.6
BIN      := pqzip

PREFIX  ?= /usr/local
BINDIR  := $(PREFIX)/bin
DATADIR := $(PREFIX)/share
APPDIR  := $(DATADIR)/applications
ICONBASE := $(DATADIR)/icons/hicolor
ICONDIR  := $(ICONBASE)/scalable/apps

# Raster icon sizes installed alongside the scalable SVG so the icon shows
# reliably in the applications menu and the window/taskbar.
ICON_SIZES := 16 24 32 48 64 128 256

CC      ?= cc
PKGS     = gtk+-3.0 libsodium libargon2 libcrypto zlib
CFLAGS  ?= -O2 -Wall -Wextra
# Kyber-1024 = NIST level 5 (KYBER_K=4); kyber/ holds the CRYSTALS reference.
CFLAGS  += -DPQZIP_VERSION=\"$(VERSION)\" -DKYBER_K=4 -Isrc/kyber \
           $(shell pkg-config --cflags $(PKGS))
LDLIBS  += $(shell pkg-config --libs $(PKGS))

# Kyber-1024 reference sources (SHAKE/fips202 only). randombytes resolves from
# libsodium, so kyber/randombytes.c is intentionally omitted.
KYBER_SRC = src/kyber/kem.c src/kyber/indcpa.c src/kyber/poly.c \
            src/kyber/polyvec.c src/kyber/ntt.c src/kyber/reduce.c \
            src/kyber/cbd.c src/kyber/fips202.c src/kyber/verify.c \
            src/kyber/symmetric-shake.c

SRC      = src/main.c src/cli.c src/pqzip.c src/archive.c src/compress.c \
           src/crypto.c src/secure_buffer.c src/hybrid_kem.c $(KYBER_SRC)
OBJ      = $(SRC:.c=.o)

.PHONY: all clean install uninstall icons

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Regenerate raster icons from the scalable SVG.
icons: data/pqzip.svg
	for s in $(ICON_SIZES); do \
	    rsvg-convert -w $$s -h $$s data/pqzip.svg -o data/pqzip-$$s.png; \
	done

clean:
	rm -f $(OBJ) $(BIN)

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -d $(DESTDIR)$(ICONDIR)
	install -m 0644 data/pqzip.svg $(DESTDIR)$(ICONDIR)/pqzip.svg
	for s in $(ICON_SIZES); do \
	    install -d $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps; \
	    install -m 0644 data/pqzip-$${s}.png \
	        $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps/pqzip.png; \
	done
	install -d $(DESTDIR)$(APPDIR)
	install -m 0644 data/pqzip.desktop $(DESTDIR)$(APPDIR)/pqzip.desktop
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "PQ-Zip $(VERSION) installed to $(BINDIR)/$(BIN)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(ICONDIR)/pqzip.svg
	for s in $(ICON_SIZES); do \
	    rm -f $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps/pqzip.png; \
	done
	rm -f $(DESTDIR)$(APPDIR)/pqzip.desktop
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "PQ-Zip uninstalled"
