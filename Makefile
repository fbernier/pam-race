PREFIX     ?= /usr
LIBDIR     ?= $(PREFIX)/lib
PAMDIR     ?= $(LIBDIR)/security
HELPERDIR  ?= $(LIBDIR)/pam-race
CARGO      ?= cargo

# Baked into the module at build time: where it executes the helper from.
export PAM_RACE_HELPER := $(HELPERDIR)/pam-race-helper

.PHONY: all check install uninstall clean

all:
	$(CARGO) build --release --lib --bin pam-race-helper

check:
	$(CARGO) test

# Deliberately does not depend on `all`: build as yourself, install as root.
install:
	install -Dm755 target/release/libpam_race.so $(DESTDIR)$(PAMDIR)/pam_race.so
	install -Dm755 target/release/pam-race-helper $(DESTDIR)$(PAM_RACE_HELPER)

uninstall:
	rm -f $(DESTDIR)$(PAMDIR)/pam_race.so $(DESTDIR)$(PAM_RACE_HELPER)
	-rmdir $(DESTDIR)$(HELPERDIR)

clean:
	$(CARGO) clean
