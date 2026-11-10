PY ?= python3
PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: help test check install dist clean

help:
	@echo "make test    - run the test suite (stdlib only)"
	@echo "make check   - byte-compile every module"
	@echo "make install - install haven and havend under $(PREFIX) (no pip needed)"
	@echo "make dist    - build a wheel and sdist in dist/"
	@echo "make clean   - remove build artefacts and caches"

test:
	$(PY) run_tests.py -v

check:
	$(PY) -m compileall -q haven tests run_tests.py
	@echo "compile ok"

install: check
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/haven
	install -d $(DESTDIR)$(PREFIX)/share/doc/haven
	rm -rf $(DESTDIR)$(PREFIX)/lib/haven/haven
	cp -r haven $(DESTDIR)$(PREFIX)/lib/haven/
	cp README.md CHANGELOG.md $(DESTDIR)$(PREFIX)/share/doc/haven/
	cp -r docs $(DESTDIR)$(PREFIX)/share/doc/haven/
	printf '#!/bin/sh\nPYTHONPATH=%s/lib/haven exec %s -m haven "$$@"\n' "$(PREFIX)" "$(PY)" > $(DESTDIR)$(PREFIX)/bin/haven
	printf '#!/bin/sh\nPYTHONPATH=%s/lib/haven exec %s -m haven.server "$$@"\n' "$(PREFIX)" "$(PY)" > $(DESTDIR)$(PREFIX)/bin/havend
	chmod 0755 $(DESTDIR)$(PREFIX)/bin/haven $(DESTDIR)$(PREFIX)/bin/havend
	@echo "installed $(DESTDIR)$(PREFIX)/bin/haven and havend"

dist: check
	$(PY) -m pip install --quiet build && $(PY) -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
