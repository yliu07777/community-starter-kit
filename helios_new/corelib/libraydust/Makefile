-include ../../mk/Makefile.rules
all:
	$(HIDE)python3 setup.py egg_info --tag-date --tag-build=DEV bdist_egg
clean:
	$(HIDE)rm -rf libraydust.egg-info *.pyc setuptools*.zip setuptools*.egg *.out *.bin *.exe *.o *.a *.so test build *~ dist __pycache__
