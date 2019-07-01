#!/usr/bin/env python3
# pylint: skip-file
import ez_setup
ez_setup.use_setuptools()
from setuptools import setup, Extension, find_packages


setup(
    name="libraydust",
    version="0.1",
    description="RayDust Security Library",
    packages=find_packages(),
    ext_modules=[Extension("libraydust",
                           ["python.c", "fuzzy.c", "fuzzy_api.c", "geo.c", "ioc.c",
                            "hash.c", "blacklist.c", 'cuckoofilter.c', 'hashutil.c'],
                           include_dirs = ['./include'],
                           libraries=['ssl'])]
)
