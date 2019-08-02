import setuptools
import time

with open("README.md", "r") as fh:
    long_description = fh.read()

version="0.dev5"
with open('log.out','w') as f:
    f.write(version)

setuptools.setup(
    name="QiyNodeLib",
    version=version,
    author="Freek Driesenaar",
    author_email="freek.driesenaar@digital-me.nl",
    description="Qiy Node Library",
    install_requires=['cryptography>=2.2.2',
                      'pyOpenSSL>=18.0.0',
                      'requests>=2.19.0'],
    keywords="qiy privacy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://code.digital-me.nl/DEVtst/QiyNodeLib",
    packages=setuptools.find_packages(),
    classifiers=(
        "Development Status :: 1 - Planning",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Framework :: Pytest",
        "Framework :: tox",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Telecommunications Industry",
        "Programming Language :: Python :: 3",
        "License :: Other/Proprietary License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Communications",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ),
)
