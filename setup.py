'''Package setup'''

import setuptools

with open("README.md", "r", encoding='UTF-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name='splynx-api',
    version='2.0.1',
    scripts=[],
    author="Splynx s.r.o",
    author_email="support@splynx.com",
    description="Splynx Python API client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://bitbucket.org/splynx/splynx-python-api/src/master/",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "certifi>=2020.12",
        "chardet>=4.0",
        "deprecation>=2.1",
        "idna>=2.10",
        "pyparsing>=2.4",
        "requests>=2.25",
        "urllib3>=1.26",
    ]
)
