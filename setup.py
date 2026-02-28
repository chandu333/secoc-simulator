"""Setup configuration for SecOC Simulator."""

from setuptools import setup, find_packages

setup(
    name="secoc-simulator",
    version="1.0.0",
    description=(
        "AUTOSAR SecOC message simulator — generates and validates "
        "MAC-authenticated CAN frames"
    ),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="SecOC Simulator Contributors",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "pycryptodome>=3.19.0",
        "pyyaml>=6.0.1",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "secoc-sim=secoc_simulator.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="autosar secoc can automotive security mac authentication",
)
