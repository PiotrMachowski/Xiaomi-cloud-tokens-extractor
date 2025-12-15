from setuptools import setup
import pathlib

here = pathlib.Path(__file__).parent.resolve()

long_description = (here / "README.md").read_text(encoding="utf-8")

with (here / "requirements.txt").open() as f:
    install_requires = f.readlines()

setup(
    name="xiaomi-cloud-tokens-extractor",
    version="1.5.1",
    description="Cloud token extractor for Xiaomi BLE devices",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor",
    author="Piotr Machowski",
    #keywords="sample, setuptools, development",  # Optional
    py_modules=["token_extractor"],
    entry_points={
        "console_scripts": [ "xiaomi-cloud-tokens-extractor = token_extractor:main" ],
    },
    python_requires=">=3.9, <4",
    install_requires=install_requires,
    project_urls={
        "Bug Reports": "https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor/issues",
        "Funding": "https://ko-fi.com/piotrmachowski",
        "Source": "https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor",
    },
)
