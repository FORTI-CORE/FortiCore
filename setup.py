from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="forticore",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive penetration testing framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/forticore",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.6",
    install_requires=[
        "requests>=2.26.0",
        "python-dotenv>=0.19.0",
        "pyyaml>=5.4.1",
        "colorama>=0.4.4",
        "python-nmap>=0.7.1",
        "pyfiglet",
    ],
    entry_points={
        "console_scripts": [
            "ftcore=forticore.__main__:main",
        ],
    },
)
