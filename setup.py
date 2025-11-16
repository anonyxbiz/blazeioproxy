from setuptools import setup, find_packages

setup(
    name = "BlazeioProxy",
    version = "0.0.3",
    description = "BlazeioProxy is a high-performance SOCKS5 proxy server that enables raw TCP protocol handling with zero-copy efficiency and enterprise-grade performance.",
    license = "MIT",
    author = "Anonyxbiz",
    author_email = "anonyxbiz@gmail.com",
    url = "https://github.com/anonyxbiz/blazeioproxy",
    packages = find_packages(),
    include_package_data = True,
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: MIT",
        "Operating System :: OS Independent",
    ],
    py_modules = ['BlazeioProxy'],
    python_requires = '>=3.6',
    entry_points = {
        'console_scripts': [
            'BlazeioProxy = BlazeioProxy.__main__:entry_point',
        ],
    }
)

