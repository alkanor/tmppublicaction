from setuptools import setup, find_packages


setup(
    name="action",
    version="0.0.1",
    author="Alka",
    description=("Some core action package for future"),
    license="MIT",
    #packages=['action'],
    packages=find_packages(exclude=['tests']),
    include_package_data=True,
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
    ],
)
