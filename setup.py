import os

from setuptools import setup, find_packages

here = os.path.dirname(__file__)

readme_file = os.path.join(here, 'README.md')
with open(readme_file) as f:
    long_description = f.read()

requirements_file = os.path.join(here, 'requirements', 'base.txt')
with open(requirements_file) as f:
    install_requires = f.read()

packages = find_packages()

setup_params = dict(
    name='serviceregistrator',
    description='MetaBrainz Docker/Consul Services Registration',
    long_description=long_description,
    long_description_content_type="text/markdown",
    version='0.0.1',
    url='https://github.com/metabrainz/serviceregistrator',
    author='Laurent Monin',
    author_email='zas@metabrainz.org',
    license='GPL-3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)'
        'Programming Language :: Python :: 3'
    ],
    packages=packages,
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'serviceregistrator=serviceregistrator.main:main'
        ]
    },
    python_requires='>=3.6',
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
)

if __name__ == '__main__':
    # allow setup.py to run from another directory
    here and os.chdir(here)
    dist = setup(**setup_params)
