# crlbuilder

A Python library for creating and signing X.509 certificate revocation lists
(CRLs).

 - [Related Crypto Libraries](#related-crypto-libraries)
 - [Current Release](#current-release)
 - [Dependencies](#dependencies)
 - [Installation](#installation)
 - [License](#license)
 - [Documentation](#documentation)
 - [Continuous Integration](#continuous-integration)
 - [Testing](#testing)
 - [Development](#development)
 - [CI Tasks](#ci-tasks)

[![GitHub Actions CI](https://github.com/wbond/crlbuilder/workflows/CI/badge.svg)](https://github.com/wbond/crlbuilder/actions?workflow=CI)
[![CircleCI](https://circleci.com/gh/wbond/crlbuilder.svg?style=shield)](https://circleci.com/gh/wbond/crlbuilder)
[![PyPI](https://img.shields.io/pypi/v/crlbuilder.svg)](https://pypi.python.org/pypi/crlbuilder)

## Related Crypto Libraries

*crlbuilder* is part of the modularcrypto family of Python packages:

 - [asn1crypto](https://github.com/wbond/asn1crypto)
 - [oscrypto](https://github.com/wbond/oscrypto)
 - [csrbuilder](https://github.com/wbond/csrbuilder)
 - [certbuilder](https://github.com/wbond/certbuilder)
 - [crlbuilder](https://github.com/wbond/crlbuilder)
 - [ocspbuilder](https://github.com/wbond/ocspbuilder)
 - [certvalidator](https://github.com/wbond/certvalidator)

## Current Release

0.10.2 - [changelog](changelog.md)

## Dependencies

 - [*asn1crypto*](https://github.com/wbond/asn1crypto)
 - [*oscrypto*](https://github.com/wbond/oscrypto)
 - Python 2.6, 2.7, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9 or pypy

## Installation

```bash
pip install crlbuilder
```

## License

*crlbuilder* is licensed under the terms of the MIT license. See the
[LICENSE](LICENSE) file for the exact license text.

## Documentation

[*crlbuilder* documentation](docs/readme.md)

## Continuous Integration

 - [macOS, Linux, Windows](https://github.com/wbond/crlbuilder/actions/workflows/ci.yml) via GitHub Actions
 - [arm64](https://circleci.com/gh/wbond/crlbuilder) via CircleCI

## Testing

Tests are written using `unittest` and require no third-party packages.

Depending on what type of source is available for the package, the following
commands can be used to run the test suite.

### Git Repository

When working within a Git working copy, or an archive of the Git repository,
the full test suite is run via:

```bash
python run.py tests
```

To run only some tests, pass a regular expression as a parameter to `tests`.

```bash
python run.py tests build
```

### PyPi Source Distribution

When working within an extracted source distribution (aka `.tar.gz`) from
PyPi, the full test suite is run via:

```bash
python setup.py test
```

## Development

To install the package used for linting, execute:

```bash
pip install --user -r requires/lint
```

The following command will run the linter:

```bash
python run.py lint
```

Support for code coverage can be installed via:

```bash
pip install --user -r requires/coverage
```

Coverage is measured by running:

```bash
python run.py coverage
```

To install the packages requires to generate the API documentation, run:

```bash
pip install --user -r requires/api_docs
```

The documentation can then be generated by running:

```bash
python run.py api_docs
```

To change the version number of the package, run:

```bash
python run.py version {pep440_version}
```

To install the necessary packages for releasing a new version on PyPI, run:

```bash
pip install --user -r requires/release
```

Releases are created by:

 - Making a git tag in [PEP 440](https://www.python.org/dev/peps/pep-0440/#examples-of-compliant-version-schemes) format
 - Running the command:

   ```bash
   python run.py release
   ```

Existing releases can be found at https://pypi.org/project/crlbuilder.

## CI Tasks

A task named `deps` exists to ensure a modern version of `pip` is installed,
along with all necessary testing dependencies.

The `ci` task runs `lint` (if flake8 is avaiable for the version of Python) and
`coverage` (or `tests` if coverage is not available for the version of Python).
If the current directory is a clean git working copy, the coverage data is
submitted to codecov.io.

```bash
python run.py deps
python run.py ci
```
