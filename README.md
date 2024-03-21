![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# greenbone-scap-api <!-- omit in toc -->

[![GitHub releases](https://img.shields.io/github/release/greenbone/greenbone-scap-api.svg)](https://github.com/greenbone/greenbone-scap-api/releases)
[![PyPI release](https://img.shields.io/pypi/v/greenbone-scap-api.svg)](https://pypi.org/project/greenbone-scap-api/)

A REST API on top of [greenbone-scap](https://github.com/greenbone/greenbone-scap)
based on [FastAPI](https://fastapi.tiangolo.com/).

It provides a similar CVE API to [NVD NIST](https://nvd.nist.gov/developers/vulnerabilities)
at https://services.nvd.nist.gov/rest/json/cves/2.0.

## Table of Contents <!-- omit in toc -->

- [Requirements](#requirements)
  - [Install using pipx](#install-using-pipx)
  - [Install using pip](#install-using-pip)
- [Usage](#usage)
- [Settings](#settings)
- [Development](#development)
- [Maintainer](#maintainer)
- [License](#license)

## Requirements

Python 3.11 and later is supported.

### Install using pipx

You can install the latest stable release of **greenbone-scap-api** from the
[Python Package Index (pypi)][pypi] using [pipx]

    python3 -m pipx install greenbone-scap-api

### Install using pip

> [!NOTE]
> The `pip install` command does no longer work out-of-the-box in newer
> distributions like Ubuntu 23.04 because of [PEP 668](https://peps.python.org/pep-0668).
> Please use the [installation via pipx](#install-using-pipx) instead.

You can install the latest stable release of **greenbone-scap-api** from the
[Python Package Index (pypi)][pypi] using [pip]

    python3 -m pip install --user greenbone-scap-api

## Usage

A simple web server to serve the API can be started by running
`greenbone-scap-api`. The settings of the web server can be controlled via
[environment variables](#settings).

Internally the `greenbone-scap-api` script uses [uvicorn](https://www.uvicorn.org/)

It's also possible to serve the API with uvicorn directly

```
uvicorn greenbone.scap.api.app:app --reload
```

Using uvicorn directly allows for more flexibility regarding the [settings](https://www.uvicorn.org/settings/)
for serving the API.

After starting the web server the CVE API is available at `http://127.0.0.1:8000/cves`
by default. [Interactive API docs](https://github.com/swagger-api/swagger-ui)
are served at `http://127.0.0.1:8000/docs`.

## Settings

**greenbone-scap-api** can be configured via the following environment variables

| Name              | Description                                                                                           | Default   |
| ----------------- | ----------------------------------------------------------------------------------------------------- | --------- |
| DATABASE_USER     | Username for the connection to the PostgreSQL database.                                               | scap      |
| DATABASE_PASSWORD | Username for the connection to the PostgreSQL database.                                               |           |
| DATABASE_NAME     | Name of the PostgreSQL database.                                                                      | scap      |
| DATABASE_HOST     | Host where the PostgreSQL database is running. IP or DNS name.                                        | 127.0.0.1 |
| DATABASE_PORT     | Port on which the PostgreSQL database is listening.                                                   | 5432      |
| ECHO_SQL          | Log SQL statements. `true` or `1` to enable.                                                          | disabled  |
| API_HOST          | IP address or DNS name to listen on                                                                   | 127.0.0.1 |
| API_PORT          | Port to listen on                                                                                     | 8000      |
| LOG_LEVEL         | Log level for server output. Options are `critical`, `error`, `warning`, `info`, `debug` and `trace`. | `info`    |

## Development

**greenbone-scap-api** uses [poetry] for its own dependency management and build
process.

First install poetry via [pipx]

    python3 -m pipx install poetry

Afterwards run

    poetry install

in the checkout directory of **greenbone-scap-api** (the directory containing the
`pyproject.toml` file) to install all dependencies including the packages only
required for development.

Afterwards activate the git hooks for auto-formatting and linting via
[autohooks].

    poetry run autohooks activate

Validate the activated git hooks by running

    poetry run autohooks check

## Maintainer

This project is maintained by [Greenbone AG][Greenbone]

## License

Copyright (C) 2024 [Greenbone AG][Greenbone]

Licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).

[Greenbone]: https://www.greenbone.net/
[poetry]: https://python-poetry.org/
[pip]: https://pip.pypa.io/
[pipx]: https://pypa.github.io/pipx/
[autohooks]: https://github.com/greenbone/autohooks
[pypi]: https://pypi.org
