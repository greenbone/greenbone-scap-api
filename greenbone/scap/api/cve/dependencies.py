# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
from typing import Annotated, AsyncGenerator

from fastapi import Depends

from greenbone.scap.api.errors import InvalidSettingError
from greenbone.scap.cve.manager import CVEManager
from greenbone.scap.db import PostgresDatabase

POSTGRES_USER = os.environ.get("DATABASE_USER", "scap")
POSTGRES_DATABASE = os.environ.get("DATABASE_NAME", "scap")
POSTGRES_HOST = os.environ.get("DATABASE_HOST", "127.0.0.1")
POSTGRES_PORT = os.environ.get("DATABASE_PORT", "5432")
POSTGRES_PASSWORD = os.environ.get("DATABASE_PASSWORD")
ECHO_SQL = os.environ.get("ECHO_SQL") in ("true", "1")

cve_database = PostgresDatabase(
    user=POSTGRES_USER,
    password=POSTGRES_PASSWORD,
    host=POSTGRES_HOST,
    port=POSTGRES_PORT,
    dbname=POSTGRES_DATABASE,
    echo=ECHO_SQL,
)

if not POSTGRES_PASSWORD:
    raise InvalidSettingError(
        "PostgreSQL database password missing. Please set the "
        "DATABASE_PASSWORD environment variable."
    )


async def get_cve_manager() -> AsyncGenerator[CVEManager, None]:
    async with cve_database, CVEManager(cve_database) as cve_manager:
        yield cve_manager


CVEManagerDependency = Annotated[CVEManager, Depends(get_cve_manager)]
