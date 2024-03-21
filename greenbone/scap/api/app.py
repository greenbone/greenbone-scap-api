# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from fastapi import FastAPI

from . import cve

__all__ = ("app",)

app = FastAPI()

app.include_router(cve.router)
