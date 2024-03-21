# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from greenbone.scap.errors import ScapError


class ScapAPIError(ScapError):
    """
    Base error for errors originating in this module
    """


class InvalidSettingError(ScapAPIError):
    """
    Raised if a setting or configuration is invalid or missing
    """
