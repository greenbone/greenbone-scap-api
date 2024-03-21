# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later


import sys

from greenbone.scap.api.errors import InvalidSettingError, ScapAPIError


def main() -> None:
    import os

    import uvicorn

    try:
        port_str = os.environ.get("API_PORT", "8000")
        try:
            port = int(port_str)
        except ValueError:
            raise InvalidSettingError(f"Invalid API_PORT {port_str!r}")

        uvicorn.run(
            "greenbone.scap.api.app:app",
            port=port,
            log_level=os.environ.get("LOG_LEVEL", "info"),
            host=os.environ.get("API_HOST", "127.0.0.1"),
        )
    except ScapAPIError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(2)


if __name__ == "__main__":
    main()
