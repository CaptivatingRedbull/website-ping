from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = ["override"]

if TYPE_CHECKING:
    from typing_extensions import override
else:

    def override(func):
        """typing.override needs 3.12 and bin/ can't rely on typing_extensions."""
        return func
