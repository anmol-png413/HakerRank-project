"""Decide whether a request actually authorizes deletion (multi-language).

Deletion is the default reading of a request in this workflow.  A request is
``NOT_APPLICABLE`` when the person explicitly refuses deletion ("do not close
the account", "not asking for deletion") or asks for something else (access,
export, correction, marketing opt-out, contact change) without asking for the
account or its data to be removed.
"""
from __future__ import annotations

import re

# Explicit wish to delete / erase / close, in EN, ES, PT, FR, JA, KO.
DELETE_RE = re.compile(
    r"(delet|erase|erasure|permanent|close (my|this|the) account|closed (my|this) account"
    r"|supprim|elimin|exclus|borrar|apagar|削除|삭제|消去)",
    re.IGNORECASE)

# Statements that the person does NOT want the account deleted / changed.
REFUSAL_RE = re.compile(
    r"(not (asking|a request|requesting)[^.]{0,30}(delet|eras|clos)"
    r"|(do not|don't|do n't|never)\s+(close|delete|remove|erase)"
    r"|without (removing|deleting|erasing)"
    r"|(leave|keep)[^.]{0,40}(account|profile)[^.]{0,40}(active|place|as it is)"
    r"|keep the account|keep my account|still need the account|still use it"
    r"|(want|wish) to continue using|continue using the service"
    r"|marketing lists only)",
    re.IGNORECASE)

# Requests for something other than deletion.
OTHER_RE = re.compile(
    r"(download|portable format|copy of|what personal information|information request"
    r"|out of date|misspell|correct it|change the email|replace it|promotional emails"
    r"|resetting the login|can't access|cannot access|invoice)",
    re.IGNORECASE)


def authorizes_deletion(text: str) -> bool:
    t = text or ""
    if REFUSAL_RE.search(t):
        return False
    if OTHER_RE.search(t) and not DELETE_RE.search(t):
        return False
    return True
