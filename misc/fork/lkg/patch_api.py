#!/usr/bin/env python3
"""Fail closed if the pinned upstream API changes; no approximate text patching."""

from pathlib import Path

p = Path("/usr/share/bunkerweb/lua/bunkerweb/api.lua")
s = p.read_text()


def replace(old, new):
    global s
    if s.count(old) != 1:
        raise SystemExit("Pinned API anchor mismatch; review upstream before building")
    s = s.replace(old, new, 1)


replace('local api = class("api")', 'local lkg = require "bunkerweb.lkg_guard"\nlocal api = class("api")')
replace(
    "local function reload_locked(test_arg)\n",
    """local function reload_locked(test_arg)
    if not lkg.run("preflight") then
        return HTTP_INTERNAL_SERVER_ERROR, "error", "LKG preflight rejected candidate; previous configuration restored"
    end
""",
)
replace(
    "local ran, status, level, message = pcall(reload_locked, test_arg)\n\tlock:unlock()",
    """local ran, status, level, message = pcall(reload_locked, test_arg)
    if ran and level == "success" then
        if not lkg.run("commit") then
            status, level, message = HTTP_INTERNAL_SERVER_ERROR, "error", "LKG commit failed; previous configuration restored"
        end
    elseif ran then
        lkg.run("abort")
    end
    lock:unlock()""",
)
replace(
    "local ran, ok, err = pcall(pushswap.swap, destination, staging)",
    """if not lkg.run("begin") then
        if generating then ffi.C.fclose(generating) end
        lock:unlock()
        execute("rm -rf '" .. staging .. "'")
        os.remove(tmp)
        return self:response(HTTP_INTERNAL_SERVER_ERROR, "error", "cannot create durable LKG transaction")
    end
    local ran, ok, err = pcall(pushswap.swap, destination, staging)
    if not ran or not ok then lkg.run("abort") end""",
)
p.write_text(s)
