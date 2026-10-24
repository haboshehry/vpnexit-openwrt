#!/usr/bin/env python3
"""Run a local shell script on the router over SSH (password auth).

usage: rssh.py <script.sh> [--put local:remote]...
The router password is read from ROUTER_PASS, never from the command line.
"""
import os
import sys

import paramiko

HOST = os.environ.get("ROUTER_HOST", "192.168.1.1")
USER = os.environ.get("ROUTER_USER", "root")


def connect():
    """Open a session. A fresh OpenWrt has no root password, which dropbear
    accepts through "none" authentication rather than an empty password, so
    that is tried first and the password is used as a fallback."""
    transport = paramiko.Transport((HOST, 22))
    transport.start_client(timeout=15)
    try:
        transport.auth_none(USER)
    except paramiko.SSHException:
        password = os.environ.get("ROUTER_PASS")
        if not password:
            transport.close()
            raise
        transport.auth_password(USER, password)

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli._transport = transport
    return cli


def put(cli, local, remote):
    data = open(local, "rb").read()
    chan = cli.exec_command("cat > %s" % remote, timeout=90)
    stdin = chan[0]
    stdin.write(data)
    stdin.channel.shutdown_write()
    chan[1].read()
    chan[2].read()


def main():
    args = sys.argv[1:]
    script = None
    puts = []
    i = 0
    while i < len(args):
        if args[i] == "--put":
            # Two arguments: local path then remote path (Windows paths contain
            # a colon, so they cannot be joined with ":").
            puts.append((args[i + 1], args[i + 2]))
            i += 3
        else:
            script = args[i]
            i += 1
    cli = connect()
    for local, remote in puts:
        put(cli, local, remote)
    if script:
        body = open(script, "rb").read()
        sin, sout, serr = cli.exec_command("sh -s", timeout=180)
        sin.write(body)
        sin.channel.shutdown_write()
        print(sout.read().decode(errors="replace"))
        sys.stderr.write(serr.read().decode(errors="replace"))
    cli.close()


if __name__ == "__main__":
    main()
