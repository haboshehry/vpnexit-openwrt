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
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(
        HOST,
        username=USER,
        password=os.environ["ROUTER_PASS"],
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
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
