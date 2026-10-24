"""Tiny SSH helper for the router (password auth, no sftp subsystem needed).

usage:
  python rssh.py run "<shell command>"
  python rssh.py put <local-file> <remote-path>
"""
import base64
import sys

import paramiko

HOST = "192.168.1.1"
USER = "root"
PASS = "Xo0ox@xo0oX"


def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=20,
              banner_timeout=20, auth_timeout=20, look_for_keys=False,
              allow_agent=False)
    return c


def run(c, cmd, timeout=180):
    _, so, se = c.exec_command(cmd, timeout=timeout)
    out = so.read().decode("utf-8", "replace")
    err = se.read().decode("utf-8", "replace")
    rc = so.channel.recv_exit_status()
    return rc, out, err


def main():
    c = connect()
    try:
        if sys.argv[1] == "put":
            with open(sys.argv[2], "rb") as fh:
                data = fh.read()
            remote = sys.argv[3]
            si, so, se = c.exec_command("cat > %s" % remote, timeout=60)
            si.write(data)
            si.channel.shutdown_write()
            si.close()
            out = so.read().decode("utf-8", "replace")
            err = se.read().decode("utf-8", "replace")
            rc = so.channel.recv_exit_status()
            print("uploaded %d bytes rc=%d %s %s" % (len(data), rc, out.strip(), err.strip()))
        else:
            rc, out, err = run(c, sys.argv[2])
            sys.stdout.write(out)
            if err.strip():
                sys.stderr.write("\n[stderr]\n" + err)
            print("\n[rc=%d]" % rc)
    finally:
        c.close()


if __name__ == "__main__":
    main()
