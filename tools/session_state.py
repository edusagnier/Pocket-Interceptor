#!/usr/bin/env python3
"""Private recovery journal for a portal session (no network scanning)."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import uuid


SERVICES = ("NetworkManager", "wpa_supplicant", "isc-dhcp-server",
            "dnsmasq", "beef-xss", "apache2")
CONFIG_FILES = (
    "/etc/default/isc-dhcp-server", "/etc/dhcp/dhcpd.conf", "/etc/dnsmasq.conf",
    "/etc/apache2/sites-available/000-default.conf",
    "/etc/apache2/sites-available/default-ssl.conf",
    "/etc/ssl/private/captive-portal.key", "/etc/ssl/certs/captive-portal.crt",
    "/etc/beef-xss/config.yaml", "/etc/beef-xss/captive-portal.key",
    "/etc/beef-xss/captive-portal.crt",
    *(f"/var/www/html/{name}" for name in (
        "index.php", "register.php", "style.css", ".htaccess",
        "linkedin_login.php", "microsoft_login.php",
        "logo_linkedin.svg", "logo_microsoft.svg")),
)
APACHE_LINK_DIRS = ("/etc/apache2/sites-enabled", "/etc/apache2/mods-enabled")


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=30, **kwargs)


class Session:
    def __init__(self, directory, runner=command):
        self.directory = Path(directory)
        self.run = runner

    def save(self, state):
        temporary = self.directory / "state.new"
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(state, stream)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.directory / "state.json")

    def load(self):
        return json.loads((self.directory / "state.json").read_text(encoding="utf-8"))

    def snapshot_file(self, path, number):
        path = Path(path)
        record = {"path": str(path), "existed": path.exists() or path.is_symlink()}
        if record["existed"]:
            # cp in the legacy caller follows destination links. Fail closed rather
            # than snapshotting a link while its unsaved target is overwritten.
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Expected a regular file: {path}")
            info = path.lstat()
            record.update(uid=info.st_uid, gid=info.st_gid)
            backup = self.directory / "backups" / str(number)
            shutil.copy2(path, backup, follow_symlinks=False)
            record["backup"] = str(backup)
        return record

    def begin(self, interface, paths=CONFIG_FILES, link_dirs=APACHE_LINK_DIRS):
        # Complete every read before permitting the caller to change the host.
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
            raise ValueError("Invalid interface name")
        (self.directory / "backups").mkdir(mode=0o700)
        (self.directory / "generated").mkdir(mode=0o700)
        states = {}
        for service in SERVICES:
            result = self.run("systemctl", "show", service, "--property=ActiveState", "--value")
            active = result.stdout.decode().strip()
            if active not in ("active", "inactive", "failed"):
                raise ValueError(f"Service has an unstable or unknown state: {service}")
            states[service] = active
        forwarding = self.run("sysctl", "-n", "net.ipv4.ip_forward").stdout.decode().strip()
        if forwarding not in ("0", "1"):
            raise ValueError("Cannot determine IPv4 forwarding state")
        link = json.loads(self.run("ip", "-j", "link", "show", "dev", interface).stdout)[0]
        info = self.run("iw", "dev", interface, "info").stdout.decode()
        match = re.search(r"^\s*type (.+)$", info, re.MULTILINE)
        if not match or match[1] not in ("managed", "monitor", "AP"):
            raise ValueError("Cannot determine wireless interface type")
        for name, args in (
            ("addresses", ("ip", "address", "save", "dev", interface)),
            ("routes", ("ip", "route", "save", "table", "all", "dev", interface)),
            ("routes6", ("ip", "-6", "route", "save", "table", "all", "dev", interface)),
        ):
            (self.directory / name).write_bytes(self.run(*args).stdout)
        files = [self.snapshot_file(path, i) for i, path in enumerate(paths)]
        links = {}
        for directory in link_dirs:
            folder = Path(directory)
            links[directory] = {
                item.name: os.readlink(item) for item in folder.iterdir() if item.is_symlink()
            } if folder.exists() else {}
        state = dict(tag="pocket-" + uuid.uuid4().hex, interface=interface,
                     interface_type=match[1], interface_up="UP" in link.get("flags", []),
                     services=states, touched_services=[], forwarding=forwarding,
                     forwarding_dirty=False, interface_dirty=False, files=files,
                     apache_links=links, new_apache_links={}, finished=False)
        self.save(state)
        return state

    def mark(self, field):
        state = self.load()
        state[field] = True
        self.save(state)

    def service(self, action, service):
        state = self.load()
        if service not in SERVICES or action not in ("stop", "restart", "start"):
            raise ValueError("Unsupported service operation")
        if service not in state["touched_services"]:
            state["touched_services"].append(service)
            self.save(state)  # Journal before attempting the mutation.
        self.run("systemctl", action, service)

    def apache(self, executable, name):
        if executable not in ("a2ensite", "a2dissite", "a2enmod"):
            raise ValueError("Unsupported Apache operation")
        # Journal newly created links even if a2enmod only partially succeeds.
        try:
            self.run(executable, name)
        finally:
            state = self.load()
            for directory, original in state["apache_links"].items():
                folder = Path(directory)
                for item in folder.iterdir() if folder.exists() else ():
                    if item.is_symlink() and item.name not in original:
                        state["new_apache_links"][str(item)] = os.readlink(item)
            self.save(state)

    def iptables(self, arguments):
        if not arguments or not any(x in arguments for x in ("-A", "-I", "-D")):
            raise ValueError("Only session rule operations are permitted")
        self.run("iptables", *arguments, "-m", "comment", "--comment", self.load()["tag"])

    def finish(self):
        state = self.load()
        if state["finished"]:
            return []
        errors = []

        def attempt(label, operation):
            try:
                operation()
            except Exception as error:
                errors.append(f"{label}: {type(error).__name__}")

        # Stop consumers before restoring their files and interface.
        for service in reversed(state["touched_services"]):
            attempt(f"stop {service}", lambda s=service: self.run("systemctl", "stop", s))

        def remove_rules():
            saved = self.run("iptables-save").stdout.decode()
            table = None
            for line in saved.splitlines():
                if line.startswith("*"):
                    table = line[1:]
                elif line.startswith("-A ") and table:
                    args = shlex.split(line)
                    # Match the full comment value, never a substring of another rule.
                    if any(args[i:i+2] == ["--comment", state["tag"]]
                           for i in range(len(args) - 1)):
                        args[0] = "-D"
                        attempt("remove session rule", lambda a=args, t=table:
                                self.run("iptables", "-t", t, *a))

        attempt("read firewall rules", remove_rules)
        if state["forwarding_dirty"]:
            attempt("restore forwarding", lambda: self.run(
                "sysctl", "-w", "net.ipv4.ip_forward=" + state["forwarding"]))

        for record in state["files"]:
            attempt("restore " + record["path"], lambda r=record: self.restore_file(r))
        for path, target in state["new_apache_links"].items():
            item = Path(path)
            if item.is_symlink() and os.readlink(item) == target:
                attempt("remove session Apache link", item.unlink)
        for directory, links in state["apache_links"].items():
            for name, target in links.items():
                item = Path(directory) / name
                if not item.exists() and not item.is_symlink():
                    attempt("restore Apache link", lambda p=item, t=target: p.symlink_to(t))

        if state["interface_dirty"]:
            interface = state["interface"]
            attempt("lower interface", lambda: self.run("ip", "link", "set", interface, "down"))
            kind = "__ap" if state["interface_type"] == "AP" else state["interface_type"]
            attempt("restore interface type", lambda: self.run("iw", "dev", interface, "set", "type", kind))
            attempt("clear session addresses", lambda: self.run("ip", "address", "flush", "dev", interface))
            attempt("restore addresses", lambda: self.run("ip", "address", "restore",
                    input=(self.directory / "addresses").read_bytes()))
            attempt("restore link state", lambda: self.run(
                "ip", "link", "set", interface, "up" if state["interface_up"] else "down"))
            attempt("restore routes", lambda: self.run("ip", "route", "restore",
                    input=(self.directory / "routes").read_bytes()))
            attempt("restore IPv6 routes", lambda: self.run("ip", "-6", "route", "restore",
                    input=(self.directory / "routes6").read_bytes()))
        for service in state["touched_services"]:
            if state["services"][service] == "active":
                attempt("start " + service, lambda s=service: self.run("systemctl", "start", s))
        if not errors:
            state["finished"] = True
            self.save(state)
        return errors

    @staticmethod
    def restore_file(record):
        path = Path(record["path"])
        if record["existed"]:
            # Refuse to overwrite unexpected directories, and never follow a new symlink.
            if path.is_symlink():
                path.unlink()
            if path.exists() and not path.is_file():
                raise ValueError("Unexpected directory at recovery destination")
            backup = Path(record["backup"])
            if backup.is_symlink() and path.exists():
                path.unlink()
            shutil.copy2(backup, path, follow_symlinks=False)
            if hasattr(os, "chown"):
                os.chown(path, record["uid"], record["gid"], follow_symlinks=False)
        elif path.exists() or path.is_symlink():
            path.unlink()  # Exact journaled file only; never a directory tree or wildcard.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("begin", "finish", "service", "apache", "iptables", "interface", "forwarding"))
    parser.add_argument("directory")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        parser.error("Recovery operations require root")
    session = Session(args.directory)
    if args.operation == "begin":
        print(session.begin(*args.arguments)["tag"])
    elif args.operation == "finish":
        errors = session.finish()
        for error in errors:
            print(error, file=sys.stderr)
        return bool(errors)
    elif args.operation in ("service", "apache"):
        getattr(session, args.operation)(*args.arguments)
    elif args.operation == "iptables":
        session.iptables(args.arguments)
    else:
        session.mark(args.operation + "_dirty")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError, IndexError) as error:
        # Do not include command stdout/stderr: it may contain sensitive configuration.
        print(f"Session operation failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
