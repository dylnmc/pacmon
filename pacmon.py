#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""{}----------------------------------------------------
 _ __   __ _  ___ _ __ ___   ___  _ __              \
| '_ \ / _` |/ __| '_ ` _ \ / _ \| '_ \              \
| |_) | (_| | (__| | | | | | (_) | | | |              \
| .__/ \__,_|\___|_| |_| |_|\___/|_| |_|               \
|_| {} a cli utility for storing snapshots for arch linux {}\
---------------------------------------------------------{}"""

from collections import namedtuple
import argparse
import binascii
import datetime
import getpass
import hashlib
import os
import pyalpm
import sqlite3
import sys


Verifier = namedtuple("Verifier", "valid new")


def main(args):
    """ main

        :param args: args from argparse
    """
    username = args.user
    command = args.command
    arguments = args.arguments
    conn, c = setupDb()

    if command == "setpass":
        change_password(c, username)
        conn.commit()

    handle, localdb, core = setupAlpm()

    verifier = verify_user(c, username)
    if command == "snap":
        create_snap(c, localdb, core, username)
        conn.commit()
    elif command == "list":
        list_snaps(c, username)
    elif command == "show":
        if not arguments:
            print("Requres a snapid")
            return
        try:
            snapid = int(arguments[0])
        except ValueError:
            print("Argument for 'snapid' must be an integer")
        show_snap(c, username, snapid)


def create_snap(c, localdb, core, username):
    """ create a new snapshot

        :param c: db cursor
        :param localdb: alpm localdb "database"
    """
    c.execute("SELECT userid FROM Users where username=?", (username,))
    fetch = c.fetchone()
    if fetch is None:
        print(f"Error: username {username!r} doesn't exist in database")
        return
    userid = fetch[0]
    c.execute("INSERT INTO Snapshots VALUES (?, ?, ?)",
            (None, userid, datetime.datetime.now()))
    snapshotid = c.lastrowid

    for pkg in localdb.search(".*"):
        name, version, arch, licenses = pkg.name, pkg.version, pkg.arch, pkg.licenses
        c.execute("SELECT pkgid FROM Packages WHERE pkgname=? AND pkgver=? AND pkgarch=?",
                (pkg.name, pkg.version, arch))
        pkgid = c.lastrowid
        fetch = c.fetchall()
        if not fetch or fetch[0] is None:
            c.execute("INSERT INTO Packages VALUES (?, ?, ?, ?, ?)",
                    (None, name, version, arch, ";".join(licenses)))
        c.execute("INSERT INTO Uploads VALUES (?, ?, ?)", (None, snapshotid, pkgid))


def list_snaps(c, username):
    c.execute("SELECT userid FROM Users where username=?", (username,))
    fetch = c.fetchone()
    if fetch is None:
        print(f"Error: username {username!r} doesn't exist in database")
        return
    userid = fetch[0]
    c.execute("SELECT * FROM Snapshots WHERE userid=?", (userid,))
    fetch = c.fetchall()
    if not fetch:
        print("No results")
        return
    print(f"All Snapshots for {username!r}", end=": ")
    print(", ".join(str(i[0]) for i in fetch if i is not None))


def show_snap(c, username, snapshotid):
    c.execute("SELECT userid FROM Users where username=?", (username,))
    fetch = c.fetchone()
    if fetch is None:
        print(f"Error: username {username!r} doesn't exist in database")
        return
    userid = fetch[0]
    c.execute("SELECT * from Packages INNER JOIN Uploads on Packages.pkgid == Uploads.pkgid")
    fetch = c.fetchall()
    if not fetch:
        print("No results")
    print(f"All Packages from Snapshot {snapshotid}: ")
    print("; ".join(str(i[1]) for i in fetch if i is not None))


def change_password(c, username):
    """ change password for username

        :param c: db cursor
        :param username: user's name
    """
    c.execute("SELECT * FROM Users where username=?", (username,))
    user = c.fetchone()
    new = user is None
    if user is not None:
        # user in database
        _, _, hash = user
        valid = hash is None
        print(hash, hash is None)
        if not valid:
            # password required
            try:
                if verify_password(hash, getpass.getpass(f"OLD password for {username!r}: ")):
                    valid = True
            except KeyboardInterrupt:
                print("\nctrl-c intercepted: Skipping password")
        if not valid:
            print("invalid password")
            return
    try:
        pwd = None
        while pwd is None:
            pwd = getpass.getpass(f"(optional) NEW password for {username!r}: ")
            if pwd:
                cpwd = getpass.getpass(f"confirm NEW password for {username!r}: ")
                if pwd != cpwd:
                    print("passwords do not match")
                    pwd = None
            else:
                print("No password used")
                pwd = ""
    except KeyboardInterrupt:
        print("\nctrl-c intercepted: Skipping password")
    if new:
        c.execute("INSERT INTO Users VALUES (?, ?, ?)", (None, username, hash_password(pwd)))
        print(f"New user user created: {username!r}")
    else:
        c.execute("UPDATE Users SET pass=? WHERE username=?", (hash_password(pwd), username))
        print("password changed successfully")



def verify_user(c, username):
    """ create new user or verify password

        if username doesn't exist, prompt for optional password;
        else check for password and authenticate then return or just return.

        :param c: db cursor
        :param username: username to verify
        :return: True if new user, False otherwise
    """
    c.execute("SELECT * FROM Users where username=?", (username,))
    user = c.fetchone()
    if user is None:
        # user not in database
        pwd = None
        try:
            pwd = None
            while pwd is None:
                pwd = getpass.getpass(f"password for {username!r}: ")
                if pwd:
                    cpwd = getpass.getpass(f"confirm password for {username!r}: ")
                    if pwd != cpwd:
                        print("passwords do not match")
                        pwd = None
                else:
                    print("No password used")
                    pwd = ""
        except KeyboardInterrupt:
            print("\nctrl-c intercepted: Skipping password")
        c.execute("INSERT INTO Users VALUES (?, ?, ?)", (None, username, hash_password(pwd)))
        print(f"New user user created: {username!r}")
        valid, new = True, True
    else:
        # user in database
        _, _, hash = user
        valid = hash is None
        new = False
        if not valid:
            # password required
            try:
                if verify_password(hash, getpass.getpass(f"password for {username!r}: ")):
                    valid = True
            except KeyboardInterrupt:
                print("\nctrl-c intercepted: Skipping password")
    return Verifier(valid=valid, new=new)



def setupDb():
    """ setup database, verify user, return db connection and cursor

        :return: db connection, db cursor
    """
    conn = sqlite3.connect("pacmon.db")
    c = conn.cursor()

    # Users: (userid, username, useremail, pass
    c.execute(
    """CREATE TABLE IF NOT EXISTS Users
        (
            userid INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            pass TEXT
        )
    """)

    # Packages: (pkgid, pkgname, pkgver, pkgarch, licenses)
    c.execute(
    """CREATE TABLE IF NOT EXISTS Packages
        (
            pkgid INTEGER PRIMARY KEY AUTOINCREMENT,
            pkgname TEXT NOT NULL,
            pkgver TEXT,
            pkgarch TEXT,
            licenses TEXT
        )
    """)

    # Snapshots: (snapshotid, userid, datetime)
    c.execute(
    """CREATE TABLE IF NOT EXISTS Snapshots
        (
            snapshotid INTEGER PRIMARY KEY AUTOINCREMENT,
            userid INTEGER NOT NULL,
            datetime TIMESTAMP NOT NULL,

            FOREIGN KEY(userid) REFERENCES Users(userid) ON DELETE CASCADE
        )
    """)

    # Uploads: (uploadid, snapshotid, pkgid)
    c.execute(
    """CREATE TABLE IF NOT EXISTS Uploads
        (
            uploadid INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshotid INTEGER NOT NULL,
            pkgid INTEGER NOT NULL,

            FOREIGN KEY(snapshotid) REFERENCES Snapshots(shapshotid) ON DELETE CASCADE,
            FOREIGN KEY(pkgid) REFERENCES Packages(pkgid) ON DELETE CASCADE
        )
    """)

    # Dependencies: (dependencyid, pkgid, depid)
    c.execute(
    """CREATE TABLE IF NOT EXISTS Dependencies
        (
            dependencyid INTEGER NOT NULL PRIMARY KEY,
            pkgid INTEGER NOT NULL,
            depid INTEGER NOT NULL,

            FOREIGN KEY(pkgid) REFERENCES Packages(pkgid) ON DELETE CASCADE
            FOREIGN KEY(depid) REFERENCES Packages(pkgid) ON DELETE CASCADE
        )
    """)

    conn.commit()
    return conn, c


def setupAlpm():
    """ set up alpm and get handle/localdb

        :return: alpm handle, localdb 'database'
    """
    handle = pyalpm.Handle("/", "/var/lib/pacman")
    core = handle.register_syncdb("core", pyalpm.SIG_DATABASE)
    localdb = handle.get_localdb()
    return handle, localdb, core


def hash_password(password):
    """ hash a password for storing

        if the salt is not passed, then generate one. otherwise, the salt is coming from the
        database (or other location) presumably

        :param password: plaintext password to hash
        :param salt: if passed, use this salt, otherwise, generate a salt
        :return: securely hashed password, salt
    """
    if not password:
        return None
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode("ascii")
    pwdhash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode("ascii")

def verify_password(stored_password, provided_password):
    """ verify a stored password against one provided by user

        :param stored_password: stored (hashed) password
        :param provided_password: plaintext (unhashed) password
    """
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac("sha512", provided_password.encode("utf-8"), salt.encode("ascii"), 100000)
    pwdhash = binascii.hexlify(pwdhash).decode("ascii")
    return pwdhash == stored_password


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.format("\x1b[34;1m", "\x1b[35;22m", "\x1b[34;1m", "\x1b[0m"),
            formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-u", "--user", help="optional username to use for transactions", type=str, default=getpass.getuser())
    parser.add_argument("-s", "--snap", help="select a snapshot for various commands", type=int)
    parser.add_argument("command", help="command to create and list snapshots, show licenses", choices=("snap", "list", "licenses", "show", "setpass"))
    parser.add_argument("arguments", help="extra arguments for some commands", nargs="*")
    main(parser.parse_args())

