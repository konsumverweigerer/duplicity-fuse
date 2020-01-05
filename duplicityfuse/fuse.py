#!/usr/bin/env python
'''
 Original written by Peter Gruber, changes to make work with
 more recent Python versions & Duplicity made by Jose Riha <jose1711 gmail com>

 Copyright (C) 2008 Peter Gruber <nokos@gmx.net>

 This file is in part based on code of duplicity by.
 Ben Escoto <bescoto@stanford.edu>
'''

from .filesystem import DuplicityFS

import sys

import fuse
from fuse import Fuse

def mount():
    usage="""
Userspace duplicity filesystem

""" + Fuse.fusage

    server = DuplicityFS(version="%prog " + fuse.__version__,
                     usage=usage,
                     dash_s_do='setsingle')
    server.parser.add_option(mountopt="url", metavar="PATH", default='scp://localhost/',
                             help="backup url [default: %default]")
    server.parser.add_option(mountopt="passwordfd", metavar="NUM",
                             help="filedescriptor for the password")
    server.parser.add_option(mountopt="passphrasefd", metavar="NUM",
                             help="filedescriptor for the passphrase")
    server.parser.add_option(mountopt="debuglevel", metavar="NUM",
                             help="debug level")
    server.parser.add_option(mountopt="foreground", metavar="NUM",
                             help="foreground")
    server.parser.add_option(mountopt="filemode", metavar="NUM", default="0",
                             help="file mode (0=full, 1=nosizes)")
    for n in server.options:
        server.parser.add_option(mountopt=n.replace("-",""), metavar="STRING",
                                 help=n+" option from duplicity")
    for n in server.no_options:
        server.parser.add_option(mountopt=n.replace("-",""),
                                 help=n+" option from duplicity")
    server.parse(values=server, errex=1)

    if server.foreground > 0:
        server.fuse_args.setmod('foreground')

    try:
        if server.fuse_args.mount_expected():
            server.runduplicity()
    except OSError as e:
        print("can't enter root of underlying filesystem", file=sys.stderr)
        sys.exit(5)

    try:
        server.main()
    except Exception as e:
        server.parser.print_help()
        sys.exit(10)


if __name__ == '__main__':
    mount()
