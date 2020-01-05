'''
 Original written by Peter Gruber, changes to make work with
 more recent Python versions & Duplicity made by Jose Riha <jose1711 gmail com>

 Copyright (C) 2008 Peter Gruber <nokos@gmx.net>

 This file is in part based on code of duplicity by.
 Ben Escoto <bescoto@stanford.edu>
'''

# python2 compatibility
from __future__ import print_function

import os
from os.path import join, sep
import stat
import errno
import sys
import getpass
import logging

from xml.etree.cElementTree import Element, SubElement
from datetime import datetime
from time import mktime

from duplicity import commandline, diffdir, dup_temp, file_naming, globals, gpg, patchdir
try:
    from duplicity import collections
except Exception:
    from duplicity import dup_collections as collections
from duplicity import log as duplicity_log
import fuse
from fuse import Fuse, Stat, Direntry

log = logging.getLogger("duplicity-fuse")

filename_tdp = {}

if not hasattr(fuse, '__version__'):
    raise RuntimeError(
        "your fuse-py doesn't know of fuse.__version__, probably it's too old.")

fuse.fuse_python_api = (0, 2)


def pathencode(s):
    return str(s.__hash__())


def date2num(ff):
    return mktime(ff.timetuple()) + 1e-6 * ff.microsecond


def date2str(ff):
    return ff.strftime("%Y%m%d%H%M%S")


def str2date(ff):
    return datetime.strptime(ff, "%Y%m%d%H%M%S")


class DuplicityStat(Stat):
    def __init__(self):
        self.st_mode = 0
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_size = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0


class DuplicityFS(Fuse):
    debuglevel = 0
    foreground = 0
    filemode = 0
    options = ["file-to-restore", "archive-dir", "encrypt-key", "num-retries",
               "scp-command", "sftp-command", "sign-key", "timeout", "volsize",
               "verbosity", "gpg-options", "ssh-options"]
    no_options = ["allow-source-mismatch", "force", "ftp-passive",
                  "ftp-regular", "no-encryption",
                  "no-print-statistics", "null-separator",
                  "short-filenames"]
    url = None
    passphrasefd = None
    passwordfd = None
    filecache = {}
    col_stats = None
    dates = []
    dircache = {}

    def fill_cache(self, path):
        if self.dircache[path] is None:
            debug_log("filling cache " + path)
            self.dircache[path] = self.get_path_content(path)
        return self.dircache[path]

    def get_path_content(self, path):
        for date, type in self.date_types:
            if date2str(date) in path:
                debug_log("filling cache for " + str(date) + " " + path)
                timestamp = date2num(date)
                return get_filetree(path,
                                    self.col_stats
                                    .get_signature_chain_at_time(timestamp)
                                    .get_fileobjs(timestamp))

    def readdir(self, path, offset):
        debug_log("readdir " + path)
        try:
            return self.read_dir(path)
        except Exception as e:
            debug_log("could not read dir: " + str(e))

    def read_dir(self, path):
        debug_log("reading directory " + path)
        if path == '/':
            for r in self.dircache.keys():
                yield Direntry(r)
        else:
            path = path[1:].split(sep)
            dir_entry = find_path(self.fill_cache(path[0]), path[1:])
            debug_log("read dir " + path[0] + ": " + str(dir_entry))
            for file in dir_entry.getchildren():
                yield Direntry(file.get("name"))

    def getattr(self, path):
        debug_log("getattr " + path)
        try:
            return self.get_attr(path)
        except Exception as e:
            debug_log("could not get attributes: " + str(e))

    def get_attr(self, path):
        debug_log("getting attributes " + path)
        st = DuplicityStat()
        if path == '/':
            st.st_mode = stat.S_IFDIR | 0o755
            st.st_nlink = 1 + len(self.dircache.keys())
            return st
        p = path[1:].split(sep)
        if len(p) == 1:
            if p[0] not in self.dircache:
                return -errno.ENOENT
            st.st_mode = stat.S_IFDIR | 0o755
            st.st_nlink = 2
            ctime = date2num(str2date(p[0].split("_")[0]))
            st.st_ctime = ctime
            st.st_mtime = ctime
            st.st_atime = ctime
            return st
        e = find_path(self.fill_cache(p[0]), p[1:])
        if e is None:
            return -errno.ENOENT
        mode = int((3 * '{:b}').format(*[int(x)
                                         for x in e.get("perm").split()[-1]]),
                   base=2)
        if e.get("type") == 'dir':
            st.st_mode = stat.S_IFDIR | mode
            e.set("size", 0)
        else:
            st.st_mode = stat.S_IFREG | mode
        # need to read size from filearch? not in signature?
        if int(self.filemode) == 0 and e.get("size") < 0:
            ds = [d[0] for d in self.date_types if date2str(d[0]) in p[0]]
            np = join(*p[1:])
            files = restore_get_patched_rop_iter(
                self.col_stats, date2num(ds[0]), tuple(p[1:]))
            for x in files[0]:
                lp = join(
                    *[y for y in (np + sep + x.get_relative_path()).split(sep)
                      if y != '.'])
                debug_log("looking at %s for %s" % (lp, np))
                le = find_path(self.dircache[p[0]], lp.split(sep))
                if le is None:
                    debug_log("not found in dircache: " + str(le))
                    continue
                if le.get("size") < 0:
                    le.set("size", x.getsize())
                if lp == np:
                    debug_log("found " + np)
                    break
            for x in files[1]:
                x.close()
        elif e.get("size") < 0:
            e.set("size", 0)
        st.st_size = e.get("size")
        st.st_uid = e.get("uid")
        st.st_gid = e.get("gid")
        st.st_mtime = e.get("mtime")
        st.st_nlink = 1 + len(e.getchildren())
        return st

    def open(self, path, flags):
        p = path[1:].split(sep)
        if path == '/' or len(p) == 1:
            return -errno.ENOENT
        e = find_path(self.dircache[p[0]], p[1:])
        if e is None or e.get("type") == 'dir':
            return -errno.ENOENT
        if flags & os.O_RDWR:
            return -errno.ENOENT
        if flags & os.O_WRONLY:
            return -errno.ENOENT
        return 0

    def read(self, path, size, offset):
        p = path[1:].split(sep)
        if path == '/' or len(p) == 1:
            return ''
        e = find_path(self.dircache[p[0]], p[1:])
        if e is None or e.get("type") == 'dir':
            return ''
        if path in self.filecache:
            dat = self.filecache[path]
            return dat[offset:(offset + size)]
        ds = [date for date, type in self.date_types if date2str(date) in p[0]]
        files = restore_get_patched_rop_iter(
            self.col_stats, date2num(ds[0]), tuple(p[1:]))
        np = join(*p[1:])
        dat = None
        s = 0
        for f in files[0]:
            lp = join(
                *[y for y in (np + sep + f.get_relative_path()).split(sep)
                  if y != '.'])
            if lp == np:
                dat = f.get_data()
                s = f.getsize()
                break
        for f in files[1]:
            f.close()
        if dat is not None:
            offset = min(s - 1, offset)
            size = min(s - offset, size)
            self.filecache[path] = dat
            return dat[offset:(offset + size)]
        return ''

    def runduplicity(self):
        if not self.url:
            return
        duplicity_log.setup()
        duplicity_log.setverbosity(int(self.debuglevel))
        log.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))

        if self.passphrasefd:
            self.passphrasefd = int(self.passphrasefd)
        if self.passwordfd:
            self.passwordfd = int(self.passwordfd)
        if self.url.find("file:/") != 0:
            get_backendpassphrase(self.passwordfd)
        opts = []
        self_dict = vars(self)
        for option in self.options:
            value = self_dict.get(option.replace("-", ""))
            if value:
                opts.append("--%s=%s" % (option, value))
        for option in self.no_options:
            if option.replace("-", "") in self_dict:
                opts.append("--%s" % (option))
        self.options = []
        parameter = ["list-current-files", "--ssh-askpass"] + opts + [self.url]
        debug_log("processing %s" % (" ".join(parameter)))
        sys.argv = ["duplicity"] + parameter
        action = commandline.ProcessCommandLine(parameter)
        debug_log("running action %s" % (action))
        globals.gpg_profile.passphrase = get_passphrase(self.passphrasefd)
        self.col_stats = collections.CollectionsStatus(
            globals.backend,
            globals.archive_dir,
            "collection-status").set_values()
        self.date_types = [(datetime.fromtimestamp(s.get_time()), s.type)
                           for chain in self.col_stats.all_backup_chains
                           for s in chain.get_all_sets()]
        self.dircache.update(
            {(date2str(timestamp) + '_' + type): None
             for timestamp, type in self.date_types})
        debug_log("initialized cache: " + str(self.date_types)
                  + ", " + str(self.dircache))


def debug_log(message, level=5):
    log.warning(message)
    duplicity_log.Log("duplicity_fuse: " + message, level)
    with open("/tmp/log", 'a') as f:
        f.write(message + "\n")


def find_path(root, path):
    if len(path) == 0:
        return root
    dir_path = path[0]
    encode_dir = pathencode(dir_path)
    dir_entry = root.find(encode_dir)
    if dir_entry is None:
        debug_log("node " + dir_path + "(" + encode_dir + ") in "
                  + str(root) + " not found")
        return None
    if len(path) == 1:
        debug_log("node " + dir_path + "(" + encode_dir + ") in "
                  + str(root) + " found")
        return dir_entry
    debug_log("searching " + path[1] + " in "
              + dir_path + "(" + encode_dir + ") in " + str(root))
    return find_path(dir_entry, path[1:])


def get_filetree(name, files):
    # TODO: use more efficient structure
    root = Element(name)
    debug_log("reading filetree for " + len(files) + " files")
    for file in diffdir.get_combined_path_iter(files):
        if file.difftype == 'deleted':
            continue
        stat = file.stat
        uid, gid, mtime, size = (stat.st_uid, stat.st_gid, stat.st_mtime,
                                 stat.st_size) if stat else (0, 0, 0, 0)
        path = file.get_relative_path()
        debug_log("reading file in tree " + path)
        if path == '.':
            continue
        if path[0:2] == './':
            path = path[2:]
        extend_filetree(root, path.split(sep), file.getperms(),
                        size, mtime, uid, gid, file.type)
    for file in files:
        file.close()
    return root


def get_passphrase(fd=None):
    """Get passphrase from environment or, failing that, from user"""
    try:
        return os.environ['PASSPHRASE']
    except KeyError:
        pass
    debug_log("PASSPHRASE variable not set, asking user.")
    while 1:
        if not fd:
            pass1 = getpass.getpass("GnuPG passphrase: ")
        else:
            pass1 = os.fdopen(fd).read()
        if not pass1 and not globals.gpg_profile.recipients:
            print(
                "Cannot use empty passphrase with symmetric encryption!"
                + " Please try again.")
            continue
        os.environ['PASSPHRASE'] = pass1
        return pass1


def get_backendpassphrase(fd=None):
    """Get passphrase from environment or, failing that, from user"""
    try:
        return os.environ['FTP_PASSWORD']
    except KeyError:
        pass
    debug_log("FTP_PASSWORD variable not set, asking user.")
    while 1:
        if not fd:
            pass1 = getpass.getpass("Backend passphrase: ")
        else:
            pass1 = os.fdopen(fd).read()
        if not pass1:
            print("Need Backend passphrase!  Please try again.")
            continue
        os.environ['FTP_PASSWORD'] = pass1
        return pass1


def restore_get_patched_rop_iter(col_stats, time, index=()):
    """Return iterator of patched ROPaths of desired restore data"""
    backup_chain = col_stats.get_backup_chain_at_time(time)
    assert backup_chain, col_stats.all_backup_chains
    backup_setlist = backup_chain.get_sets_at_time(time)

    def get_fileobj_iter(backup_set):
        """Get file object iterator from backup_set contain given index"""
        manifest = backup_set.get_manifest()
        for vol_num in manifest.get_containing_volumes(index):
            a = restore_get_enc_fileobj(backup_set.backend,
                                        backup_set.volume_name_dict[vol_num],
                                        manifest.volume_info_dict[vol_num])
            if a:
                yield a
    tarfiles = (patchdir.TarFile_FromFileobjs(x)
                for x in (get_fileobj_iter(s) for s in backup_setlist))
    debug_log("looking through: " + str(tarfiles))
    return (patchdir.tarfiles2rop_iter(tarfiles, index), tarfiles)


def restore_get_enc_fileobj(backend, filename, volume_info):
    """Return plaintext fileobj from encrypted filename on backend """
    global filename_tdp
    parseresults = file_naming.parse(filename)
    if filename in filename_tdp:
        tdp = filename_tdp[filename]
    else:
        tdp = dup_temp.new_tempduppath(parseresults)
        filename_tdp[filename] = tdp

    backend.get(filename, tdp)
    if not restore_check_hash(volume_info, tdp):
        return None
    fileobj = tdp.filtered_open_with_delete("rb")
    if parseresults.encrypted and globals.gpg_profile.sign_key:
        restore_add_sig_check(fileobj)
    return fileobj


def restore_check_hash(volume_info, vol_path):
    """Check the hash of vol_path path against data in volume_info"""
    hash_pair = volume_info.get_best_hash()
    if hash_pair:
        calculated_hash = gpg.get_hash(hash_pair[0], vol_path)
        if calculated_hash != hash_pair[1]:
            debug_log(("Invalid data - %s hash mismatch:\nCalculated hash: %s"
                      + "\nManifest hash: %s\n") %
                      (hash_pair[0], calculated_hash, hash_pair[1]))
            return False
    return True


def restore_add_sig_check(fileobj):
    """Require signature when closing fileobj matches sig in gpg_profile"""
    assert (isinstance(fileobj, dup_temp.FileobjHooked)
            and isinstance(fileobj.fileobj, gpg.GPGFile)), fileobj

    def check_signature():
        """Thunk run when closing volume file"""
        actual_sig = fileobj.fileobj.get_signature()
        if actual_sig != globals.gpg_profile.sign_key:
            log.FatalError("Volume was not signed by key %s, not %s" %
                           (actual_sig, globals.gpg_profile.sign_key))
    fileobj.addhook(check_signature)


def extend_filetree(root, path, perm, size, mtime, uid, gid, type):
    debug_log("extending " + str(root) + " with " + str(path))
    if len(path) == 1:
        path = path[0]
        encoded_path = pathencode(path)
        file_element = next((file
                            for file in root.getchildren()
                            if file.tag == encoded_path), None)
        if file_element is not None:
            debug_log("found " + path
                      + "(" + encoded_path + ") in " + str(root))
            return
        file_element = SubElement(root, encoded_path)
        debug_log("added " + path
                  + "(" + encoded_path + ") to " + str(root))
        file_element.set("perm", perm)
        file_element.set("size", -1)
        file_element.set("mtime", mtime)
        file_element.set("uid", uid)
        file_element.set("gid", gid)
        file_element.set("type", type)
        file_element.set("name", path)
    else:
        dir_path, path = path[0], path[1:]
        encoded_dir = pathencode(dir_path)
        dir_element = next((file
                            for file in root.getchildren()
                            if file.tag == encoded_dir), None)
        if dir_element is not None:
            debug_log(
                "adding " + dir_path + " to " + dir_element + "(" + encoded_dir
                + ") in " + str(root))
        else:
            dir_element = SubElement(root, encoded_dir)
            debug_log("new " + dir_path + "(" + encoded_dir
                      + ") in " + str(root))
        extend_filetree(dir_element, path, perm, size, mtime, uid, gid, type)
