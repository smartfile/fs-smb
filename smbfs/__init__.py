""" Filesystem to access SMB servers.
"""
import datetime
import errno
import random
import socket
import stat
import string

from functools import wraps

from smb.SMBConnection import SMBConnection
from smb.base import NotConnectedError
from smb.base import NotReadyError
from smb.base import OperationFailure

from fs import _thread_synchronize_default
from fs import iotools
from fs.base import FS
from fs.base import synchronize
from fs.errors import DestinationExistsError
from fs.errors import DirectoryNotEmptyError
from fs.errors import FSError
from fs.errors import OperationFailedError
from fs.errors import ParentDirectoryMissingError
from fs.errors import PermissionDeniedError
from fs.errors import RemoteConnectionError
from fs.errors import RemoveRootError
from fs.errors import ResourceInvalidError
from fs.errors import ResourceNotFoundError
from fs.filelike import SpooledTemporaryFile
from fs.filelike import StringIO
from fs.path import abspath
from fs.path import basename
from fs.path import dirname
from fs.path import normpath
from fs.path import pathjoin
from fs.path import recursepath
from fs.remote import RemoteFileBuffer


# Override the default message to display the operation and path together.
PermissionDeniedError.default_message = (
    'Unable to %(opname)s %(path)s: permission denied')


class AccountError(PermissionDeniedError):
    """ Base error for issues with an authenticated account. """


class AccountExpiredError(AccountError):
    default_message = 'Account expired'


class AccountLockedError(AccountError):
    default_message = 'Account locked'


class AccountTimeRestrictedError(AccountError):
    default_message = 'Account restricted from access at this time'


class DeletePendingError(OperationFailedError):
    default_message = 'Unable to access %(path)s: delete pending'


class PasswordChangeRequiredError(AccountError):
    default_message = 'Password change required'


class PasswordExpiredError(AccountError):
    default_message = 'Password expired'


def _conv_smb_errors(outer):
    """ Convert Samba errors into PyFilesystem errors. """
    @wraps(outer)
    def inner(*args, **kwargs):
        try:
            return outer(*args, **kwargs)
        except socket.gaierror as e:
            if e.errno == socket.EAI_NONAME:
                raise RemoteConnectionError(str(e), details=e)
            raise
        except socket.error as e:
            if e.errno in (errno.ECONNREFUSED, errno.EPIPE, errno.ETIMEDOUT):
                raise RemoteConnectionError(str(e), details=e)
            raise
        except OperationFailure as e:
            # Cycle through each message and map the first one to PyFilesystem
            # that is not a successful status (0x00000000).
            share = args[0]
            path = args[1]
            for msg in e.smb_messages:
                # Protocol versions expose the error values differently.
                if msg.protocol == 1:
                    msg_status = msg.status.internal_value
                else:
                    msg_status = msg.status

                if msg_status == 0x0:
                    continue
                elif msg_status == 0x103:
                    # Unknown error, but message says it is not found.
                    raise ResourceNotFoundError(path=path)
                elif msg_status == 0xc000000f:
                    raise ResourceNotFoundError(path=path)
                elif msg_status == 0xc0000022:
                    raise PermissionDeniedError('access', path=path)
                elif msg_status == 0xc0000033:
                    raise ResourceInvalidError(path=path)
                elif msg_status == 0xc0000034:
                    raise ResourceNotFoundError(path=path)
                elif msg_status == 0xc0000035:
                    raise DestinationExistsError(path=path)
                elif msg_status == 0xc000003a:
                    raise ResourceNotFoundError(path=path)
                elif msg_status == 0xc0000056:
                    raise DeletePendingError(path=path)
                elif msg_status == 0xc000006f:
                    raise AccountTimeRestrictedError(path=path)
                elif msg_status == 0xc0000071:
                    raise PasswordExpiredError(path=path)
                elif msg_status == 0xc00000ba:
                    raise ResourceInvalidError(path=path)
                elif msg_status == 0xc00000cc:
                    # Share does not exist.
                    raise ResourceInvalidError(path=share)
                elif msg_status == 0xc00000d0:
                    raise ResourceInvalidError(path=path)
                elif msg_status == 0xc0000101:
                    raise DirectoryNotEmptyError(path=path)
                elif msg_status == 0xc0000103:
                    raise ResourceInvalidError(path=path)
                elif msg_status == 0xc0000193:
                    raise AccountExpiredError(path=path)
                elif msg_status == 0xc0000224:
                    raise PasswordChangeRequiredError(path=path)
                elif msg_status == 0xc0000234:
                    raise AccountLockedError(path=path)
                else:
                    raise Exception('Unhandled SMB error:  {0}'.format(
                        hex(msg_status)))
            raise
        except NotConnectedError as e:
            # Connection does not exist or was disconnected.  Using the wrong
            # NetBIOS name can cause this against a Windows server while Samba
            # will ignore it.
            raise RemoteConnectionError("Disconnected from the SMB server. "
                                        "Check the NetBIOS name.", details=e)
        except NotReadyError as e:
            # Connection has not been successfully authenticated.
            raise RemoteConnectionError(str(e), details=e)
    return inner


def _determine_cause(outer):
    """ Determine specific path raising an exception for src/dst operations.

        The error raised by pysmb does not report which path is the cause.
    """
    @wraps(outer)
    def inner(*args, **kwargs):
        try:
            return outer(*args, **kwargs)
        except DestinationExistsError:
            raise DestinationExistsError(args[2])
        except ResourceNotFoundError:
            # Parent directory does not exist or is not a directory.
            src, dst = args[1:3]
            fs = args[0]
            for p in (src, dst):
                if not fs.exists(p):
                    root = dirname(p)
                    if not fs.isdir(root):
                        if fs.isfile(root):
                            raise ResourceInvalidError(p)
                        else:
                            raise ParentDirectoryMissingError(p)
                    else:
                        raise ResourceNotFoundError(p)
    return inner


def _absnorm_path(num_paths):
    """ Convert path (first) argument to absolute and normalize it.

        For example, pysmb has issues with ".", so "/" is needed.
    """
    def inner_1(func):
        @wraps(func)
        def inner_2(fs, *args, **kwargs):
            new_args = []
            for ndx, arg in enumerate(args):
                if ndx < num_paths:
                    arg = abspath(normpath(arg))
                new_args.append(arg)
            return func(fs, *new_args, **kwargs)
        return inner_2
    return inner_1


class SMBFS(FS):
    """ Filesystem stored on a SMB share.

        This wraps pysmb (https://pypi.python.org/pypi/pysmb) to access SMB
        shares.
    """
    _meta = {'thread_safe': True,
             'virtual': False,
             'read_only': False,
             'unicode_paths': True,
             'case_insensitive_paths': False,  # It depends upon the server.
             'network': True,
             'atomic.makedir': True,
             'atomic.removedir': False,
             'atomic.rename': True,
             'atomic.setcontents': False,
             'mime_type': 'virtual/smb'}

    def __init__(self, username, password, server_name, server_IP, share,
                 port=139, client_name=None,
                 thread_synchronize=_thread_synchronize_default):
        self.username = username
        self.password = password
        self.server_name = server_name
        self.share = share
        self.server_IP = server_IP
        self.port = port
        self._conn = None

        # Automatically generate a client name if not provided.
        if client_name is None:
            self.client_name = 'fs{0}'.format(''.join(random.choice(
                string.uppercase + string.digits) for i in xrange(12)))
        else:
            self.client_name = client_name

        super(SMBFS, self).__init__(thread_synchronize=thread_synchronize)

    def __getstate__(self):
        # Close the connection to allow pickling.
        self.close()
        return super(SMBFS, self).__getstate__()

    def _listPath(self, path, list_contents=False):
        """ Path listing with SMB errors converted. """
        # Explicitly convert the SMB errors to be able to catch the
        # PyFilesystem error while listing the path.
        if list_contents:
            try:
                # List all contents of a directory.
                return _conv_smb_errors(self.conn.listPath)(
                    self.share, normpath(path))
            except ResourceNotFoundError:
                if self.isfile(path):
                    raise ResourceInvalidError(path)
                raise
        else:
            # List a specific path (file or directory) by listing the contents
            # of the containing directory and comparing the filename.
            pathdir = dirname(path)
            searchpath = basename(path)
            for i in _conv_smb_errors(self.conn.listPath)(self.share, pathdir):
                if i.filename == '..':
                    continue
                elif ((i.filename == '.' and searchpath == '') or
                      i.filename == searchpath):
                    return i
            raise ResourceNotFoundError(path)

    @_conv_smb_errors
    def _retrieveFile(self, path, file_obj):
        """ Retrieve a file.  Convert SMB errors. """
        # Retrieve a file then rewind it to the beginning as pysmb leaves it at
        # the end of the file.
        self.conn.retrieveFile(self.share, path, file_obj)
        file_obj.seek(0)

    @_conv_smb_errors
    def _rename(self, src, dst):
        """ Rename a path.  Convert SMB errors. """
        self.conn.rename(self.share, src, dst)

    @_conv_smb_errors
    def _create_dir(self, path):
        """ Create a directory.  Convert SMB errors. """
        self.conn.createDirectory(self.share, path)

    @_conv_smb_errors
    def _remove_dir(self, path):
        """ Remove a directory.  Convert SMB errors. """
        self.conn.deleteDirectory(self.share, path)

    @synchronize
    @_conv_smb_errors
    @_absnorm_path(1)
    def setcontents(self, path, data=b'', encoding=None, errors=None,
                    chunk_size=1024 * 64):
        # Remove then write contents.  There is no method to erase the contents
        # of a file when writing to it using pysmb.
        try:
            self.remove(path)
        except ResourceNotFoundError:
            pass

        if not hasattr(data, 'read'):
            data = StringIO(data)
        self.conn.storeFile(self.share, path, data)

    @property
    @synchronize
    @_conv_smb_errors
    def conn(self):
        """ Connection to server. """
        if self._conn is None:
            self._conn = SMBConnection(
                self.username, self.password, self.client_name,
                self.server_name, use_ntlm_v2=True)
            self._conn.connect(self.server_IP, self.port)
        return self._conn

    @synchronize
    def close(self):
        super(SMBFS, self).close()
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @synchronize
    @iotools.filelike_to_stream
    @_absnorm_path(1)
    def open(self, path, mode='r', **kwargs):
        if self.isdir(path):
            raise ResourceInvalidError(path)

        # Erase the contents of a file upon write.
        if 'w' in mode:
            file_obj = None
            self.setcontents(path, StringIO())
        else:
            file_obj = SpooledTemporaryFile()
            self._retrieveFile(path, file_obj)
        return RemoteFileBuffer(self, path, mode, file_obj)

    @synchronize
    @_absnorm_path(1)
    def isfile(self, path):
        try:
            return not self._listPath(path).isDirectory
        except FSError:
            return False

    @synchronize
    @_absnorm_path(1)
    def isdir(self, path):
        try:
            return self._listPath(path).isDirectory
        except FSError:
            return False

    def _conv_smb_info_to_fs(self, smb_info):
        """ Convert SMB information into PyFilesystem info dict. """
        return {'size': smb_info.file_size,
                'st_mode': (stat.S_IFDIR if smb_info.isDirectory else
                            stat.S_IFREG),
                'created_time': datetime.datetime.fromtimestamp(
                    smb_info.create_time),
                'st_ctime': smb_info.create_time,
                'accessed_time': datetime.datetime.fromtimestamp(
                    smb_info.last_access_time),
                'st_atime': smb_info.last_access_time,
                'modified_time': datetime.datetime.fromtimestamp(
                    smb_info.last_write_time),
                'st_mtime': smb_info.last_write_time}

    @synchronize
    def listdirinfo(self, path="./", wildcard=None, full=False, absolute=False,
                    dirs_only=False, files_only=False):
        listing = []
        for i in self._listPath(path, list_contents=True):
            # Skip ., .. and undesired types.
            if (i.filename == '.' or i.filename == '..' or
                (dirs_only and not i.isDirectory) or
                (files_only and i.isDirectory)):
                continue

            # Rely on the PyFilesystem helper to determine if the path should
            # be listed.  An empty listing indicates to not list the path.
            name = self._listdir_helper(path, [i.filename], wildcard, full,
                                        absolute, False, False)
            if len(name) == 1:
                listing.append((name[0], self._conv_smb_info_to_fs(i)))
        return listing

    @synchronize
    def listdir(self, path="./", wildcard=None, full=False, absolute=False,
                dirs_only=False, files_only=False):
        # Wrap whatever listdirinfo returns while discarding the info.
        return [name[0] for name in self.listdirinfo(
            path, wildcard, full, absolute, dirs_only, files_only)]

    @synchronize
    def makedir(self, path, recursive=False, allow_recreate=False):
        # Create a directory from the top downwards depending upon the flags.
        paths = recursepath(path) if recursive else (path, )
        for p in paths:
            if p == '/':
                continue

            # Try to create a directory first then ask for forgiveness.
            try:
                self._create_dir(p)
            except DestinationExistsError as e:
                if self.isfile(p):
                    raise ResourceInvalidError(path)
                elif self.isdir(p):
                    if not recursive and not allow_recreate:
                        raise DestinationExistsError(path)
            except ResourceNotFoundError as e:
                if not recursive and not self.isdir(dirname(p)):
                    raise ParentDirectoryMissingError(path)
                e.path = path
                raise
            except FSError as e:
                e.path = path
                raise

    @synchronize
    @_conv_smb_errors
    @_absnorm_path(1)
    def remove(self, path):
        self.conn.deleteFiles(self.share, path)

    @synchronize
    @_conv_smb_errors
    @_absnorm_path(1)
    def removedir(self, path, recursive=False, force=False):
        if path == '/':
            raise RemoveRootError(path)

        # Remove directory tree from the bottom upwards depending upon the
        # flags.
        if force:
            for (del_dir, del_files) in self.walk(path, search='depth',
                                                  ignore_errors=True):
                for f in del_files:
                    self.remove(pathjoin(del_dir, f))
                self.removedir(del_dir)
        elif recursive:
            paths = recursepath(path, reverse=True)[:-1]
            for p in paths:
                self._remove_dir(p)
        else:
            self._remove_dir(path)

    @synchronize
    @_absnorm_path(2)
    @_determine_cause
    def rename(self, src, dst):
        self._rename(src, dst)

    @synchronize
    @_absnorm_path(1)
    def getinfo(self, path):
        return self._conv_smb_info_to_fs(self._listPath(path))
