fs-smb
======

PyFilesystem interface for SMB filesystems

Note: This is for pyfilesystem2 only.


Running Locally:

.. code-block::

   from smbfs import SMBFS
   smb = SMBFS('username', 'password', 'Remote NETBIOS Name', '0.0.0.0', 'share')

   # Try out connection out:
   smb.listdir()

