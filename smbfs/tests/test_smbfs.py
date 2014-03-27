""" Unit tests for smbfs. """
import unittest

from fs.tests import FSTestCases

from smbfs import SMBFS


class TestSMBFS(FSTestCases, unittest.TestCase):
    """ Unit test suite as defined within Pyfilesystem. """
    server_name = 'testserver'
    server_IP = 'test IP'
    username = 'testuser'
    password = 'testpass'

    def setUp(self):
        self.fs = SMBFS(self.username, self.password, self.server_name,
                        self.server_IP, self.username)
        super(TestSMBFS, self).setUp()

    def tearDown(self):
        super(TestSMBFS, self).tearDown()
        self.fs.close()
