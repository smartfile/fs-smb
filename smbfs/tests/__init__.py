""" Unit tests for smbfs. """
import unittest

from fs.tests import FSTestCases
from fs.tests import ThreadingTestCases

from smbfs import SMBFS


class TestSMBFS(FSTestCases, ThreadingTestCases, unittest.TestCase):
    """ Unit test suite as defined within PyFilesystem. """
    server_name = 'testserver'
    server_IP = 'test IP'
    username = 'testuser'
    password = 'testpass'
    share = 'testuser'

    def setUp(self):
        self.fs = SMBFS(self.username, self.password, self.server_name,
                        self.server_IP, self.share)
        super(TestSMBFS, self).setUp()

    def tearDown(self):
        super(TestSMBFS, self).tearDown()
        self.fs.close()
