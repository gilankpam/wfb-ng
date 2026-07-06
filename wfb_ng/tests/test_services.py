# Unit tests for services.key_arg: a stream with keypair=None launches
# wfb_tx/wfb_rx with no -K (plaintext); a set keypair yields -K <path>.
from twisted.trial import unittest

from wfb_ng import services
from wfb_ng.config_parser import Section


class KeyArgTestCase(unittest.TestCase):
    def test_keypair_set(self):
        cfg = Section()
        cfg.keypair = 'gs.key'
        arg = services.key_arg(cfg)
        self.assertTrue(arg.startswith('-K '))
        self.assertTrue(arg.endswith('gs.key'))

    def test_keypair_none(self):
        cfg = Section()
        cfg.keypair = None
        self.assertEqual(services.key_arg(cfg), '')
