# B5 test: services.fec_tx_args / fec_rx_args shape-check.
#
# Asserts the helpers emit the exact CLI fragments that wfb_tx / wfb_rx
# expect. If this drifts, operators running either codec break silently.

from twisted.trial import unittest

from wfb_ng.config_parser import Section
from wfb_ng.services import fec_tx_args, fec_rx_args


def _cfg_block():
    c = Section()
    c.fec_type = 'block'
    c.fec_k = 8
    c.fec_n = 12
    return c


def _cfg_sliding():
    c = Section()
    c.fec_type = 'sliding'
    c.swin_w = 64
    c.swin_r = '1/2'
    c.t_flush_ms = 100
    return c


class FecArgsTestCase(unittest.TestCase):

    def test_tx_block(self):
        self.assertEqual(fec_tx_args(_cfg_block()), '-k 8 -n 12')

    def test_tx_sliding(self):
        self.assertEqual(
            fec_tx_args(_cfg_sliding()),
            '--codec=sliding --swin-w=64 --swin-r=1/2')

    def test_rx_block_is_empty(self):
        # RX block path adds no new flags — backward compatibility.
        self.assertEqual(fec_rx_args(_cfg_block()), '')

    def test_rx_sliding_carries_codec_and_tflush(self):
        self.assertEqual(
            fec_rx_args(_cfg_sliding()),
            '--codec=sliding --t-flush-ms=100')

    def test_tx_default_is_block(self):
        # If cfg has no fec_type attribute at all, we fall back to
        # block for backward compatibility with older master.cfgs.
        c = Section()
        c.fec_k = 1
        c.fec_n = 2
        self.assertEqual(fec_tx_args(c), '-k 1 -n 2')

    def test_rx_default_is_empty(self):
        c = Section()
        self.assertEqual(fec_rx_args(c), '')

    def test_unknown_fec_type_raises(self):
        c = Section()
        c.fec_type = 'quantum'
        self.assertRaises(Exception, fec_tx_args, c)
        self.assertRaises(Exception, fec_rx_args, c)
