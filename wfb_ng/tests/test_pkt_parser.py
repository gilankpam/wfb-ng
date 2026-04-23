# B7 test: protocols.StatisticsMsgPackProtocol PKT-line parser.
#
# The PKT line grew from 11 to 12 colon-separated counters in B7
# (added w_flush at the end). Old wfb_rx binaries still on a
# deployed drone emit the 11-field form; new binaries emit 12. The
# parser must accept both and always produce the same dict shape so
# downstream code (cli.py, log_parser.py) doesn't branch on
# session age.

from twisted.trial import unittest


# Mirror of the PKT branch in StatisticsMsgPackProtocol. Extracted
# so the test can drive it without the Twisted framing.
def _parse_pkt(payload):
    k_tuple = ('all', 'all_bytes', 'dec_err', 'session', 'data',
               'uniq', 'fec_rec', 'lost', 'bad',
               'out', 'out_bytes', 'w_flush')
    raw = tuple(int(i) for i in payload.split(':'))
    if len(raw) == len(k_tuple) - 1:
        counters = raw + (0,)
    elif len(raw) == len(k_tuple):
        counters = raw
    else:
        raise ValueError('bad len: %d' % len(raw))
    return dict(zip(k_tuple, counters))


class PktParserTestCase(unittest.TestCase):

    def test_old_11_field_pads_w_flush_to_zero(self):
        # pre-B7 wfb_rx emits 11 fields. The new parser synthesizes
        # w_flush=0 so downstream dict always has the same keys.
        payload = '100:5000:0:1:90:90:0:0:0:90:4500'
        d = _parse_pkt(payload)
        self.assertEqual(d['all'], 100)
        self.assertEqual(d['out_bytes'], 4500)
        self.assertEqual(d['w_flush'], 0)
        self.assertEqual(len(d), 12)

    def test_new_12_field_includes_w_flush(self):
        # post-B7 wfb_rx emits 12 fields including w_flush at the
        # end. Non-zero here signals SWIN T_flush retirements.
        payload = '100:5000:0:1:90:90:3:0:0:90:4500:7'
        d = _parse_pkt(payload)
        self.assertEqual(d['fec_rec'], 3)
        self.assertEqual(d['w_flush'], 7)

    def test_malformed_rejected(self):
        # Neither 11 nor 12 fields — the format has shifted in a
        # way the parser doesn't know how to interpret. Reject
        # rather than silently dropping counters.
        self.assertRaises(Exception, _parse_pkt,
                          '100:5000:0:1:90:90:3:0:0:90')       # 10
        self.assertRaises(Exception, _parse_pkt,
                          '100:5000:0:1:90:90:3:0:0:90:4500:7:0')  # 13
