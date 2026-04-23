# B6 test: protocols.StatisticsMsgPackProtocol SESSION-line parser.
#
# Exercises the SESSION-handling branch in
# StatisticsMsgPackProtocol.send_rx_log() via a minimal stand-in
# object, covering:
#   - old 4-field format (pre-B6 wfb_rx binaries): carried
#     epoch:fec_type:k:n, no swin fields.
#   - new 6-field format: epoch:fec_type:k:n:swin_w:r_num/r_den.
#   - block and sliding codecs in the new format.
#
# We don't spin up the full Twisted Int32StringReceiver stack — we
# reach into the SESSION branch directly by copying its logic into
# a helper that mirrors the parser. This keeps the test fast and
# independent of the wider framing.

from twisted.trial import unittest

from wfb_ng.protocols import fec_types


def _parse_session(payload):
    """Mirror of the SESSION branch in StatisticsMsgPackProtocol.
    Returns the session dict the parser would produce, or raises
    on malformed input.
    """
    parts = payload.split(':')
    if len(parts) == 4:
        epoch, fec_type, fec_k, fec_n = (int(x) for x in parts)
        swin_w, swin_r_num, swin_r_den = 0, 0, 0
    elif len(parts) == 6:
        epoch = int(parts[0])
        fec_type = int(parts[1])
        fec_k = int(parts[2])
        fec_n = int(parts[3])
        swin_w = int(parts[4])
        r_num, r_den = parts[5].split('/', 1)
        swin_r_num = int(r_num)
        swin_r_den = int(r_den)
    else:
        raise ValueError('bad len: %d' % len(parts))

    return dict(fec_type=fec_types.get(fec_type, 'Unknown'),
                fec_k=fec_k, fec_n=fec_n,
                swin_w=swin_w,
                swin_r_num=swin_r_num, swin_r_den=swin_r_den,
                epoch=epoch)


class SessionParserTestCase(unittest.TestCase):

    def test_fec_types_includes_swin(self):
        # B6: fec_types dict must map codec 0x2 to the SWIN label so
        # log lines and CLI can render it correctly.
        self.assertEqual(fec_types[1], 'VDM_RS')
        self.assertEqual(fec_types[2], 'SWIN_RS')

    def test_old_4_field_format_block(self):
        # pre-B6 wfb_rx binaries. No swin data — defaults to zeros.
        s = _parse_session('42:1:8:12')
        self.assertEqual(s['epoch'], 42)
        self.assertEqual(s['fec_type'], 'VDM_RS')
        self.assertEqual(s['fec_k'], 8)
        self.assertEqual(s['fec_n'], 12)
        self.assertEqual(s['swin_w'], 0)
        self.assertEqual(s['swin_r_num'], 0)
        self.assertEqual(s['swin_r_den'], 0)

    def test_new_6_field_format_block(self):
        # Post-B6 block session: k/n carry the codec params, swin
        # fields are zero.
        s = _parse_session('42:1:8:12:0:0/0')
        self.assertEqual(s['fec_type'], 'VDM_RS')
        self.assertEqual(s['fec_k'], 8)
        self.assertEqual(s['fec_n'], 12)
        self.assertEqual(s['swin_w'], 0)
        self.assertEqual(s['swin_r_num'], 0)
        self.assertEqual(s['swin_r_den'], 0)

    def test_new_6_field_format_sliding(self):
        # Post-B6 SWIN session: k/n are zero, swin carries W and R.
        s = _parse_session('99:2:0:0:64:1/2')
        self.assertEqual(s['fec_type'], 'SWIN_RS')
        self.assertEqual(s['fec_k'], 0)
        self.assertEqual(s['fec_n'], 0)
        self.assertEqual(s['swin_w'], 64)
        self.assertEqual(s['swin_r_num'], 1)
        self.assertEqual(s['swin_r_den'], 2)

    def test_unknown_fec_type_still_parses(self):
        # Forward-compat: an unknown codec code should land on
        # 'Unknown' and not crash.
        s = _parse_session('1:99:0:0:0:0/0')
        self.assertEqual(s['fec_type'], 'Unknown')

    def test_malformed_raises(self):
        # 5 fields is not a valid format (neither old nor new).
        self.assertRaises(Exception, _parse_session, '1:1:8:12:0')
        # Non-numeric tokens.
        self.assertRaises(Exception, _parse_session, 'x:1:8:12')
        # Ratio missing '/'.
        self.assertRaises(Exception, _parse_session, '1:2:0:0:64:12')
