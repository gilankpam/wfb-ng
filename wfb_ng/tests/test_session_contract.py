# Contract-v3 parsing tests for RXAntennaProtocol: tolerant SESSION
# (4..6 fields), swfec fec_type naming, on-change dedup, tolerant PKT.
#
# Note: RXAntennaProtocol.lineReceived catches BadTelemetry internally
# (logs the bad line and continues), so rejection is asserted via
# "callback not called / state not mutated" rather than assertRaises.
from unittest.mock import MagicMock

from twisted.trial import unittest

from wfb_ng.protocols import RXAntennaProtocol


def make_proto():
    cb = MagicMock()
    p = RXAntennaProtocol(cb, 'video rx')
    return p, cb


class SessionContractTests(unittest.TestCase):
    def test_six_field_session_parsed(self):
        p, cb = make_proto()
        p.lineReceived(b'100\tSESSION\t7:2:50:30:1:3')
        cb.process_new_session.assert_called_once_with('video rx', dict(
            fec_type='swfec', fec_k=50, fec_n=30, epoch=7,
            interleave_depth=1, contract_version=3))

    def test_four_field_session_defaults(self):
        p, cb = make_proto()
        p.lineReceived(b'100\tSESSION\t7:1:8:12')
        cb.process_new_session.assert_called_once_with('video rx', dict(
            fec_type='VDM_RS', fec_k=8, fec_n=12, epoch=7,
            interleave_depth=1, contract_version=1))

    def test_session_reemission_deduped(self):
        p, cb = make_proto()
        p.lineReceived(b'100\tSESSION\t7:2:50:30:1:3')
        p.lineReceived(b'200\tSESSION\t7:2:50:30:1:3')   # periodic re-emit
        self.assertEqual(cb.process_new_session.call_count, 1)

    def test_session_change_notifies_again(self):
        p, cb = make_proto()
        p.lineReceived(b'100\tSESSION\t7:2:50:30:1:3')
        p.lineReceived(b'200\tSESSION\t7:2:80:30:1:3')   # overhead changed
        self.assertEqual(cb.process_new_session.call_count, 2)

    def test_short_session_rejected(self):
        p, cb = make_proto()
        p.lineReceived(b'100\tSESSION\t7:1:8')
        cb.process_new_session.assert_not_called()
        self.assertIsNone(p.session)

    def test_pkt_eleven_fields_ok(self):
        p, cb = make_proto()
        p.lineReceived(b'100\tPKT\t1:2:3:4:5:6:7:8:9:10:11')
        cb.update_rx_stats.assert_called_once()

    def test_pkt_extra_fields_tolerated(self):
        p, cb = make_proto()
        p.lineReceived(b'100\tPKT\t1:2:3:4:5:6:7:8:9:10:11:12:13:14')
        cb.update_rx_stats.assert_called_once()

    def test_pkt_short_rejected(self):
        p, cb = make_proto()
        p.lineReceived(b'100\tPKT\t1:2:3:4:5:6:7:8:9:10')
        cb.update_rx_stats.assert_not_called()
