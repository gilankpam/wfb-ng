#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import os
import struct
import errno
import hashlib
import random
import itertools

from twisted.python import log
from twisted.trial import unittest
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol

from ..common import df_sleep
from ..protocols import RXProtocol, TXProtocol
from .. import call_and_check_rc


def batched(iterable, n):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx:min(ndx + n, l)]


class UDP_TXRX(DatagramProtocol):
    def __init__(self, tx_addr, tx_proto=None):
        self.rxq = []
        self.tx_addr = tx_addr
        self.tx_proto = tx_proto

    def datagramReceived(self, data, addr):
        log.msg("got %r from %s" % (data, addr))
        self.rxq.append(data)

    def send_msg(self, data):
        t = (self.tx_proto.transport if self.tx_proto else self.transport)
        t.write(data, self.tx_addr)
        log.msg("sent %r to %r" % (data, t,))


def gen_req_id(f):
    def _f(self, *args, **kwargs):
        req_id = self.req_id % (1 << 32)
        self.req_id = req_id + 1
        return f(self, req_id, *args, **kwargs)
    return _f


class FakeAntennaProtocol(object):
    def process_new_session(self, rx_id, session):
        log.msg('%s new session %r' % (rx_id, session))


    def update_rx_stats(self, rx_id, packet_stats, ant_stats, session):
        log.msg('%s %r %r %r' % (rx_id, packet_stats, ant_stats, session))

        for (((freq, mcs_index, bandwidth), ant_id), v) in ant_stats.items():
            (pkt_s,
             rssi_min, rssi_avg, rssi_max,
             snr_min, snr_avg, snr_max) = v[:7]
            # wfb_rx appends EVM (evm_min/avg/max) after SNR. Synthetic test
            # frames carry no radiotap lock_quality, so EVM is reported absent (-1).
            evm_min, evm_avg, evm_max = v[7:10] if len(v) >= 10 else (-1, -1, -1)

            assert pkt_s >= 0
            assert freq == 4321
            assert mcs_index == 1
            assert bandwidth == 20
            assert rssi_min == rssi_avg == rssi_max == -42
            assert snr_min == snr_avg == snr_max == 28
            assert evm_min == evm_avg == evm_max == -1

            host, port, wlan_idx, ant_id = struct.unpack('!IHBB', ant_id.to_bytes(8, byteorder='big'))
            assert host == 0x7f000001
            assert port == 0
            assert 0 <= wlan_idx < 2
            assert 0 <= ant_id < 2

    def update_tx_stats(self, tx_id, packet_stats, ant_latency):
        log.msg('%s %r %r' % (tx_id, packet_stats, ant_latency))



class TXCommandClient(DatagramProtocol):
    noisy = False

    CMD_SET_FEC = 1
    CMD_SET_RADIO = 2
    CMD_GET_FEC = 3
    CMD_GET_RADIO = 4

    resp_map = {
        CMD_SET_FEC: lambda x: None,
        CMD_SET_RADIO: lambda x: None,
        CMD_GET_FEC: lambda x: struct.unpack('!BB', x),
        CMD_GET_RADIO: lambda x: struct.unpack('!B??BB?B', x)
    }

    def __init__(self, tx_addr):
        self.tx_addr = tx_addr
        self.callbacks = {}
        self.req_id = int(time.time())

    def datagramReceived(self, data, addr):
        if addr != self.tx_addr:
            return

        req_id, rc = struct.unpack('!II', data[:8])
        df = self.callbacks.pop(req_id, None)

        if df is None:
            log.msg("Unknown response from %s %d" % (addr, req_id), isError=1)
            return

        if rc == 0:
            df.callback(data[8:])
        else:
            df.errback(OSError("Error: %s" % (errno.errorcode.get(rc, str(rc)))))

    def _do_cmd(self, req_id, msg):
        df = defer.Deferred()
        self.callbacks[req_id] = df
        self.transport.write(msg, self.tx_addr)
        return df

    @gen_req_id
    def set_fec(self, req_id, k, n):
        def _got_response(data):
            return None

        return self._do_cmd(req_id, struct.pack('!IBBB', req_id, self.CMD_SET_FEC, k, n))\
                   .addCallback(_got_response)

    @gen_req_id
    def set_radio(self, req_id, stbc, ldpc, short_gi, bandwidth, mcs_index, vht_mode, vht_nss):
        def _got_response(data):
            return None

        return self._do_cmd(req_id, struct.pack('!IBB??BB?B', req_id, self.CMD_SET_RADIO,
                                                stbc, ldpc, short_gi, bandwidth, mcs_index, vht_mode, vht_nss))\
                   .addCallback(_got_response)

    @gen_req_id
    def get_fec(self, req_id):
        def _got_response(data):
            return dict(zip(('k', 'n'), self.resp_map[self.CMD_GET_FEC](data)))

        return self._do_cmd(req_id, struct.pack('!IB', req_id, self.CMD_GET_FEC))\
                   .addCallback(_got_response)

    @gen_req_id
    def get_radio(self, req_id):
        def _got_response(data):
            return dict(zip(('stbc', 'ldpc', 'short_gi', 'bandwidth', 'mcs_index', 'vht_mode', 'vht_nss'),
                            self.resp_map[self.CMD_GET_RADIO](data)))

        return self._do_cmd(req_id, struct.pack('!IB', req_id, self.CMD_GET_RADIO))\
                   .addCallback(_got_response)


class TXRXTestCase(unittest.TestCase):
    def setup_keys(self, bindir):
        return  call_and_check_rc(os.path.join(bindir, 'wfb_keygen'))

    @defer.inlineCallbacks
    def setUp(self):
        bindir = os.path.join(os.path.dirname(__file__), '../..')
        yield self.setup_keys(bindir)

        self.rxp = UDP_TXRX(('127.0.0.1', 10001))
        self.txp = UDP_TXRX(('127.0.0.1', 10003))
        self.cmdp = TXCommandClient(('127.0.0.1', 7003))

        self.rx_ep = reactor.listenUDP(10002, self.rxp)
        self.tx_ep = reactor.listenUDP(10004, self.txp)
        self.cmd_ep = reactor.listenUDP(0, self.cmdp)

        link_id = int.from_bytes(os.urandom(3), 'big')
        epoch = int(time.time())
        cmd_rx = [os.path.join(bindir, 'wfb_rx'), '-K', 'drone.key', '-a', '10001', '-u', '10002',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        cmd_tx = [os.path.join(bindir, 'wfb_tx'), '-K', 'gs.key', '-u', '10003', '-D', '10004', '-T', '30', '-F', '3000', '-C', '7003',
                  # '-Q', '-P 1',  ## requires root priv
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']

        ap = FakeAntennaProtocol()
        self.rx_pp = RXProtocol(ap, cmd_rx, 'debug rx')
        self.tx_pp = TXProtocol(ap, cmd_tx, 'debug tx')

        self.rx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))

        # Wait for tx/rx processes to initialize
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def tearDown(self):
        self.rx_pp.transport.signalProcess('KILL')
        self.tx_pp.transport.signalProcess('KILL')
        self.rx_ep.stopListening()
        self.tx_ep.stopListening()
        self.cmd_ep.stopListening()
        # Wait for tx/rx processes to die
        yield df_sleep(0.1)

    def test_keys(self):
        keys = [open(k, 'rb').read() for k in ('gs.key', 'drone.key')]
        self.assertEqual(len(keys), 2)
        self.assertNotEqual(keys[0], keys[1])

    @defer.inlineCallbacks
    def test_txrx(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(16):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.1)
        self.assertEqual(len(self.txp.rxq), 25) # 1 session + (8 data packets + 4 fec packets) * 2

        # Check FEC fail and recovery
        # 1. Fail on block #1: lost 5 packets
        # 2. Recover on block #2: lost 3 packets
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (4, 9, 10, 11, 12, 11 + 4, 11 + 5, 11 + 6):
                self.rxp.send_msg(pkt)

        yield df_sleep(1.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(16) if i + 1 != 4], self.rxp.rxq)


    @defer.inlineCallbacks
    def test_aggregation(self):
        self.assertEqual(len(self.txp.rxq), 0)

        for i in range(256):
            payload = os.urandom(random.randint(0, 1024))
            self.txp.send_msg(b'%04d%s%s' % (i, payload, hashlib.sha1(payload).digest()))
            # We have 3ms fec timeout after each fec packet so limit input packet speed
            yield df_sleep(0.003)

        yield df_sleep(1.1) # wait stats refresh
        self.assertGreaterEqual(len(self.txp.rxq), 32 * 12 + 1) # session(s) + 32 blocks

        # Always send session packet first
        session = self.txp.rxq.pop(0)
        self.rxp.send_msg(session)

        # first packet to open first block
        self.rxp.send_msg(self.txp.rxq.pop(0))

        for batch in batched(self.txp.rxq, 18): # 1.5 FEC blocks
            # Reoder packets
            batch = list(batch)
            random.shuffle(batch)
            for pkt in batch:
                # Drop packet with 1/8 probability
                if random.random() > 0.125:
                    self.rxp.send_msg(pkt)
                    yield df_sleep(0.003)

        yield df_sleep(2.1) # wait stats refresh
        self.assertGreater(len(self.rxp.rxq), 200)
        self.assertLessEqual(len(self.rxp.rxq), 256)
        log.msg('Lost: %d/256' % (256 - len(self.rxp.rxq),))

        prev = -1
        for pkt in self.rxp.rxq:
            idx = int(pkt[0:4])
            payload = pkt[4:-20]
            checksum = pkt[-20:]
            self.assertEqual(hashlib.sha1(payload).digest(), checksum)
            self.assertGreater(idx, prev)
            prev = idx

    @defer.inlineCallbacks
    def test_fec_timeout(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.1)
        self.assertEqual(len(self.txp.rxq), 13) # 1 session + 8 data packets + 4 fec packets

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(6)], self.rxp.rxq)


    @defer.inlineCallbacks
    def test_cmd_fec(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.02) # don't wait for first fec timeout
        self.assertEqual(len(self.txp.rxq), 7) # 1 session + (6 data packets)

        res = yield self.cmdp.get_fec()
        self.assertEqual(res['k'], 8)
        self.assertEqual(res['n'], 12)

        yield self.cmdp.set_fec(1, 2) # should close FEC block, set FEC 1/2 and issue N-K+1 session packets

        res = yield self.cmdp.get_fec()
        self.assertEqual(res['k'], 1)
        self.assertEqual(res['n'], 2)

        self.assertEqual(len(self.txp.rxq), 15) # 1 session + (8 data packets + 4 fec packets) + 2 session
        self.txp.send_msg(b'm%d' % (7,))
        yield df_sleep(0.1)

        self.assertEqual(len(self.txp.rxq), 17) # 1 session + (8 data packets + 4 fec packets) + 2 session + (1 data packet + 1 fec packet)

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4, 15):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(7)], self.rxp.rxq)


    @defer.inlineCallbacks
    def test_cmd_fec_invalid_args(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.02) # don't wait for first fec timeout
        self.assertEqual(len(self.txp.rxq), 7) # 1 session + (6 data packets)

        try:
            yield self.cmdp.set_fec(1, 0)
            self.fail('Should fail')
        except OSError as v:
            self.assertEqual(str(v), 'Error: EINVAL')

        self.assertEqual(len(self.txp.rxq), 7) # command should be ignored
        yield df_sleep(0.1)

        self.txp.send_msg(b'm%d' % (7,))
        yield df_sleep(0.02)  # don't wait for first fec timeout

        self.assertEqual(len(self.txp.rxq), 14) # 1 session + (8 data packets + 4 fec packets) + 1 data packet

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(7)], self.rxp.rxq)

    @defer.inlineCallbacks
    def test_cmd_radio(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.02) # don't wait for first fec timeout
        self.assertEqual(len(self.txp.rxq), 7) # 1 session + (6 data packets)

        res = yield self.cmdp.get_radio()
        self.assertEqual(res['stbc'], 0)
        self.assertEqual(res['ldpc'], False)
        self.assertEqual(res['short_gi'], False)
        self.assertEqual(res['bandwidth'], 0)
        self.assertEqual(res['mcs_index'], 0)
        self.assertEqual(res['vht_mode'], False)
        self.assertEqual(res['vht_nss'], 0)

        yield self.cmdp.set_radio(stbc=1, ldpc=True, short_gi=False, bandwidth=40, mcs_index=3, vht_mode=False, vht_nss=0)

        res = yield self.cmdp.get_radio()
        self.assertEqual(res['stbc'], 1)
        self.assertEqual(res['ldpc'], True)
        self.assertEqual(res['short_gi'], False)
        self.assertEqual(res['bandwidth'], 40)
        self.assertEqual(res['mcs_index'], 3)
        self.assertEqual(res['vht_mode'], False)
        self.assertEqual(res['vht_nss'], 0)

        self.txp.send_msg(b'm%d' % (7,))
        yield df_sleep(0.1)

        self.assertEqual(len(self.txp.rxq), 13) # 1 session + (8 data packets + 4 fec packets)

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(7)], self.rxp.rxq)

    @defer.inlineCallbacks
    def test_cmd_radio_invalid_args(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(6):
            self.txp.send_msg(b'm%d' % (i + 1,))

        yield df_sleep(0.02) # don't wait for first fec timeout
        self.assertEqual(len(self.txp.rxq), 7) # 1 session + (6 data packets)

        try:
            yield self.cmdp.set_radio(stbc=200, ldpc=True, short_gi=False, bandwidth=1, mcs_index=100, vht_mode=False, vht_nss=0)
            self.fail('Should fail')
        except OSError as v:
            self.assertEqual(str(v), 'Error: EINVAL')

        self.txp.send_msg(b'm%d' % (7,))
        yield df_sleep(0.1)

        self.assertEqual(len(self.txp.rxq), 13) # 1 session + (8 data packets + 4 fec packets)

        # Check FEC recovery
        for i, pkt in enumerate(self.txp.rxq):
            if i not in (2, 4):
                self.rxp.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'm%d' % (i + 1,) for i in range(7)], self.rxp.rxq)


class KeyDerivationTestCase(TXRXTestCase):
    def setup_keys(self, bindir):
        return call_and_check_rc(os.path.join(bindir, 'wfb_keygen'), 'secret password')

    def test_keys(self):
        keys = [open(k, 'rb').read() for k in ('gs.key', 'drone.key')]
        self.assertEqual(len(keys), 2)
        self.assertNotEqual(keys[0], keys[1])
        self.assertEqual(hashlib.sha1(keys[0]).hexdigest(), 'cb8d52ca7602928f67daba6ba1f308f4cfc88aa7')
        self.assertEqual(hashlib.sha1(keys[1]).hexdigest(), '7a6ffb44cebc53b4538d20bdcaba8d70c9cf4095')


class PlaintextTXOnlyTestCase(unittest.TestCase):
    # wfb_tx with no -K must run in plaintext and emit the same packet
    # structure as encrypted mode (1 session + (8 data + 4 fec) per block).
    @defer.inlineCallbacks
    def setUp(self):
        bindir = os.path.join(os.path.dirname(__file__), '../..')
        self.txp = UDP_TXRX(('127.0.0.1', 10003))
        self.tx_ep = reactor.listenUDP(10004, self.txp)
        link_id = int.from_bytes(os.urandom(3), 'big')
        epoch = int(time.time())
        # NOTE: no -K -> plaintext
        cmd_tx = [os.path.join(bindir, 'wfb_tx'), '-u', '10003', '-D', '10004', '-T', '30', '-F', '3000',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        ap = FakeAntennaProtocol()
        self.tx_pp = TXProtocol(ap, cmd_tx, 'debug tx')
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def tearDown(self):
        self.tx_pp.transport.signalProcess('KILL')
        self.tx_ep.stopListening()
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def test_plaintext_tx_emits(self):
        self.assertEqual(len(self.txp.rxq), 0)
        for i in range(16):
            self.txp.send_msg(b'm%d' % (i + 1,))
        yield df_sleep(0.1)
        # 1 session + (8 data + 4 fec) * 2 blocks, same as the encrypted test_txrx
        self.assertEqual(len(self.txp.rxq), 25)


class PlaintextTXRXTestCase(TXRXTestCase):
    # Same end-to-end round-trip assertions as TXRXTestCase, but both
    # wfb_tx and wfb_rx run with NO -K (plaintext). Inherits test_txrx,
    # test_aggregation, test_fec_timeout, test_cmd_* unchanged.
    @defer.inlineCallbacks
    def setUp(self):
        bindir = os.path.join(os.path.dirname(__file__), '../..')
        yield self.setup_keys(bindir)  # keys generated but unused (no -K passed)

        self.rxp = UDP_TXRX(('127.0.0.1', 10001))
        self.txp = UDP_TXRX(('127.0.0.1', 10003))
        self.cmdp = TXCommandClient(('127.0.0.1', 7003))

        self.rx_ep = reactor.listenUDP(10002, self.rxp)
        self.tx_ep = reactor.listenUDP(10004, self.txp)
        self.cmd_ep = reactor.listenUDP(0, self.cmdp)

        link_id = int.from_bytes(os.urandom(3), 'big')
        epoch = int(time.time())
        # NOTE: no -K on either side -> plaintext
        cmd_rx = [os.path.join(bindir, 'wfb_rx'), '-a', '10001', '-u', '10002',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        cmd_tx = [os.path.join(bindir, 'wfb_tx'), '-u', '10003', '-D', '10004', '-T', '30', '-F', '3000', '-C', '7003',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']

        ap = FakeAntennaProtocol()
        self.rx_pp = RXProtocol(ap, cmd_rx, 'debug rx')
        self.tx_pp = TXProtocol(ap, cmd_tx, 'debug tx')

        self.rx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        yield df_sleep(0.1)


class PlaintextSafetyTestCase(unittest.TestCase):
    # Core invariant: a plaintext TX (no -K) must NOT be decoded by an
    # ENCRYPTED RX (-K). The encrypted RX rejects 0x3/0x4 -> no output.
    @defer.inlineCallbacks
    def setUp(self):
        bindir = os.path.join(os.path.dirname(__file__), '../..')
        yield call_and_check_rc(os.path.join(bindir, 'wfb_keygen'))

        self.rxp = UDP_TXRX(('127.0.0.1', 10001))
        self.txp = UDP_TXRX(('127.0.0.1', 10003))
        self.rx_ep = reactor.listenUDP(10002, self.rxp)
        self.tx_ep = reactor.listenUDP(10004, self.txp)

        link_id = int.from_bytes(os.urandom(3), 'big')
        epoch = int(time.time())
        cmd_rx = [os.path.join(bindir, 'wfb_rx'), '-K', 'drone.key', '-a', '10001', '-u', '10002',  # ENCRYPTED rx
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        cmd_tx = [os.path.join(bindir, 'wfb_tx'), '-u', '10003', '-D', '10004', '-T', '30', '-F', '3000',  # PLAINTEXT tx
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']

        ap = FakeAntennaProtocol()
        self.rx_pp = RXProtocol(ap, cmd_rx, 'debug rx')
        self.tx_pp = TXProtocol(ap, cmd_tx, 'debug tx')
        self.rx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def tearDown(self):
        self.rx_pp.transport.signalProcess('KILL')
        self.tx_pp.transport.signalProcess('KILL')
        self.rx_ep.stopListening()
        self.tx_ep.stopListening()
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def test_encrypted_rx_rejects_plaintext(self):
        for i in range(16):
            self.txp.send_msg(b'm%d' % (i + 1,))
        yield df_sleep(0.1)
        self.assertEqual(len(self.txp.rxq), 25)  # plaintext tx still emits
        for pkt in self.txp.rxq:                  # forward every packet to the ENCRYPTED rx
            self.rxp.send_msg(pkt)
        yield df_sleep(1.1)
        self.assertEqual(self.rxp.rxq, [])        # ...which decodes nothing


class PlaintextSwfecTestCase(unittest.TestCase):
    # Plaintext swfec (-z, no -K) no-loss round-trip: every source message,
    # forwarded without loss, is delivered in order through the reorder buffer.
    @defer.inlineCallbacks
    def setUp(self):
        bindir = os.path.join(os.path.dirname(__file__), '../..')
        self.rxp = UDP_TXRX(('127.0.0.1', 10001))
        self.txp = UDP_TXRX(('127.0.0.1', 10003))
        self.rx_ep = reactor.listenUDP(10002, self.rxp)
        self.tx_ep = reactor.listenUDP(10004, self.txp)

        link_id = int.from_bytes(os.urandom(3), 'big')
        epoch = int(time.time())
        # swfec plaintext: -z, -k overhead_pct=20, -n deadline_ms=50, no -K
        cmd_rx = [os.path.join(bindir, 'wfb_rx'), '-a', '10001', '-u', '10002',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        cmd_tx = [os.path.join(bindir, 'wfb_tx'), '-z', '-k', '20', '-n', '50', '-u', '10003', '-D', '10004',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']

        ap = FakeAntennaProtocol()
        self.rx_pp = RXProtocol(ap, cmd_rx, 'debug rx')
        self.tx_pp = TXProtocol(ap, cmd_tx, 'debug tx')
        self.rx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def tearDown(self):
        self.rx_pp.transport.signalProcess('KILL')
        self.tx_pp.transport.signalProcess('KILL')
        self.rx_ep.stopListening()
        self.tx_ep.stopListening()
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def test_swfec_plaintext_roundtrip(self):
        msgs = [b'swfec-%03d' % i for i in range(10)]
        for m in msgs:
            self.txp.send_msg(m)
            yield df_sleep(0.01)  # let each source packet flush
        yield df_sleep(0.1)
        self.assertGreater(len(self.txp.rxq), len(msgs))  # session(s) + source + repair packets
        for pkt in self.txp.rxq:       # forward everything, in order, no loss
            self.rxp.send_msg(pkt)
            yield df_sleep(0.002)
        yield df_sleep(0.3)            # > deadline so the reorder buffer drains
        self.assertEqual(self.rxp.rxq, msgs)


class PlaintextRestartTestCase(unittest.TestCase):
    # A plaintext TX that restarts with UNCHANGED FEC params must recover at a
    # long-running RX. The RX detects the new random session ID and rebuilds
    # (resetting last_known_block / the swfec reorder cursor). Runs for both RS
    # and swfec via the swfec flag on cmd_tx.
    swfec = False

    @defer.inlineCallbacks
    def setUp(self):
        self.bindir = os.path.join(os.path.dirname(__file__), '../..')
        self.rxp = UDP_TXRX(('127.0.0.1', 10001))
        self.txp = UDP_TXRX(('127.0.0.1', 10003))
        self.rx_ep = reactor.listenUDP(10002, self.rxp)
        self.tx_ep = reactor.listenUDP(10004, self.txp)
        self.link_id = int.from_bytes(os.urandom(3), 'big')
        cmd_rx = [os.path.join(self.bindir, 'wfb_rx'), '-a', '10001', '-u', '10002',
                  '-i', str(self.link_id), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        self.rx_pp = RXProtocol(FakeAntennaProtocol(), cmd_rx, 'debug rx')
        self.rx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp = None
        self._start_tx()
        yield df_sleep(0.2)

    def _start_tx(self):
        cmd_tx = [os.path.join(self.bindir, 'wfb_tx'), '-u', '10003', '-D', '10004', '-T', '30', '-F', '3000',
                  '-i', str(self.link_id), '-R', str(512 * 1024), '-s', str(512 * 1024)]
        if self.swfec:
            cmd_tx += ['-z', '-k', '20', '-n', '50']
        cmd_tx.append('wlan0')
        self.tx_pp = TXProtocol(FakeAntennaProtocol(), cmd_tx, 'debug tx')
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))

    @defer.inlineCallbacks
    def _drain_to_rx(self):
        # forward everything the TX emitted (session first, in order) to the RX
        for pkt in self.txp.rxq:
            self.rxp.send_msg(pkt)
            yield df_sleep(0.002)
        self.txp.rxq[:] = []
        yield df_sleep(0.3)

    @defer.inlineCallbacks
    def tearDown(self):
        if self.tx_pp is not None:
            self.tx_pp.transport.signalProcess('KILL')
        self.rx_pp.transport.signalProcess('KILL')
        self.rx_ep.stopListening()
        self.tx_ep.stopListening()
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def test_restart_recovers(self):
        # Round 1: push enough blocks that the RX's last_known_block / swfec
        # cursor is well above 0, so a restarted (reset-to-0) stream would be
        # rejected as "already processed" unless the RX rebuilds.
        round1 = [b'a%03d' % i for i in range(40)]
        for m in round1:
            self.txp.send_msg(m)
            yield df_sleep(0.01)
        yield df_sleep(1.1)            # session announce + final block/window flush
        yield self._drain_to_rx()
        self.assertEqual(self.rxp.rxq, round1)

        # Restart the TX: fresh process -> new random session ID, sequence resets to 0.
        self.tx_pp.transport.signalProcess('KILL')
        yield df_sleep(0.4)            # let it die and release udp:10003
        self.txp.rxq[:] = []
        self._start_tx()
        yield df_sleep(0.2)

        # Round 2: the long-running RX must accept the restarted low-sequence stream.
        round2 = [b'b%03d' % i for i in range(40)]
        for m in round2:
            self.txp.send_msg(m)
            yield df_sleep(0.01)
        yield df_sleep(1.1)
        yield self._drain_to_rx()
        self.assertEqual(self.rxp.rxq, round1 + round2)


class PlaintextRestartSwfecTestCase(PlaintextRestartTestCase):
    swfec = True


class PlaintextForgedEpochTestCase(unittest.TestCase):
    """
    Regression for Finding M-A: a forged SESSION_PLAIN with epoch=UINT64_MAX
    (plus a fresh random session_key) triggers setup_session on the RX —
    resetting last_known_block — and then sets the RX's internal epoch to MAX.
    Under the old code the subsequent monotonic gate (epoch < current -> reject)
    permanently latches out all legitimate SESSION_PLAIN with epoch=0, so the
    session-ID restart-recovery mechanism is broken: a TX restart is invisible to
    the RX and new data at block_idx=0 is refused as "already processed".
    After the M-A fix (no epoch gate in the SESSION_PLAIN path) the forged epoch
    has no lasting effect, and this test passes GREEN.

    Byte-offset derivation for the forwarded packet in txp.rxq:
      wrxfwd_t       = 17 bytes  (sizeof: wlan_idx+antenna[4]+rssi[4]+noise[4]+freq+mcs+bw)
      wsession_hdr_t = 25 bytes  (1 type byte + 24-byte nonce)
      wsession_data_t starts at offset 42:
        epoch      at 42..49  (8 bytes, big-endian)
        channel_id at 50..53  (kept unchanged)
        fec_type   at 54      (kept)
        k          at 55      (kept)
        n          at 56      (kept)
        session_key at 57..88 (32 bytes, overwritten with fresh random)
    """

    @defer.inlineCallbacks
    def setUp(self):
        self.bindir = os.path.join(os.path.dirname(__file__), '../..')
        self.rxp = UDP_TXRX(('127.0.0.1', 10001))
        self.txp = UDP_TXRX(('127.0.0.1', 10003))
        self.rx_ep = reactor.listenUDP(10002, self.rxp)
        self.tx_ep = reactor.listenUDP(10004, self.txp)
        self.link_id = int.from_bytes(os.urandom(3), 'big')
        # Plaintext RX: no -K, no -e (epoch defaults to 0)
        cmd_rx = [os.path.join(self.bindir, 'wfb_rx'), '-a', '10001', '-u', '10002',
                  '-i', str(self.link_id), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        self.rx_pp = RXProtocol(FakeAntennaProtocol(), cmd_rx, 'debug rx')
        self.rx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp = None
        self._start_tx()
        yield df_sleep(0.2)

    def _start_tx(self):
        cmd_tx = [os.path.join(self.bindir, 'wfb_tx'), '-u', '10003', '-D', '10004', '-T', '30', '-F', '3000',
                  '-i', str(self.link_id), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        self.tx_pp = TXProtocol(FakeAntennaProtocol(), cmd_tx, 'debug tx')
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))

    @defer.inlineCallbacks
    def tearDown(self):
        if self.tx_pp is not None:
            self.tx_pp.transport.signalProcess('KILL')
        self.rx_pp.transport.signalProcess('KILL')
        self.rx_ep.stopListening()
        self.tx_ep.stopListening()
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def _drain(self):
        """Forward all buffered TX packets to the RX aggregator and clear the queue."""
        for pkt in self.txp.rxq:
            self.rxp.send_msg(pkt)
            yield df_sleep(0.002)
        self.txp.rxq[:] = []
        yield df_sleep(0.3)

    @defer.inlineCallbacks
    def test_forged_epoch_does_not_latch(self):
        # ── Round 1: establish a real session, advance last_known_block ─────────
        round1 = [b'a%03d' % i for i in range(40)]
        for m in round1:
            self.txp.send_msg(m)
            yield df_sleep(0.01)
        yield df_sleep(1.1)

        # Capture a SESSION_PLAIN (type byte 0x04 at offset 17 in the forwarded
        # frame) before draining so we have the real channel_id / fec params.
        session_pkt = None
        for pkt in self.txp.rxq:
            if session_pkt is None and len(pkt) > 17 and pkt[17] == 0x04:
                session_pkt = bytearray(pkt)

        yield self._drain()
        self.assertEqual(self.rxp.rxq, round1)
        self.assertIsNotNone(session_pkt, 'no SESSION_PLAIN captured in round 1')

        # ── Inject a forged SESSION_PLAIN ─────────────────────────────────────
        # Overwrite epoch → UINT64_MAX and session_key → fresh random (so that
        # memcmp detects a "new session" and calls setup_session, setting the RX
        # internal epoch to MAX and resetting last_known_block).
        EPOCH_OFF = 42   # sizeof(wrxfwd_t)=17 + sizeof(wsession_hdr_t)=25
        SK_OFF    = 57   # EPOCH_OFF + epoch(8)+channel_id(4)+fec_type(1)+k(1)+n(1)
        session_pkt[EPOCH_OFF:EPOCH_OFF + 8] = b'\xff' * 8   # epoch = UINT64_MAX
        session_pkt[SK_OFF:SK_OFF + 32]      = os.urandom(32) # trigger new-session rebuild
        self.rxp.send_msg(bytes(session_pkt))
        yield df_sleep(0.05)
        # RX has now: epoch=MAX, last_known_block=-1 (reset by setup_session)

        # ── Round 2: same TX session, advance last_known_block again ──────────
        # The TX continues sending with the same session_key (R1) and ascending
        # block_idx. Under old code the real SESSION_PLAIN arriving in this batch
        # is epoch-rejected (0 < MAX) and last_known_block is advanced only by the
        # data packets. Under new code the real SESSION_PLAIN re-triggers
        # setup_session at epoch=0 and data follows normally. Either way, round-2
        # messages are delivered (plaintext data does not check session_key) and
        # last_known_block ends up > 0 after this drain.
        round2 = [b'b%03d' % i for i in range(16)]
        for m in round2:
            self.txp.send_msg(m)
            yield df_sleep(0.01)
        yield df_sleep(1.1)
        yield self._drain()

        # ── Restart the TX ────────────────────────────────────────────────────
        # New process → new random session_key (R2), block_idx resets to 0.
        self.tx_pp.transport.signalProcess('KILL')
        yield df_sleep(0.4)
        self.txp.rxq[:] = []
        self._start_tx()
        yield df_sleep(0.2)

        # ── Round 3: the RX must accept the restarted stream ─────────────────
        round3 = [b'c%03d' % i for i in range(40)]
        for m in round3:
            self.txp.send_msg(m)
            yield df_sleep(0.01)
        yield df_sleep(1.1)
        yield self._drain()

        # M-A fix (new code): SESSION_PLAIN with epoch=0 accepted (no epoch gate);
        # session_key change (R1→R2) detected → setup_session → last_known_block
        # reset to -1 → block_idx=0 data accepted → round 3 delivered.
        #
        # Old code: SESSION_PLAIN with epoch=0 rejected (0 < UINT64_MAX);
        # last_known_block stays > 0 (advanced by round-2 data) → block_idx=0
        # "already processed" → round-3 messages silently dropped.
        self.assertGreater(len(self.rxp.rxq), len(round1) + len(round2),
                           'round-3 messages not received — epoch latch not fixed (M-A)')


class UNIXTXRXTestCase(TXRXTestCase):
    @defer.inlineCallbacks
    def setUp(self):
        bindir = os.path.join(os.path.dirname(__file__), '../..')
        yield self.setup_keys(bindir)

        self.rxp_txp = DatagramProtocol()
        self.rx_tx_ep = reactor.listenUDP(0, self.rxp_txp)
        self.rxp = UDP_TXRX(('127.0.0.1', 10001), self.rxp_txp)

        self.txp_rxp = DatagramProtocol()
        self.tx_rx_ep = reactor.listenUNIXDatagram(None, self.txp_rxp)
        self.txp = UDP_TXRX('\0wfb-tx-test', self.txp_rxp)

        self.cmdp = TXCommandClient(('127.0.0.1', 7003))

        self.rx_ep = reactor.listenUNIXDatagram(b'\0wfb-rx-test', self.rxp)
        self.tx_ep = reactor.listenUDP(10004, self.txp)
        self.cmd_ep = reactor.listenUDP(0, self.cmdp)

        link_id = int.from_bytes(os.urandom(3), 'big')
        epoch = int(time.time())
        cmd_rx = [os.path.join(bindir, 'wfb_rx'), '-K', 'drone.key', '-a', '10001', '-U', 'wfb-rx-test',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        cmd_tx = [os.path.join(bindir, 'wfb_tx'), '-K', 'gs.key', '-U', 'wfb-tx-test', '-D', '10004', '-T', '30', '-F', '3000', '-C', '7003',
                  # '-Q', '-P 1',  ## requires root priv
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']

        ap = FakeAntennaProtocol()
        self.rx_pp = RXProtocol(ap, cmd_rx, 'debug rx')
        self.tx_pp = TXProtocol(ap, cmd_tx, 'debug tx')

        self.rx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))

        # Wait for tx/rx processes to initialize
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def tearDown(self):
        self.rx_pp.transport.signalProcess('KILL')
        self.tx_pp.transport.signalProcess('KILL')
        self.rx_ep.stopListening()
        self.tx_ep.stopListening()
        self.rx_tx_ep.stopListening()
        self.tx_rx_ep.stopListening()
        self.cmd_ep.stopListening()
        # Wait for tx/rx processes to die
        yield df_sleep(0.1)
