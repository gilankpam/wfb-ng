# Optional (Per-Stream) Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `wfb_tx`/`wfb_rx` run a stream unencrypted (no `-K`) to save per-packet CPU on video, while encrypted streams (mavlink/tunnel) are unchanged and cannot be downgraded.

**Architecture:** Mode is `encrypted = !keypair.empty()`, derived once per process. Plaintext uses two distinct, self-describing wire types — `WFB_PACKET_DATA_PLAIN (0x3)` and `WFB_PACKET_SESSION_PLAIN (0x4)` — that carry the same headers/struct as the encrypted ones but skip the AEAD tag / `crypto_box`. The RX accepts only the types matching its own mode, so an encrypted RX rejects plaintext (and vice-versa) — enforced in `process_packet`. The ~1 Hz session packet still carries the FEC params; only the per-fragment cipher is dropped.

**Tech Stack:** C++ (libsodium, zfex/swfec FEC), Python 3 + Twisted (service launcher + trial tests), GNU Make.

## Global Constraints

- **Mode switch:** `-K` present ⇒ encrypted (today's behavior). `-K` absent ⇒ plaintext. Implemented as a single `const bool encrypted` member = `!keypair.empty()`.
- **Default keypair becomes empty:** `string keypair = ""` in both `main()`s (was `"tx.key"`/`"rx.key"`).
- **Distinct wire types:** `#define WFB_PACKET_DATA_PLAIN 0x3`, `#define WFB_PACKET_SESSION_PLAIN 0x4`. Existing `WFB_PACKET_DATA 0x1`, `WFB_PACKET_SESSION 0x2` unchanged.
- **Core safety invariant (must be enforced in code, verified by a test):** an `encrypted == true` RX MUST reject `0x3/0x4` (→ `count_p_bad`); an `encrypted == false` RX MUST reject `0x1/0x2`. Mode is per-process; no on-air packet can flip it.
- **Bound plaintext data length explicitly:** plaintext data has no AEAD tag to subtract, so the RX MUST reject `size > sizeof(wblock_hdr_t) + MAX_FEC_PAYLOAD` before copying into `decrypted[MAX_FEC_PAYLOAD]` (otherwise up to 16 bytes of stack overflow in release builds where `assert` is compiled out).
- **No wire size-macro changes:** `MAX_PAYLOAD_SIZE`/`MAX_FEC_PAYLOAD` stay as upper bounds; plaintext packets are `<=` them.
- **Loud startup warning when plaintext:** both binaries print `WARNING: no -K given — running UNENCRYPTED on radio_port <N>` (to stderr via `WFB_ERR`).
- **Encrypted path stays byte-identical:** every `else`/`if (encrypted)` branch leaves the `encrypted == true` path exactly as it was. Verified by the existing suite.
- **Secure-by-default config:** the shipped `master.cfg` keeps keys on for every stream; plaintext is an explicit, commented opt-in.
- **Build/test (NixOS):** builds run under the project's `nix-shell` with `SHELL`/`PYTHON` overrides (see memory `wfb-ng-nixos-build`). Baseline `make test` is green except 2 pre-existing `test_proxy` errors + 1 `test_tuntap` skip (environmental — not regressions). swfec reference vectors only run if a local `test_vectors/` dir exists.
- Build C binaries: `make wfb_rx wfb_tx`. Run one python test module: `PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.<module>`.

---

## Task 1: Wire constants + TX plaintext path

**Files:**
- Modify: `src/wifibroadcast.hpp` (after line 190 — packet-type defines)
- Modify: `src/tx.hpp` (Transmitter private members, ~line 120)
- Modify: `src/tx.cpp` (constructor `:51`, `rebuild_session_packet` `:119`, `send_block_fragment` `:651`, `send_swfec_wire` `:697`, `main` default `:1830` + warning `:2004`)
- Test: `wfb_ng/tests/test_txrx.py` (new `PlaintextTXOnlyTestCase`)

**Interfaces:**
- Produces: `WFB_PACKET_DATA_PLAIN` (0x3), `WFB_PACKET_SESSION_PLAIN` (0x4); a `wfb_tx` that, with no `-K`, emits a `0x4` session packet then `0x3` data packets with the same FEC block structure as encrypted mode (1 session + (k_data + fec) per block).

- [ ] **Step 1: Write the failing test** — append to `wfb_ng/tests/test_txrx.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `make wfb_rx wfb_tx && PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.test_txrx.PlaintextTXOnlyTestCase`
Expected: FAIL — current `wfb_tx` with no `-K` opens the default `tx.key`, can't find it, and exits, so `len(self.txp.rxq) == 0`.

- [ ] **Step 3: Add the plaintext packet-type constants** — in `src/wifibroadcast.hpp`, immediately after line 190 (`#define WFB_PACKET_SESSION 0x2`):

```cpp
#define WFB_PACKET_DATA_PLAIN    0x3  // wblock_hdr  + raw fragment (no AEAD tag); -K absent
#define WFB_PACKET_SESSION_PLAIN 0x4  // wsession_hdr + raw wsession_data (no crypto_box); -K absent
```

- [ ] **Step 4: Add the `encrypted` member to `src/tx.hpp`** — in the `Transmitter` private section, immediately after `const uint32_t fec_delay; // fec packet delay [us]` (line 120):

```cpp
    const bool encrypted; // false when no keypair given (-K absent): plaintext mode
```

- [ ] **Step 5: Initialize `encrypted` and guard key loading in the constructor** — in `src/tx.cpp`, change the initializer list entry `fec_delay(fec_delay),` (line 57) to:

```cpp
    fec_delay(fec_delay),
    encrypted(!keypair.empty()),
```

Then replace the key-loading block (lines 70-85, from `FILE *fp;` through the `fclose(fp);` before `init_session`) with:

```cpp
    if (encrypted)
    {
        FILE *fp;
        if ((fp = fopen(keypair.c_str(), "r")) == NULL)
        {
            throw runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
        }
        if (fread(tx_secretkey, crypto_box_SECRETKEYBYTES, 1, fp) != 1)
        {
            fclose(fp);
            throw runtime_error(string_format("Unable to read tx secret key: %s", strerror(errno)));
        }
        if (fread(rx_publickey, crypto_box_PUBLICKEYBYTES, 1, fp) != 1)
        {
            fclose(fp);
            throw runtime_error(string_format("Unable to read rx public key: %s", strerror(errno)));
        }
        fclose(fp);
    }
```

- [ ] **Step 6: Branch `rebuild_session_packet` on mode** — in `src/tx.cpp`, replace the whole body of `Transmitter::rebuild_session_packet` (lines 119-169) with:

```cpp
void Transmitter::rebuild_session_packet(void)
{
    // fill packet header (new random nonce each call)
    wsession_hdr_t *session_hdr = (wsession_hdr_t *)session_packet;
    session_hdr->packet_type = encrypted ? WFB_PACKET_SESSION : WFB_PACKET_SESSION_PLAIN;

    randombytes_buf(session_hdr->session_nonce, sizeof(session_hdr->session_nonce));

    // fill packet contents
    uint8_t tmp[MAX_SESSION_PACKET_SIZE - crypto_box_MACBYTES - sizeof(wsession_hdr_t)];

    // Fill fixed headers
    {
        wsession_data_t* session_data = (wsession_data_t*)tmp;
        assert(sizeof(*session_data) <= sizeof(tmp));

        session_data->epoch = htobe64(epoch);
        session_data->channel_id = htobe32(channel_id);
        session_data->fec_type = use_swfec ? WFB_FEC_SWFEC : WFB_FEC_VDM_RS;
        session_data->k = (uint8_t)fec_k;
        session_data->n = (uint8_t)fec_n;

        assert(sizeof(session_data->session_key) == sizeof(session_key));
        if (encrypted)
            memcpy(session_data->session_key, session_key, sizeof(session_key));
        else
            memset(session_data->session_key, 0, sizeof(session_data->session_key)); // unused in plaintext
    }

    // Fill optional Tags
    uint32_t session_data_size = sizeof(wsession_data_t);
    for(auto it = tags.begin(); it != tags.end(); it++)
    {
        tlv_hdr_t* tlv = (tlv_hdr_t*)((uint8_t*)tmp + session_data_size);
        session_data_size += sizeof(tlv_hdr_t) + it->value.size();
        assert(session_data_size <= sizeof(tmp));

        tlv->id = it->id;
        tlv->len = it->value.size();
        memcpy(tlv->value, &it->value[0], it->value.size());
    }

    if (encrypted)
    {
        if (crypto_box_easy(session_packet + sizeof(wsession_hdr_t),
                            (uint8_t*)tmp, session_data_size,
                            session_hdr->session_nonce, rx_publickey, tx_secretkey) != 0)
        {
            throw runtime_error("Unable to make session key!");
        }
        session_packet_size = sizeof(wsession_hdr_t) + session_data_size + crypto_box_MACBYTES;
    }
    else
    {
        memcpy(session_packet + sizeof(wsession_hdr_t), tmp, session_data_size);
        session_packet_size = sizeof(wsession_hdr_t) + session_data_size;
    }

    assert(session_packet_size <= MAX_SESSION_PACKET_SIZE);
}
```

- [ ] **Step 7: Branch `send_block_fragment` on mode** — in `src/tx.cpp`, replace the body of `Transmitter::send_block_fragment` (lines 651-672) with:

```cpp
void Transmitter::send_block_fragment(size_t packet_size)
{
    uint8_t ciphertext[MAX_FORWARDER_PACKET_SIZE];
    wblock_hdr_t *block_hdr = (wblock_hdr_t*)ciphertext;
    long long unsigned int ciphertext_len;

    assert(packet_size <= MAX_FEC_PAYLOAD);

    block_hdr->packet_type = encrypted ? WFB_PACKET_DATA : WFB_PACKET_DATA_PLAIN;
    block_hdr->data_nonce = htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);

    if (encrypted)
    {
        if (crypto_aead_chacha20poly1305_encrypt(ciphertext + sizeof(wblock_hdr_t), &ciphertext_len,
                                                 block[fragment_idx], packet_size,
                                                 (uint8_t*)block_hdr, sizeof(wblock_hdr_t),
                                                 NULL, (uint8_t*)(&(block_hdr->data_nonce)), session_key) < 0)
        {
            throw runtime_error("Unable to encrypt packet!");
        }
    }
    else
    {
        memcpy(ciphertext + sizeof(wblock_hdr_t), block[fragment_idx], packet_size);
        ciphertext_len = packet_size;
    }

    inject_packet(ciphertext, sizeof(wblock_hdr_t) + ciphertext_len);
}
```

- [ ] **Step 8: Branch `send_swfec_wire` on mode** — in `src/tx.cpp`, replace the body of `Transmitter::send_swfec_wire` (lines 697-725) with:

```cpp
void Transmitter::send_swfec_wire(const uint8_t *data, size_t size)
{
    uint8_t ciphertext[MAX_FORWARDER_PACKET_SIZE];
    wblock_hdr_t *block_hdr = (wblock_hdr_t*)ciphertext;
    long long unsigned int ciphertext_len = 0;

    assert(size <= MAX_FEC_PAYLOAD);
    block_hdr->packet_type = encrypted ? WFB_PACKET_DATA : WFB_PACKET_DATA_PLAIN;
    block_hdr->data_nonce = htobe64(swfec_nonce);
    swfec_nonce += 1;

    if (encrypted)
    {
        // mirror send_block_fragment's exact AEAD call shape
        if (crypto_aead_chacha20poly1305_encrypt(
                ciphertext + sizeof(wblock_hdr_t), &ciphertext_len,
                data, size,
                (uint8_t*)block_hdr, sizeof(wblock_hdr_t),
                NULL, (uint8_t*)(&(block_hdr->data_nonce)), session_key) < 0)
        {
            throw runtime_error("Unable to encrypt swfec packet!");
        }
    }
    else
    {
        memcpy(ciphertext + sizeof(wblock_hdr_t), data, size);
        ciphertext_len = size;
    }

    inject_packet(ciphertext, sizeof(wblock_hdr_t) + ciphertext_len);

    if (swfec_nonce > MAX_BLOCK_IDX)   // never in practice; keeps rekey hygiene
    {
        init_session(fec_k, fec_n);
        send_session_key();
    }
}
```

- [ ] **Step 9: Change the TX default keypair + add the warning** — in `src/tx.cpp` `main()`: change line 1830 `string keypair = "tx.key";` to:

```cpp
    string keypair = "";
```

Then insert the warning immediately after the `if (optind >= argc) { goto show_usage; }` block (after line 2004):

```cpp
    if (keypair.empty()) {
        WFB_ERR("WARNING: no -K given — running UNENCRYPTED on radio_port %d\n", radio_port);
    }
```

- [ ] **Step 10: Build and run the test to verify it passes**

Run: `make wfb_rx wfb_tx && PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.test_txrx.PlaintextTXOnlyTestCase`
Expected: PASS — `len(self.txp.rxq) == 25`.

- [ ] **Step 11: Verify the encrypted path is unchanged**

Run: `make test`
Expected: same baseline as before (2 `test_proxy` errors + 1 `test_tuntap` skip; everything else green). The encrypted `TXRXTestCase`/`UNIXTXRXTestCase`/`KeyDerivationTestCase` all pass.

- [ ] **Step 12: Commit**

```bash
git add src/wifibroadcast.hpp src/tx.hpp src/tx.cpp wfb_ng/tests/test_txrx.py
git commit -m "noenc(tx): plaintext data/session when -K absent (0x3/0x4 wire types)"
```

---

## Task 2: RX `setup_session()` refactor (encrypted path, no behavior change)

This extracts the decoder-build logic so Task 3's plaintext path can reuse it. Pure refactor — the encrypted path must behave identically.

**Files:**
- Modify: `src/rx.hpp` (declare `setup_session`, ~line 256 near `init_fec`)
- Modify: `src/rx.cpp` (add `setup_session` definition; route the RS branch `:769-792` and swfec branch `:809-833` through it)

**Interfaces:**
- Produces: `void Aggregator::setup_session(uint8_t fec_type, uint8_t k, uint8_t n, uint64_t new_epoch)` — sets `epoch`, tears down any existing decoder, builds the RS (`init_fec`) or swfec (`SwfecDecoder`/`SwfecReorder`) decoder, and emits the IPC `SESSION` line. Does **not** touch `session_key` (caller owns that). Also `void Aggregator::swfec_set_deadline(uint8_t n)` — param-only swfec deadline update (no decoder reset), used by both the encrypted and plaintext session paths.

- [ ] **Step 1: Declare the helpers** — in `src/rx.hpp`, in the `Aggregator` private section, immediately after `void init_fec(int k, int n);` (line 253):

```cpp
    void setup_session(uint8_t fec_type, uint8_t k, uint8_t n, uint64_t new_epoch);
    void swfec_set_deadline(uint8_t n); // param-only swfec deadline update (shared encrypted + plaintext)
```

- [ ] **Step 2: Define the helper** — in `src/rx.cpp`, add this function immediately after the end of `Aggregator::init_fec` (after its closing brace near line 354):

```cpp
// (Re)build the RX decoder from session FEC params and emit the IPC SESSION line.
// Shared by the encrypted session path (on session-key change) and the plaintext
// session path (on param change). Does not touch session_key.
void Aggregator::setup_session(uint8_t fec_type, uint8_t k, uint8_t n, uint64_t new_epoch)
{
    epoch = new_epoch;

    if (fec_type == WFB_FEC_VDM_RS)
    {
        // Drop any active swfec decoder when switching to RS
        delete swfec_dec;
        swfec_dec = NULL;
        delete swfec_ro;
        swfec_ro = NULL;
        session_is_swfec = false;

        if (fec_p != NULL)
        {
            deinit_fec();
        }

        init_fec(k, n);

        // Trailing field #5 (contract_version). 4-field-only parsers stay compatible.
        IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d:%u\n", get_time_ms(), epoch,
                (unsigned)WFB_FEC_VDM_RS, fec_k, fec_n, (unsigned)WFB_IPC_CONTRACT_VERSION);
        IPC_MSG_SEND();
    }
    else // WFB_FEC_SWFEC
    {
        if (fec_p != NULL)
        {
            deinit_fec();
        }

        delete swfec_dec;
        swfec_dec = NULL;
        swfec_dec = new swfec::SwfecDecoder((uint64_t)n * 1000);
        delete swfec_ro;
        swfec_ro = new swfec::SwfecReorder((uint64_t)n * 1000);
        session_is_swfec = true;
        swfec_deadline_ms = n;

        fec_k = k;   // swfec: overhead_pct rides the k slot
        fec_n = n;   // swfec: deadline_ms rides the n slot
        IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d:%u\n", get_time_ms(), epoch,
                (unsigned)WFB_FEC_SWFEC, fec_k, fec_n, (unsigned)WFB_IPC_CONTRACT_VERSION);
        IPC_MSG_SEND();
    }
}

// Param-only swfec deadline update (same session, deadline changed): no decoder
// reset. Shared by the encrypted session path and the plaintext SESSION_PLAIN path.
void Aggregator::swfec_set_deadline(uint8_t n)
{
    swfec_deadline_ms = n;
    swfec_dec->set_deadline_us((uint64_t)n * 1000);
    if (swfec_ro != NULL)
        swfec_ro->set_deadline_us((uint64_t)n * 1000);
    fec_n = n;
    IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d:%u\n",
            get_time_ms(), epoch, (unsigned)WFB_FEC_SWFEC, fec_k, fec_n,
            (unsigned)WFB_IPC_CONTRACT_VERSION);
    IPC_MSG_SEND();
}
```

- [ ] **Step 3: Route the encrypted RS branch through the helper** — in `src/rx.cpp` `process_packet`, replace the body of the RS `if (memcmp(session_key, ...) != 0)` block (lines 769-792) with:

```cpp
            if (memcmp(session_key, new_session_data->session_key, sizeof(session_key)) != 0)
            {
                memcpy(session_key, new_session_data->session_key, sizeof(session_key));
                setup_session(WFB_FEC_VDM_RS, new_session_data->k, new_session_data->n,
                              be64toh(new_session_data->epoch));
            }
```

- [ ] **Step 4: Route the encrypted swfec branches through the helpers** — in `src/rx.cpp` `process_packet`, replace the "New swfec session" block (lines 809-833) **and** the param-only `else if (session_is_swfec && ...)` block (lines 834-846) — i.e. lines 809-846 — with:

```cpp
            if (memcmp(session_key, new_session_data->session_key, sizeof(session_key)) != 0)
            {
                // New swfec session: (re)build decoder
                memcpy(session_key, new_session_data->session_key, sizeof(session_key));
                setup_session(WFB_FEC_SWFEC, new_session_data->k, new_session_data->n,
                              be64toh(new_session_data->epoch));
            }
            else if (session_is_swfec && new_session_data->n != swfec_deadline_ms)
            {
                // Param-only update: deadline changed, same key — no reset
                swfec_set_deadline(new_session_data->n);
            }
```

- [ ] **Step 5: Build and verify no regression**

Run: `make test`
Expected: identical baseline (encrypted `TXRXTestCase` etc. all pass; only the 2 `test_proxy` + 1 `test_tuntap` pre-existing). The IPC `SESSION` output is unchanged, so `test_session_contract` passes.

- [ ] **Step 6: Commit**

```bash
git add src/rx.hpp src/rx.cpp
git commit -m "noenc(rx): extract setup_session() helper (no behavior change)"
```

---

## Task 3: RX plaintext path

**Files:**
- Modify: `src/rx.hpp` (Aggregator private member, ~line 284)
- Modify: `src/rx.cpp` (constructor guard `:289`; `process_packet` switch `:680` — guards on `DATA`/`SESSION`, new `DATA_PLAIN`/`SESSION_PLAIN` cases; post-switch decrypt `:866`; `main` default `:1346` + warning `:1426`)
- Test: `wfb_ng/tests/test_txrx.py` (`PlaintextTXRXTestCase`, `PlaintextSafetyTestCase`)

**Interfaces:**
- Consumes: `WFB_PACKET_DATA_PLAIN`/`WFB_PACKET_SESSION_PLAIN` (Task 1); `setup_session(...)` and `swfec_set_deadline(...)` (Task 2); `wfb_tx` plaintext output (Task 1).
- Produces: a `wfb_rx` that with no `-K` decodes plaintext streams (RS + swfec) and with `-K` rejects plaintext packets into `count_p_bad`.

- [ ] **Step 1: Write the failing tests** — append to `wfb_ng/tests/test_txrx.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `make wfb_rx wfb_tx && PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.test_txrx.PlaintextTXRXTestCase wfb_ng.tests.test_txrx.PlaintextSafetyTestCase`
Expected: `PlaintextTXRXTestCase` FAILs — `wfb_rx` with no `-K` opens default `rx.key`, exits, nothing decodes. `PlaintextSafetyTestCase` may already pass (the encrypted RX hits `default:` for `0x3/0x4`), but it locks in the invariant once the explicit guards exist.

- [ ] **Step 3: Add the `encrypted` member to `src/rx.hpp`** — in the `Aggregator` private section, immediately after `const uint32_t channel_id; // (link_id << 8) + port_number` (line 284):

```cpp
    const bool encrypted; // false when no keypair given (-K absent): plaintext mode
```

- [ ] **Step 4: Initialize `encrypted` and guard key loading in the constructor** — in `src/rx.cpp`, change the initializer-list tail `last_known_block((uint64_t)-1), epoch(epoch), channel_id(channel_id)` (line 285) to:

```cpp
    last_known_block((uint64_t)-1), epoch(epoch), channel_id(channel_id),
    encrypted(!keypair.empty())
```

Then wrap the key-loading block (lines 290-305, the `FILE *fp;` ... `fclose(fp);`) — leave the two `memset` lines (287-288) before it — with:

```cpp
    if (encrypted)
    {
        FILE *fp;
        if((fp = fopen(keypair.c_str(), "r")) == NULL)
        {
            throw runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
        }
        if (fread(rx_secretkey, crypto_box_SECRETKEYBYTES, 1, fp) != 1)
        {
            fclose(fp);
            throw runtime_error(string_format("Unable to read rx secret key: %s", strerror(errno)));
        }
        if (fread(tx_publickey, crypto_box_PUBLICKEYBYTES, 1, fp) != 1)
        {
            fclose(fp);
            throw runtime_error(string_format("Unable to read tx public key: %s", strerror(errno)));
        }
        fclose(fp);
    }
```

- [ ] **Step 5: Guard the encrypted `DATA` and `SESSION` cases** — in `src/rx.cpp` `process_packet`, add a mode guard as the first statement inside `case WFB_PACKET_DATA:` (after line 682) and inside `case WFB_PACKET_SESSION:` (after line 691). For `WFB_PACKET_DATA`:

```cpp
    case WFB_PACKET_DATA:
        if (!encrypted)   // plaintext RX must not accept encrypted data
        {
            count_p_bad += 1;
            return;
        }
        if(size < sizeof(wblock_hdr_t) + crypto_aead_chacha20poly1305_ABYTES + sizeof(wpacket_hdr_t))
```

For `WFB_PACKET_SESSION`:

```cpp
    case WFB_PACKET_SESSION:
        if (!encrypted)   // plaintext RX must not accept encrypted session
        {
            count_p_bad += 1;
            return;
        }
        new_session_data = (wsession_data_t*)session_tmp;
```

- [ ] **Step 6: Add the `WFB_PACKET_DATA_PLAIN` case** — in `src/rx.cpp` `process_packet`, add this case immediately after the `WFB_PACKET_DATA` case's `break;` (after line 689):

```cpp
    case WFB_PACKET_DATA_PLAIN:
        if (encrypted)   // encrypted RX must not accept plaintext data (downgrade guard)
        {
            count_p_bad += 1;
            return;
        }
        if (size < sizeof(wblock_hdr_t) + sizeof(wpacket_hdr_t))
        {
            WFB_ERR("Short packet (plain fec header)\n");
            count_p_bad += 1;
            return;
        }
        if (size > sizeof(wblock_hdr_t) + MAX_FEC_PAYLOAD)  // no AEAD tag -> bound length explicitly
        {
            WFB_ERR("Long packet (plain fec payload)\n");
            count_p_bad += 1;
            return;
        }
        break;
```

- [ ] **Step 7: Add the `WFB_PACKET_SESSION_PLAIN` case** — in `src/rx.cpp` `process_packet`, add this case immediately after the `WFB_PACKET_SESSION` case's closing `return;` (after line 858, before `default:`):

```cpp
    case WFB_PACKET_SESSION_PLAIN:
    {
        if (encrypted)   // encrypted RX must not accept plaintext session (downgrade guard)
        {
            count_p_bad += 1;
            return;
        }

        if (size < sizeof(wsession_hdr_t) + sizeof(wsession_data_t) || size > MAX_SESSION_PACKET_SIZE)
        {
            WFB_ERR("Invalid plain session packet\n");
            count_p_bad += 1;
            return;
        }

        // Dedup identical re-announces (same generichash over body + nonce).
        if (crypto_generichash(new_session_hash, sizeof(new_session_hash),
                               buf + sizeof(wsession_hdr_t), size - sizeof(wsession_hdr_t),
                               ((wsession_hdr_t*)buf)->session_nonce,
                               sizeof(((wsession_hdr_t*)buf)->session_nonce)) != 0)
        {
            assert(0);
        }
        if (memcmp(session_hash, new_session_hash, sizeof(session_hash)) == 0)
        {
            count_p_session += 1;
            return;
        }

        const wsession_data_t* sd = (const wsession_data_t*)(buf + sizeof(wsession_hdr_t));

        if (be64toh(sd->epoch) < epoch)
        {
            WFB_ERR("Session epoch doesn't match: %" PRIu64 " < %" PRIu64 "\n", be64toh(sd->epoch), epoch);
            count_p_bad += 1;
            return;
        }
        if (be32toh(sd->channel_id) != channel_id)
        {
            WFB_ERR("Session channel_id doesn't match: %u != %u\n", be32toh(sd->channel_id), channel_id);
            count_p_bad += 1;
            return;
        }
        if (sd->fec_type == WFB_FEC_VDM_RS)
        {
            if (sd->n < 1 || sd->k < 1 || sd->k > sd->n)
            {
                WFB_ERR("Invalid FEC K/N: %d/%d\n", sd->k, sd->n);
                count_p_bad += 1;
                return;
            }
        }
        else if (sd->fec_type == WFB_FEC_SWFEC)
        {
            if (sd->n < 1)
            {
                WFB_ERR("Invalid swfec deadline_ms (n): %d\n", sd->n);
                count_p_bad += 1;
                return;
            }
        }
        else
        {
            WFB_ERR("Unsupported FEC codec type: %d\n", sd->fec_type);
            count_p_bad += 1;
            return;
        }

        count_p_session += 1;

        // Plaintext has no session_key, so detect a new/changed session from the
        // FEC params + epoch instead of a key change. "first ever" = no decoder yet.
        bool first = (fec_p == NULL && swfec_dec == NULL);
        uint8_t cur_type = session_is_swfec ? WFB_FEC_SWFEC : WFB_FEC_VDM_RS;
        bool rebuild = first
                    || (be64toh(sd->epoch) != epoch)
                    || (sd->fec_type != cur_type)
                    || (sd->fec_type == WFB_FEC_VDM_RS && ((int)sd->k != fec_k || (int)sd->n != fec_n));

        if (rebuild)
        {
            setup_session(sd->fec_type, sd->k, sd->n, be64toh(sd->epoch));
        }
        else if (sd->fec_type == WFB_FEC_SWFEC && session_is_swfec && sd->n != swfec_deadline_ms)
        {
            swfec_set_deadline(sd->n);  // param-only deadline update, shared helper (Task 2)
        }

        memcpy(session_hash, new_session_hash, sizeof(session_hash));
        return;
    }
```

- [ ] **Step 8: Feed plaintext data into the decode tail** — in `src/rx.cpp`, replace the AEAD decrypt block (lines 866-880) with a branch that memcpys for the plaintext type:

```cpp
    uint8_t decrypted[MAX_FEC_PAYLOAD];
    unsigned long long decrypted_len;
    wblock_hdr_t *block_hdr = (wblock_hdr_t*)buf;

    if (buf[0] == WFB_PACKET_DATA_PLAIN)
    {
        // size was bounded to <= sizeof(wblock_hdr_t) + MAX_FEC_PAYLOAD in the switch
        decrypted_len = size - sizeof(wblock_hdr_t);
        memcpy(decrypted, buf + sizeof(wblock_hdr_t), decrypted_len);
    }
    else if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
                                             NULL,
                                             buf + sizeof(wblock_hdr_t), size - sizeof(wblock_hdr_t),
                                             buf,
                                             sizeof(wblock_hdr_t),
                                             (uint8_t*)(&(block_hdr->data_nonce)), session_key) != 0)
    {
        WFB_ERR("Unable to decrypt packet #0x%" PRIx64 "\n", be64toh(block_hdr->data_nonce));
        count_p_dec_err += 1;
        return;
    }
```

- [ ] **Step 9: Change the RX default keypair + add the warning** — in `src/rx.cpp` `main()`: change line 1346 `string keypair = "rx.key";` to:

```cpp
    string keypair = "";
```

Then insert the warning immediately after `uint32_t channel_id = (link_id << 8) + radio_port;` (line 1426):

```cpp
        if (rx_mode != FORWARDER && keypair.empty()) {
            WFB_ERR("WARNING: no -K given — running UNENCRYPTED on radio_port %d\n", radio_port);
        }
```

- [ ] **Step 10: Build and run the tests to verify they pass**

Run: `make wfb_rx wfb_tx && PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.test_txrx.PlaintextTXRXTestCase wfb_ng.tests.test_txrx.PlaintextSafetyTestCase`
Expected: PASS — plaintext round-trip decodes (FEC recovery identical to encrypted), and the encrypted RX decodes nothing from plaintext input (`self.rxp.rxq == []`).

- [ ] **Step 11: Verify the full suite**

Run: `make test`
Expected: baseline green (2 `test_proxy` + 1 `test_tuntap` pre-existing) plus the new plaintext + safety + TX-only cases passing.

- [ ] **Step 12: Commit**

```bash
git add src/rx.hpp src/rx.cpp wfb_ng/tests/test_txrx.py
git commit -m "noenc(rx): accept plaintext 0x3/0x4 when -K absent; reject cross-mode (safety)"
```

---

## Task 4: swfec plaintext round-trip test

The swfec plaintext code already landed in Tasks 1+3 (`send_swfec_wire` type byte / skip-AEAD; the `DATA_PLAIN`→`swfec_dec->push` tail; the `SESSION_PLAIN` swfec branch). This task adds an end-to-end no-loss swfec test.

**Files:**
- Test: `wfb_ng/tests/test_txrx.py` (new `PlaintextSwfecTestCase`)

**Interfaces:**
- Consumes: plaintext swfec TX (`-z`, no `-K`) and plaintext swfec RX (no `-K`).

- [ ] **Step 1: Write the failing test** — append to `wfb_ng/tests/test_txrx.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it passes (code already implemented)**

Run: `make wfb_rx wfb_tx && PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.test_txrx.PlaintextSwfecTestCase`
Expected: PASS — all 10 messages delivered in order. (If timing-flaky, raise the final `df_sleep` and/or `-n` deadline; the assertion is no-loss in-order delivery.)

- [ ] **Step 3: Commit**

```bash
git add wfb_ng/tests/test_txrx.py
git commit -m "noenc: swfec plaintext round-trip test"
```

---

## Task 5: Python `key_arg()` helper + `services.py`

**Files:**
- Modify: `wfb_ng/services.py` (add `key_arg`; replace 8 `-K %(key)s` sites)
- Test: `wfb_ng/tests/test_services.py` (new)

**Interfaces:**
- Produces: `key_arg(cfg)` → `'-K <conf_dir>/<keypair>'` when `cfg.keypair` is truthy, else `''`. Used in every `cmd_*` template via `%(key_arg)s` so a stream with `keypair = None` launches `wfb_tx`/`wfb_rx` without `-K`.

- [ ] **Step 1: Write the failing test** — create `wfb_ng/tests/test_services.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.test_services`
Expected: FAIL — `AttributeError: module 'wfb_ng.services' has no attribute 'key_arg'`.

- [ ] **Step 3: Add the helper** — in `wfb_ng/services.py`, immediately after the `hash_link_domain` function (after line 54):

```python
def key_arg(cfg):
    # '-K <conf_dir>/<keypair>' for an encrypted stream, or '' when keypair is
    # None/unset (plaintext). Templates are .split() before exec, so '' vanishes.
    return ('-K %s' % os.path.join(settings.path.conf_dir, cfg.keypair)) if cfg.keypair else ''
```

- [ ] **Step 4: Replace the 8 `-K %(key)s` sites** — in each of the 5 cmd templates, change `-K %(key)s` in the format string to `%(key_arg)s`, and change the `key=os.path.join(settings.path.conf_dir, cfg.keypair),` dict entry to `key_arg=key_arg(cfg),`. The sites are:
  - `init_udp_direct_tx`: template line 103 + dict line 115
  - `init_udp_direct_rx`: template line 166 + dict line 171
  - `init_mavlink`: template line 250 (rx) + dict line 255; template line 262 (tx) + dict line 272
  - `init_tunnel`: template line 364 (rx) + dict line 369; template line 376 (tx) + dict line 386
  - `init_udp_proxy`: template line 483 (rx) + dict line 488; template line 499 (tx) + dict line 509

  Example for `init_udp_direct_tx` — the format string fragment `... %(conn_str)s -K %(key)s '\` becomes `... %(conn_str)s %(key_arg)s '\`, and the dict entry:

```python
                key_arg=key_arg(cfg),
```

  (delete the old `key=os.path.join(settings.path.conf_dir, cfg.keypair),` line). Repeat verbatim for all 8 sites.

- [ ] **Step 5: Run the unit test to verify it passes**

Run: `PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.test_services`
Expected: PASS — both `test_keypair_set` and `test_keypair_none`.

- [ ] **Step 6: Sanity-check no `-K %(key)s` remains and templates still format**

Run: `grep -n "%(key)s\|cfg.keypair" wfb_ng/services.py`
Expected: no `-K %(key)s` matches; the only `cfg.keypair` reference is inside `key_arg`.

- [ ] **Step 7: Commit**

```bash
git add wfb_ng/services.py wfb_ng/tests/test_services.py
git commit -m "noenc(server): omit -K for streams with keypair=None (key_arg helper)"
```

---

## Task 6: `master.cfg` opt-in + spec/docs note

**Files:**
- Modify: `wfb_ng/conf/master.cfg` (`[video]` profile, line 245)
- Modify: `docs/superpowers/specs/2026-06-26-optional-encryption-design.md` (mark implemented)

**Interfaces:**
- Produces: a documented, commented opt-in. Uncommenting `keypair = None` in `[video]` makes both drone-TX and gs-RX video plaintext; everything else stays encrypted.

- [ ] **Step 1: Add the commented opt-in** — in `wfb_ng/conf/master.cfg`, in the `[video]` section (immediately under the `[video]` header at line 245), add:

```ini
# keypair = None   # UNENCRYPTED video — saves CPU. Leave commented to keep encryption.
                   # Uncomment to run video plaintext on BOTH drone-TX and gs-RX.
                   # mavlink/tunnel keep their keys; only this stream goes plaintext.
```

- [ ] **Step 2: Verify config still parses (default still encrypted)**

Run: `PYTHONPATH=$(pwd) $(PYTHON) -c "from wfb_ng.conf import settings; print(settings.video.__dict__.get('keypair', 'inherited'))"`
Expected: no parse error; `keypair` is not set in `[video]` (commented), so video inherits `drone.key`/`gs.key` — encrypted by default.

- [ ] **Step 3: Note implementation status in the spec** — in `docs/superpowers/specs/2026-06-26-optional-encryption-design.md`, change the `**Status:**` line near the top to:

```markdown
**Status:** Implemented (branch `optional-encryption`)
```

- [ ] **Step 4: Final full-suite run**

Run: `make test`
Expected: baseline green (2 `test_proxy` + 1 `test_tuntap` pre-existing) plus all new tests: `PlaintextTXOnlyTestCase`, `PlaintextTXRXTestCase` (inherited round-trip set), `PlaintextSafetyTestCase`, `PlaintextSwfecTestCase`, `KeyArgTestCase`.

- [ ] **Step 5: Commit**

```bash
git add wfb_ng/conf/master.cfg docs/superpowers/specs/2026-06-26-optional-encryption-design.md
git commit -m "noenc: documented [video] keypair=None opt-in; mark spec implemented"
```

---

## Task 7: Plaintext session ID for restart detection

Supersedes the `(fec_type,k,n,epoch)`-based "new session" detection from Task 3. The encrypted path recovers from a TX restart because `init_session()` mints a fresh random `session_key` on every (re)start, and the RX rebuilds when that field changes. Plaintext gets the same recovery for free by carrying that already-generated random `session_key` on the wire as an opaque **session ID** (no cipher use) and reusing the exact `memcmp(session_key, …)` rebuild trigger. Clock-independent — fixes the restart-recovery gap on RTC-less drones without touching the launcher.

**Files:**
- Modify: `src/tx.cpp` (`rebuild_session_packet` — stop zeroing the field in the plaintext branch)
- Modify: `src/rx.cpp` (`process_packet` `WFB_PACKET_SESSION_PLAIN` case — replace param-based detection with session-ID detection)
- Modify: `docs/superpowers/specs/2026-06-26-optional-encryption-design.md` (§4.2 / §4.4 / security note)
- Test: `wfb_ng/tests/test_txrx.py` (new `PlaintextRestartTestCase`)

**Interfaces:**
- Consumes: `setup_session(...)` / `swfec_set_deadline(...)` (Task 2); the `wsession_data_t.session_key` field (already on the wire); the RX `session_key` member (already memset to 0 at construction, previously unused in plaintext).
- Produces: a plaintext RX that rebuilds its decoder when the TX's per-session random ID changes (restart / RS reconfigure), and falls to the swfec deadline-only update when it doesn't (swfec live tweak) — behavior identical to the encrypted path.

- [ ] **Step 1: Write the failing tests** — append to `wfb_ng/tests/test_txrx.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail (current param-based detection can't see the restart)**

Run: `make wfb_rx wfb_tx && PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.test_txrx.PlaintextRestartTestCase wfb_ng.tests.test_txrx.PlaintextRestartSwfecTestCase`
Expected: FAIL — round 2's messages are missing from `rxp.rxq`. With the Task 3 detector, the restarted TX re-announces the identical `(fec_type,k,n,epoch=0)`, so `rebuild=false`, `last_known_block` / the swfec reorder cursor stay high, and every restarted packet is dropped as "already processed."

- [ ] **Step 3: TX — carry the random `session_key` as a session ID** — in `src/tx.cpp` `rebuild_session_packet`, replace the `session_key`-field fill (the `if (encrypted) memcpy … else memset(…, 0, …)` block inside the "Fill fixed headers" scope) with an unconditional copy:

```cpp
        assert(sizeof(session_data->session_key) == sizeof(session_key));
        // session_key is a fresh random value per init_session() (startup /
        // restart / reconfigure), generated even in plaintext. Encrypted: it is
        // the AEAD key. Plaintext: it rides the wire purely as an opaque session
        // ID, so the RX detects a TX restart (new random ID) exactly as the
        // encrypted path detects a session-key change. No secret is exposed.
        memcpy(session_data->session_key, session_key, sizeof(session_key));
```

- [ ] **Step 4: RX — detect rebuild via the session ID** — in `src/rx.cpp` `process_packet`, in the `WFB_PACKET_SESSION_PLAIN` case, replace the param-based detection block (the `bool first = …; uint8_t cur_type = …; bool rebuild = …; if (rebuild) { setup_session(...); } else if (…) { swfec_set_deadline(...); }`) with the session-ID form that mirrors the encrypted path:

```cpp
        count_p_session += 1;

        // Plaintext carries the TX's fresh-per-session random session_key as an
        // opaque session ID (not used for any cipher). Detect a new session — a
        // TX (re)start or an RS reconfigure, both of which call init_session()
        // and mint a new ID — exactly as the encrypted path does: by a change in
        // that field. A swfec live param tweak keeps the same ID (swfec_set_params
        // does not call init_session), so it falls to the deadline-only update.
        // This recovers a long-running RX from a TX restart with no clock/epoch
        // dependency. The RX session_key member starts memset to 0, so the first
        // real session (random ID) always differs and triggers the initial build.
        if (memcmp(session_key, sd->session_key, sizeof(session_key)) != 0)
        {
            memcpy(session_key, sd->session_key, sizeof(session_key));
            setup_session(sd->fec_type, sd->k, sd->n, be64toh(sd->epoch));
        }
        else if (sd->fec_type == WFB_FEC_SWFEC && session_is_swfec && sd->n != swfec_deadline_ms)
        {
            swfec_set_deadline(sd->n);  // param-only deadline update, shared helper (Task 2)
        }

        memcpy(session_hash, new_session_hash, sizeof(session_hash));
        return;
```

Leave the preceding validation in this case unchanged (size, dedup hash, `epoch < epoch` reject, `channel_id` match, `fec_type`/`k`/`n` validation). `sd` remains the `const wsession_data_t*` declared earlier in the case.

- [ ] **Step 5: Build and run the restart tests to verify they pass**

Run: `make wfb_rx wfb_tx && PYTHONPATH=$(pwd) $(PYTHON) -m twisted.trial wfb_ng.tests.test_txrx.PlaintextRestartTestCase wfb_ng.tests.test_txrx.PlaintextRestartSwfecTestCase`
Expected: PASS — `rxp.rxq == round1 + round2` for both RS and swfec. The restarted TX's new random ID triggers `setup_session`, which resets `last_known_block` (RS) / rebuilds the swfec decoder + reorder buffer, so the low-sequence restarted stream is accepted.

- [ ] **Step 6: Verify the full suite (no regression; live RS reconfigure still works)**

Run: `make test`
Expected: baseline (2 `test_proxy` + 1 `test_tuntap`) plus all plaintext cases. In particular `PlaintextTXRXTestCase`'s inherited `test_cmd_fec` still passes: a live RS `set_fec` calls `init_session` → new session ID → the RX rebuilds with the new `k/n` (the new-ID path adopts the announced params), so reconfigure is covered by the same mechanism.

- [ ] **Step 7: Update the design spec** — in `docs/superpowers/specs/2026-06-26-optional-encryption-design.md`: in §4.2 change "the `session_key` field is zeroed/unused" to note it carries a fresh random **session ID**; in §4.4 replace the "new session?" subtlety (param-based) with the session-ID detection; and in §5 add that plaintext recovers from a TX restart via the session-ID change (no `-e`/clock dependency).

- [ ] **Step 8: Commit**

```bash
git add src/tx.cpp src/rx.cpp wfb_ng/tests/test_txrx.py docs/superpowers/specs/2026-06-26-optional-encryption-design.md
git commit -m "noenc: plaintext session ID for clock-free TX-restart recovery"
```

---

## Self-Review

**Spec coverage:**
- §4.1 CLI `-K` switch + default `""` + warning → Task 1 (TX main), Task 3 (RX main). ✓
- §4.2 distinct `0x3/0x4` types → Task 1 Step 3. ✓
- §4.3 TX branches (constructor guard, `rebuild_session_packet`, `send_block_fragment`, `send_swfec_wire`) → Task 1 Steps 5-8. ✓
- §4.4 RX `setup_session` + `SESSION_PLAIN`/`DATA_PLAIN` + param-based change detection + mode guards → Task 2, Task 3 Steps 5-8. ✓
- §4.5 size accounting (no macro change; explicit plaintext min/max) → Task 3 Step 6 (max bound), Step 8. ✓
- §4.6 `key_arg` + `[video]` opt-in → Task 5, Task 6. ✓
- §5 safety invariant (encrypted RX rejects plaintext) → Task 3 Steps 5-7 (guards) + `PlaintextSafetyTestCase`. ✓
- §7 testing (RS + swfec round-trip, safety, regression) → Tasks 1/3/4 tests + `make test`. ✓

**Placeholder scan:** every code step contains complete code; no TBD/TODO/"handle edge cases". ✓

**Type/name consistency:** `encrypted` (both classes), `setup_session(uint8_t,uint8_t,uint8_t,uint64_t)` and `swfec_set_deadline(uint8_t)` (declared Task 2 Step 1, defined Step 2, called Tasks 2-3), `WFB_PACKET_DATA_PLAIN`/`WFB_PACKET_SESSION_PLAIN` (defined Task 1, consumed Task 3), `key_arg(cfg)` (defined Task 5 Step 3, used Steps 4 + tested Step 1). The plaintext session reader uses a local `const wsession_data_t* sd` to avoid aliasing the non-const `new_session_data`. ✓

**Note for the implementer:** member-initializer order must match declaration order (GCC `-Werror=reorder`): `encrypted` is declared and initialized last among each class's init-list members per the steps above. Build with `make wfb_rx wfb_tx` after each C++ task and watch for reorder/unused warnings.
