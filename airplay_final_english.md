# AirPlay 2 Technical Findings: macOS to HomePod mini Stereo Pair

Date: 2026-06-26, updated 2026-06-28 with confirmed route-selection capture conclusions.

Target: macOS sender to a HomePod mini stereo pair named `卧室` (Bedroom).

This document preserves protocol fields, device capabilities, capture facts, and inference boundaries; reverse-engineering processes, command steps, and tool operation details have been removed.

## 1. Summary of Conclusions

- The HomePod mini stereo pair exposes itself on the LAN as two AirPlay/RAOP receivers: `卧室` and `卧室 (2)`, not as a single black-box endpoint.
- Both receivers share `gid`, `pgid`, `gpn`, and `tsid`, indicating they belong to the same stereo playback group.
- Each receiver possesses its own independent `deviceid`, `pi`, `psi`, `pk`, `featuresEx`, `statusFlags`, and network identity.
- Both receivers listen on TCP `7000`; `OPTIONS *` returns `AirTunes/950.7.1`, supporting `ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET, PUT`.
- `GET /info` returns `application/x-apple-binary-plist` containing `supportedFormats`, `supportedAudioFormatsExtended`, `playbackCapabilities`, `features/featuresEx`, volume, device identity, and sender address.
- The `/info` capability matrix shows that both HomePod minis have identical `supportedFormats`, `supportedAudioFormatsExtended`, and `playbackCapabilities`; differences are concentrated in identity, role, or status fields.
- `featuresEx` values are `AMp/StBLNTwQoS54` and `AMp/StBrNTwQoS54` respectively; local left/right channel verification has confirmed that `StBL` corresponds to the physical left and `StBr` to the physical right.
- Multiple real-playback captures confirm: the Mac sends byte-for-byte identical RTP-like UDP audio streams simultaneously to both HomePod members, with RTP payload type `97` and RTP timestamp incrementing by `352` per packet.
- RTP timestamps and wall-clock duration are consistent with 44.1 kHz, 352 sample frames per packet.
- In existing route-selection, confirmed-output, and playback captures, PTP synchronization traffic appears exclusively between the Mac and `192.168.2.197`, indicating that `卧室` / `192.168.2.197` stably assumes the timing leader (or at least timing peer) role in the current local configuration; `192.168.2.117` receives audio data but does not directly participate in PTP in these pcaps.
- The local confirmed route-selection pcap captured switching, `GET /info`, PTP, and real RTP-like media streams, but no plaintext stream `SETUP`; the control channel enters a binary or encrypted form on this path.
- Therefore, local capture facts can prove `spf=352`, 44.1 kHz, RTP payload type `97`, dual-identical-stream delivery, and the PTP timing peer; `ct=2`, `audioFormat=262144`, and `streams[].type=96` are inferences consistent with open-source AirPlay 2 documentation and receiver implementations, not direct evidence from a local plaintext `SETUP`.

## 2. Device and Discovery Information

Local network context:

| Item | Value |
| --- | --- |
| Active LAN interface | `en0` |
| Mac IPv4 | `192.168.2.206` |
| AWDL interface | `awdl0`, active |

AirPlay instances:

| Instance | Host | IP | Port | Model | Source version | OS version |
| --- | --- | --- | ---: | --- | --- | --- |
| `卧室` | `woshi.local.` | `192.168.2.197` | 7000 | `AudioAccessory5,1` | `950.7.1` | `26.5` |
| `卧室 (2)` | `woshi-0499B95BC204.local.` | `192.168.2.117` | 7000 | `AudioAccessory5,1` | `950.7.1` | `26.5` |

RAOP instances:

| Instance | Host | Port | `am` | `vs` | Transport |
| --- | --- | ---: | --- | --- | --- |
| `5EB9F5399D7F@卧室` | `woshi.local.` | 7000 | `AudioAccessory5,1` | `950.7.1` | `tp=UDP` |
| `A6C9681350A8@卧室 (2)` | `woshi-0499B95BC204.local.` | 7000 | `AudioAccessory5,1` | `950.7.1` | `tp=UDP` |

Key AirPlay TXT and `/info` identity fields:

| Field | `卧室` / `192.168.2.197` | `卧室 (2)` / `192.168.2.117` | Notes |
| --- | --- | --- | --- |
| `deviceid` | `5E:B9:F5:39:9D:7F` | `A6:C9:68:13:50:A8` | Per-receiver AirPlay ID |
| `btaddr` | `5E:2A:A4:37:A9:62` | `6D:75:EE:D8:0A:2A` | Bluetooth-related address |
| `macAddress` from `/info` | `94:EA:32:B3:79:17` | `04:99:B9:5B:C2:04` | Hardware/network identity |
| `gid` | `57B542A0-BAE6-47EB-BCDB-702FE1647DA7` | same | Group ID |
| `pgid` | `57B542A0-BAE6-47EB-BCDB-702FE1647DA7` | same | Playback group ID |
| `gpn` | `卧室` | `卧室` | Group playback name |
| `tsid` | `AD7AFC26-E4D8-594A-AB7D-CD8EB5E4A12E` | same | Timing/session group identifier candidate |
| `pi` | `25458874-1293-4ecc-96c0-929bd8569201` | `45a1ca0a-a35a-4a90-8df8-1dec26e49ad2` | Per-instance persistent identifier |
| `psi` | `5CB9F539-9D7F-48A3-82B2-00BC24C72396` | `A7C96813-50A8-47CA-AD2C-33779697D2B6` | Per-speaker/session identifier candidate |
| `pk` | `8387c632...51153a9` | `3623e6b5...2d84c79` | Public key material |
| `features` | `0x4A7FCA00,0x3C354BD0` | `0x4A7FCA00,0x3C356BD0` | Second word differs |
| `flags` / RAOP `sf` | `0x3a0c04` | `0x1a2c04` | Likely state/role flags differ |
| `fex` | `AMp/StBLNTwQoS54` | `AMp/StBrNTwQoS54` | `StBL` = physical left, `StBr` = physical right |

Interpretation:

- The shared `gid`, `pgid`, `gpn`, and `tsid` bind the two endpoints as the same stereo group.
- `features`, `flags`, `fex`, `featuresEx`, and `statusFlags` are the most noteworthy role/channel/leader/member fields.
- Local verification has confirmed that `StBL` / `StBr` correspond to physical left/right roles: `192.168.2.197` / `卧室` / `StBL` is the left member, `192.168.2.117` / `卧室 (2)` / `StBr` is the right member.

## 3. RTSP and `/info` Capabilities

Both HomePod endpoints return from `OPTIONS *`:

```text
RTSP/1.0 200 OK
Content-Length: 0
Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET, PUT
Server: AirTunes/950.7.1
```

Observed details:

- `Server` matches mDNS `srcvers` / RAOP `vs`: `AirTunes/950.7.1`.
- Both stereo members expose the same RTSP method set.
- `X-Apple-ProcessingTime` appears in samples, approximately `3-4 ms`.
- `X-Apple-RequestReceivedTimestamp` appears in samples, usable for timing correlation.

`GET /info` returns `application/x-apple-binary-plist`. Key decoded fields:

| Field | `卧室` / `192.168.2.197` | `卧室 (2)` / `192.168.2.117` |
| --- | --- | --- |
| `name` | `卧室` | `卧室 (2)` |
| `model` | `AudioAccessory5,1` | `AudioAccessory5,1` |
| `sourceVersion` | `950.7.1` | `950.7.1` |
| `protocolVersion` | `1.1` | `1.1` |
| `deviceID` | `5E:B9:F5:39:9D:7F` | `A6:C9:68:13:50:A8` |
| `pi` | `25458874-1293-4ecc-96c0-929bd8569201` | `45a1ca0a-a35a-4a90-8df8-1dec26e49ad2` |
| `psi` | `5CB9F539-9D7F-48A3-82B2-00BC24C72396` | `A7C96813-50A8-47CA-AD2C-33779697D2B6` |
| `features` | `4338457174016510464` | `4338492358388599296` |
| `featuresEx` | `AMp/StBLNTwQoS54` | `AMp/StBrNTwQoS54` |
| `statusFlags` | `3804164` | `1715204` |
| `initialVolume` | `-26.12949562072754` | `-26.12949562072754` |
| `volumeControlType` | `3` | `3` |

Both endpoints report the same `supportedFormats`:

```python
supportedFormats = {
    "lowLatencyAudioStream": 33554432,
    "screenStream": 21235712,
    "audioStream": 21235712,
    "bufferStream": -577021992844656640,
}
```

Both endpoints report the same `supportedAudioFormatsExtended`:

```python
supportedAudioFormatsExtended = {
    "bufferStream": [
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
        60, 61, 62, 19, 23, 21, 22, 63, 65, 66,
        70, 71, 72, 73, 33, 34, 35, 74, 75, 39, 40,
    ]
}
```

Both endpoints report the same `playbackCapabilities`:

```python
playbackCapabilities = {
    "supportsAirPlayVideoWithSharePlay": True,
    "supportsOfflineHLS": False,
    "supportsInterstitials": False,
    "supportsUIForAudioOnlyContent": False,
    "supportsStopAtEndOfQueue": False,
    "supportsIntegratedTimeline": False,
    "supportsV2ArtworkMetadata": False,
    "supportsFPSSecureStop": False,
}
```

`/info` field comparison conclusions:

- Both receivers have 27 `/info` keys.
- 17 capability/state keys are identical; 10 identity/status keys differ.
- Differing fields include `deviceID`, `features`, `featuresEx`, `macAddress`, `name`, `pi`, `pk`, `psi`, and `statusFlags`.
- Shared capability fields include `model`, `sourceVersion`, `protocolVersion`, `supportedFormats`, `supportedAudioFormatsExtended`, and `playbackCapabilities`.
- The Mac's LAN IP and transient client port appear in `senderAddress`, indicating the receiver records the sender connection origin.

Capability matrix:

| Field family | `192.168.2.197` | `192.168.2.117` | Interpretation |
| --- | --- | --- | --- |
| `supportedFormats.audioStream` | `0x0000000001440800`, bits `11,18,22,24` | same | Same realtime/audio capability bitmask. |
| `supportedFormats.lowLatencyAudioStream` | `0x0000000002000000`, bit `25` | same | Same low-latency capability bitmask. |
| `supportedFormats.bufferStream` | `0xf7fe018e00e80000`, bits `19,21,22,23,33,34,35,39,40,49,50,51,52,53,54,55,56,57,58,60,61,62,63` | same | Same buffered-stream capability bitmask. |
| `supportedAudioFormatsExtended.bufferStream` | 31 IDs | same 31 IDs | Same receiver-advertised extended buffered-audio profile IDs. |
| `playbackCapabilities` | same booleans | same booleans | No evidence of asymmetric media capability between stereo members. |
| `features/featuresEx/statusFlags` | differs | differs | Likely identity, role, or state bits rather than codec support. |

Where `StBL` / `StBr` in `featuresEx` have been confirmed by local left/right channel testing to correspond to physical left/right. `features` and `statusFlags` also differ between left and right members, but currently only the `StB[L/R]` substring of `featuresEx` is treated as a verified left/right role marker; the remaining bits are not declared with per-bit semantics.

This proves that both HomePod mini members advertise the same stream-format capability surface, but does not prove which codec macOS selects during actual playback; codec selection still requires the stream `SETUP` plist or equivalent evidence.

## 4. Protocol Model

The protocol layers for this target:

1. Discovery
   - `_airplay._tcp.local` and `_raop._tcp.local`.
   - TXT fields advertise model, version, features, group identifiers, flags, and key material.

2. Control channel
   - TCP port `7000`.
   - RTSP/1.0-like messages; Apple uses HTTP-like endpoints and binary plists.
   - Relevant methods/endpoints include `OPTIONS`, `GET /info`, `POST /pair-setup`, `POST /pair-verify`, `POST /fp-setup`, `SETUP`, `RECORD`, `FLUSH`, `TEARDOWN`, `SET_PARAMETER`, `GET_PARAMETER`, and `POST /feedback`.

3. Pairing and authentication
   - AirPlay 2 may involve HomeKit transient pairing, persistent HomeKit pairing, FairPlay v3, and some MFi-related paths.
   - Local devices expose `pk` public-key-like material in mDNS.

4. Stream setup
   - Public AirPlay 2 RTSP notes describe two important `SETUP` phases:
     - Initial setup: carries sender/device/timing/group/encryption metadata; the receiver returns event/timing information.
     - Stream setup: carries `streams[]` entries such as `audioFormat`, `ct`, `spf`, `shk`, `latencyMin`, `latencyMax`, `controlPort`, and stream `type`.
   - Public notes map `streams[].type=96` to realtime general audio and `streams[].type=103` to buffered general audio.
   - Compression type values: `1=LPCM`, `2=ALAC`, `4=AAC`, `8=AAC ELD`, `32=OPUS`.

5. Audio data and control
   - RTP carries data packets.
   - RTCP carries control/timing/retransmission messages.
   - Public AirPlay 2 notes describe RTP payload encryption using ChaCha20-Poly1305 on the observed data path; packets contain a 12-byte RTP header, followed by encrypted payload, followed by a 24-byte trailer consisting of 8-byte nonce and 16-byte tag-related material.

6. Timing and synchronization
   - Stereo group playback requires tight synchronization.
   - Public projects point to PTP and/or NTP timing. Shairport Sync's AirPlay 2 path uses NQPTP and ports `319/320`.
   - The local TXT field `tsid` is shared between both HomePods.

## 5. Encoding and Stream Fields

`/info` does not directly expose the codec chosen by macOS during actual playback. The actual encoding selection resides in the playback setup `SETUP` plist, particularly in `streams[]`.

`SETUP` fields of interest:

| Field | Expected type | Meaning |
| --- | --- | --- |
| `streams[].type` | integer | Stream class. Public notes: `96` realtime audio, `103` buffered audio. |
| `streams[].ct` | integer bit/value | Compression. Current map: `1` PCM/LPCM, `2` ALAC, `4` AAC-LC, `8` AAC-ELD, `32` OPUS. |
| `streams[].audioFormat` | integer bitfield/code | Concrete sample format/rate/channel profile. |
| `streams[].spf` | integer | Sample frames per packet. |
| `streams[].latencyMin` / `latencyMax` | integer frames | Sender latency window; divide by sample rate for seconds. |
| `streams[].controlPort` | integer | Sender RTCP/control port; receiver response may contain receiver-side `controlPort`. |
| `streams[].dataPort` | integer in response | Receiver RTP/data port for UDP transport. |
| `streams[].shk` / `shiv` / `ekey` / `eiv` | bytes | Keying material or wrapped key/IV. |
| `timingProtocol` | string | `PTP` vs legacy/NTP path. |
| `timingPeerInfo` / `timingPeerList` | plist dict/list | Multi-room timing peer graph. |
| `groupUUID`, `groupContainsGroupLeader`, `isMultiSelectAirPlay` | plist fields | Group routing and leader/member behavior. |

Open-source `SETUP` field map:

| Field | Open-source meaning | Values relevant to this target |
| --- | --- | --- |
| `streams[].type` | AirPlay stream class / RTP payload namespace. The Cozzi RTSP example uses `96` for realtime audio; openairplay stores it as stream payload/type. | Wire RTP payload type is `97`, not necessarily in the same namespace as RTSP `streams[].type`. HomePod system audio is closest to the `type=96` realtime example; `103` is common for buffered audio in public notes. |
| `streams[].ct` | Compression type. openairplay maps `0x1=PCM`, `0x2=ALAC`, `0x4=AAC_LC`, `0x8=AAC_ELD`; the Cozzi example uses `ct=2`. | Combined with 44.1 kHz, `spf=352`, and realtime-like RTP behavior, `ct=2` / ALAC is the strongest open-source-matching hypothesis, but not a local decrypted/local plaintext fact. |
| `streams[].audioFormat` | Audio format bitmask/code. The Cozzi audio table maps bit `18` / `0x40000` to `ALAC/44100/16/2`; RTSP example shows `audioFormat=262144`. | Matches the observed 44.1 kHz stereo-style path and the `ct=2` example. |
| `streams[].spf` | Sample frames per packet. openairplay passes it through as `self.sdp.spf`; the Cozzi RTSP example shows `spf=352`. | Directly supported by local pcap: RTP timestamps in all successful HomePod playback captures increment by `352` per media packet. |
| `latencyMin` / `latencyMax` | Sender latency window in sample frames. The Cozzi example shows `11025` and `88200`, i.e., 0.25 s and 2.0 s at 44.1 kHz. | Not directly extracted locally, but consistent with the public realtime example. |
| `shk` / `shiv` | Stream key/IV material. | Local media packets show a 16-byte auth tag + 8-byte nonce trailer, consistent with encrypted RTP. |

The current HomePod `/info` reports identical `supportedAudioFormatsExtended.bufferStream` IDs:

```text
49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
60, 61, 62, 19, 23, 21, 22, 63, 65, 66,
70, 71, 72, 73, 33, 34, 35, 74, 75, 39, 40
```

These numbers should not be directly treated as `ct`; in the absence of `SETUP` and RTP correlation, they should be regarded as receiver-specific supported profile IDs.

Format information that can be conservatively mapped falls into two categories:

| Source field | Locally observed values | Conservative interpretation |
| --- | --- | --- |
| `supportedFormats.audioStream` | bits `11,18,22,24` | Per the public AirPlay 2 audio bitmask, these can correspond to `PCM/44100/16/2`, `ALAC/44100/16/2`, `AAC-LC/44100/2`, `AAC-ELD/44100/2`. This is a capability bitmask, not the actual playback selection. |
| `supportedFormats.lowLatencyAudioStream` | bit `25` | Per the public bitmask, can correspond to `AAC-ELD/48000/2`. |
| `supportedFormats.bufferStream` | bits `19,21,22,23,33,34,35,39,40,49,50,51,52,53,54,55,56,57,58,60,61,62,63` | bits `19,21,22,23` can be interpreted per the public bitmask as `ALAC/44100/24/2`, `ALAC/48000/24/2`, `AAC-LC/44100/2`, `AAC-LC/48000/2`; bits `33+` exceed the Cozzi public table and cannot be mapped solely from that table. |
| `supportedAudioFormatsExtended.bufferStream` | IDs `19,21,22,23,33,34,35,39,40,49..58,60..63,65,66,70..75` | Partially overlaps with the capability bitmask but belongs to an extended profile ID list; currently cannot be fully mapped to `(codec, sample format, sample rate, channels)`. It can only be said that the two members are identical. |

The public AirPlay 2 audio format table covers bits `2..32`, and therefore only the low-order bitmask can be interpreted. High IDs such as `49+` in `supportedAudioFormatsExtended` likely represent Apple/HomePod extended profiles, but the current local plaintext `SETUP` does not expose the binding between these IDs and the actual `audioFormat`.

The most reliable codec inference for this Mac -> HomePod mini stereo-group path:

```text
Open-source realtime SETUP model:
  streams[].type        ~= 96
  streams[].ct          ~= 2      # ALAC
  streams[].audioFormat ~= 262144 # 0x40000, ALAC/44100/16/2
  streams[].spf         = 352

Local pcap facts:
  RTP payload type      = 97
  RTP timestamp delta   = 352 per packet
  inferred sample rate  = 44100 Hz
  media packet payload  = encrypted/high-entropy, not directly decodable
```

`spf=352` and 44.1 kHz are direct local pcap facts. `ct=2` and `audioFormat=262144` come from matching inference against the Cozzi documented `SETUP` example and the openairplay compression map, because the local control channel did not expose a plaintext stream `SETUP`.

## 6. Real-Playback Capture Facts

### 6.1 Playback-stage capture: `airplay-playback-2026-06-26.pcap`

Capture summary:

| Field | Value |
| --- | --- |
| packets captured | `4082` |
| duration | `13.986829 s` |
| plaintext RTSP markers on TCP 7000 | none |

Main media flows:

| Flow | Packets | Payload bytes | RTP payload type | RTP sequence | RTP timestamp delta | Payload length |
| --- | ---: | ---: | --- | --- | --- | --- |
| `192.168.2.206:51297 -> 192.168.2.117:49761` | 1756 | 1762251 | `97` | `18748..20503`, gaps `0` | `352` for 1755 intervals | `720..1452` |
| `192.168.2.206:62010 -> 192.168.2.197:56052` | 1756 | 1762251 | `97` | `18748..20503`, gaps `0` | `352` for 1755 intervals | `720..1452` |

RTP comparison:

- The two RTP-like UDP streams are byte-for-byte identical across all 1756 packet pairs.
- Both streams have the same 12-byte RTP header, the same encrypted payload, and the same 24-byte trailer.
- `allPacketsByteIdentical=true`.
- `fullPacketSame=1756`.
- The maximum observed send-time offset for paired packets is approximately `0.000247 s`.
- Stereo role/channel split is not visible in the LAN RTP payload bytes in this capture.

RTP packet layout:

| Component | Bytes | Observed detail |
| --- | ---: | --- |
| RTP header | 12 | Version `2`, payload type `97`, SSRC `0`, continuous sequence/timestamp. |
| Encrypted payload | `684..1416` | Variable-length encrypted audio payload. |
| Auth tag | 16 | First 16 bytes of the trailing 24 bytes. |
| Nonce | 8 | Last 8 bytes of the trailing 24 bytes. All 1756 nonces are unique. |

First media packet trailer:

```text
trailer24 = cb9b2c5ca63fdfa32d1b3f89384a73d8 ea4b040000000000
tag16     = cb9b2c5ca63fdfa32d1b3f89384a73d8
nonce8    = ea4b040000000000
nonce8 LE = 281578
```

RTP timing inference:

```text
RTP packets: 1756
RTP timestamp step: 352
timestamp span: 617760 frames
617760 / 44100 = 14.008 s
617760 / 48000 = 12.870 s
wall-clock capture span for stream = 13.980 s
```

This strongly matches 44.1 kHz audio with `spf=352`. The observed RTP payload type on the wire is `97`; it is not in the same namespace as the AirPlay 2 RTSP `streams[].type` values `96` or `103`.

PTP/timing flows:

| Flow | Packets | Payload bytes | Notes |
| --- | ---: | ---: | --- |
| `192.168.2.197:319 -> 192.168.2.206:319` | 114 | 5016 | PTP sync messages |
| `192.168.2.206:319 -> 192.168.2.197:319` | 114 | 5016 | PTP delay requests |
| `192.168.2.197:320 -> 192.168.2.206:320` | 257 | 19814 | PTP follow-up, delay response, announce, signalling |

There are no PTP packets involving `192.168.2.117`. This fact supports `192.168.2.197` being the timing leader/peer in this session, while `192.168.2.117` receives synchronized media but does not directly negotiate PTP with the Mac.

PTP identities:

| Flow | Message types | Clock identity | Source port id |
| --- | --- | --- | ---: |
| `192.168.2.197:320 -> 192.168.2.206:320` | `Delay_Resp=115`, `Follow_Up=114`, `Announce=14`, `Signaling=14` | `94ea3246bb640008` | `32777` |
| `192.168.2.197:319 -> 192.168.2.206:319` | `Sync=114` | `94ea3246bb640008` | `32777` |
| `192.168.2.206:319 -> 192.168.2.197:319` | `Delay_Req=114` | `f68cba224c6c0008` | `32770` |

TCP 7000 control:

| Flow | Packets | Payload bytes | Payload pattern |
| --- | ---: | ---: | --- |
| `192.168.2.206:53695 -> 192.168.2.197:7000` | 14 | 602 | 7 client payloads of 86 bytes |
| `192.168.2.197:7000 -> 192.168.2.206:53695` | 14 | 2142 | 7 server payloads of 306 bytes |
| `192.168.2.206:53696 -> 192.168.2.117:7000` | 14 | 602 | 7 client payloads of 86 bytes |
| `192.168.2.117:7000 -> 192.168.2.206:53696` | 14 | 2142 | 7 server payloads of 306 bytes |

No plaintext `RTSP/1.0`, `SETUP`, `GET /info`, or `bplist00` markers were found in the TCP 7000 payloads. This capture captured playback-stage encrypted/binary control frames rather than initial RTSP setup.

Frame-level TCP 7000 pattern:

| Direction | Flows compared | Frame length sequence | Byte-identical frames | Stable prefix |
| --- | --- | --- | ---: | --- |
| Mac -> HomePod | `192.168.2.206:53696 -> 192.168.2.117:7000` vs `192.168.2.206:53695 -> 192.168.2.197:7000` | seven `86` byte payloads on each flow | `0 / 7` | first two bytes match on all frames: `4400` |
| HomePod -> Mac | `192.168.2.117:7000 -> 192.168.2.206:53696` vs `192.168.2.197:7000 -> 192.168.2.206:53695` | seven `306` byte payloads on each flow | `0 / 7` | first two bytes match on all frames: `2001` |

The TCP 7000 control frames have identical length sequences and identical first-two-byte prefix patterns between the two members, but the payloads are not byte-for-byte identical; this contrasts with the byte-for-byte identical RTP media streams.

### 6.2 Confirmed route-selection capture: `airplay-route-selection-confirmed-2026-06-28.pcap`

Capture summary:

| Field | Value |
| --- | --- |
| packets captured | `2527` |
| duration | `36.672354 s` |
| TCP 7000 plaintext markers | `RTSP/1.0=20`, `GET /info=7`, `bplist00=7`, `SETUP=0` |

Main media flows:

| Flow | Packets | Payload bytes | RTP payload type | RTP sequence | RTP timestamp delta | Best sample rate |
| --- | ---: | ---: | --- | --- | --- | ---: |
| `192.168.2.206:54384 -> 192.168.2.197:50622` | 375 | 476686 | `97` | `45578..45952`, gaps `0` | `352` for 374 intervals | `44100` |
| `192.168.2.206:59793 -> 192.168.2.117:50963` | 375 | 476686 | `97` | `45578..45952`, gaps `0` | `352` for 374 intervals | `44100` |

RTP comparison:

- `allPacketsByteIdentical=true` for all 375 paired media packets.
- The first RTP-like packet has a 24-byte trailer, which can be split into a 16-byte tag and an 8-byte nonce.
- The first nonce is `0000000000000000`.
- Nonces are unique within the stream.

TCP 7000 / plist result:

| Evidence | Result |
| --- | --- |
| `GET /info` | Present; binary plist bodies extracted and decoded for both HomePods. |
| Stream `SETUP` plaintext | Not present: `SETUP=0` in reassembled TCP 7000 streams. |
| Extracted `streams[]` plist | Not present. Decoded plist summary contains `/info` capability plists only. |
| Control channel after route selection | Binary/high-entropy payloads without parseable RTSP method names for stream setup. |

This pcap is the strongest local route-selection evidence: even though the capture started before switching to `卧室`, macOS did not expose the stream `SETUP` in plaintext on this path. Therefore, the field-level `ct/audioFormat/type/spf` model comes from open-source AirPlay 2 receiver documentation and code; `spf=352` and 44.1 kHz come from local RTP timestamp facts.

### 6.3 Cross-capture stability

Stable items across existing local captures:

| Capture | Media RTP payload type | RTP timestamp step | Best sample rate | PTP peer observed |
| --- | --- | --- | --- | --- |
| `airplay-playback-2026-06-26.pcap` | `97` | `352` | `44100` | `192.168.2.197` |
| `airplay-confirmed-output-2026-06-28.pcap` | `97` | `352` | `44100` | `192.168.2.197` |
| `airplay-route-selection-confirmed-2026-06-28.pcap` | `97` | `352` | `44100` | `192.168.2.197` |

Thus, in the observed local stereo group configuration and `say`/system-output playback path, wire RTP payload type `97`, timestamp step `352`, 44.1 kHz, and `192.168.2.197` as the timing peer are all stable facts. This conclusion is still not extrapolated to the Apple Music buffered path, video AirPlay path, or all states after reboot/left-right role reconfiguration.

## 7. Boundary Between Local Evidence and Open-Source Model

Local evidence has confirmed:

- macOS opens TCP 7000 control sessions to both HomePod members during route selection and playback.
- The `/info` binary plists of both members have been decoded and compared.
- Both members advertise the same stream-format capability surface.
- Confirmed HomePod-output captures contain two direct UDP RTP-like media streams, sourced from the Mac, destined for the two members respectively.
- The two media streams are byte-for-byte identical across all captured packets, including RTP header, encrypted payload, and 24-byte trailer.
- RTP payload type is `97`.
- RTP sequence numbers are continuous.
- RTP timestamps increment by `352` per packet.
- RTP timing is inferred as 44.1 kHz, 352 sample frames per packet.
- PTP timing traffic uses UDP `319/320` and appears exclusively between the Mac and `192.168.2.197`; no PTP exchange with `192.168.2.117` appears in the captures.
- TCP 7000 stream reassembly found `/info` RTSP/plist bodies, but no plaintext stream `SETUP` was found on the confirmed route-selection path.

Open-source model support:

- `SETUP streams[].ct` map: `1=PCM`, `2=ALAC`, `4=AAC-LC`, `8=AAC-ELD`; Cozzi also records OPUS in the audio format table.
- The Cozzi realtime audio `SETUP` example uses `type=96`, `ct=2`, `audioFormat=262144`, `spf=352`, `latencyMin=11025`, and `latencyMax=88200`.
- `audioFormat=262144` is `0x40000`, matching the Cozzi table entry `ALAC/44100/16/2`.
- Shairport Sync AirPlay 2 notes list working macOS/HomePod-class combinations, including `ALAC/S16/44100/2` realtime audio and AAC/ALAC buffered variants.

Explicit boundaries:

- The local HomePod path did not expose the stream `SETUP` in plaintext in these pcaps.
- `spf=352` and 44.1 kHz are local facts.
- `ct=2`, `streams[].type=96`, and `audioFormat=262144` are open-source-matched inferences.
- The wire RTP payload type `97` should not be conflated with the RTSP `streams[].type` field.
- The numeric IDs in `supportedAudioFormatsExtended.bufferStream` should not be directly interpreted as `ct`.



## 8. Final Technical Conclusions

The HomePod mini stereo pair presents itself on the LAN as two AirPlay/RAOP receivers that share group identifiers but possess independent receiver identity and role/status fields. Both members have an identical codec/format capability surface; there is currently no evidence of asymmetry between the two members in supported media formats. `StBL` / `StBr` in `featuresEx` has been confirmed by local left/right channel testing as physical left/right: `192.168.2.197` is left, `192.168.2.117` is right.

Both real-playback and confirmed route-selection pcaps show that macOS sends two direct UDP RTP-like media streams to both HomePod members. The two streams are byte-for-byte identical at the packet level, using wire RTP payload type `97`, with continuous sequences, and timestamps incrementing by `352` per packet, matching 44.1 kHz, 352 sample frames per packet. On the LAN, no separation of left and right channels into different RTP payload bytes is observable.

PTP timing in observed sessions occurs only between the Mac and `192.168.2.197`; therefore `192.168.2.197` is the stable observed timing peer/leader under the current configuration. `192.168.2.117` receives synchronized media but does not directly appear in PTP exchanges.

The confirmed route-selection pcap captured `/info`, PTP, binary/encrypted TCP 7000 control, and RTP media, but no plaintext stream `SETUP`. This document therefore treats local packet observations and open-source SETUP semantics separately: local facts prove `spf=352` and 44.1 kHz; public receiver code and documentation support the most probable realtime model of `streams[].type ~= 96`, `ct ~= 2` / ALAC, `audioFormat ~= 262144` / `ALAC/44100/16/2`.
