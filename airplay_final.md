# AirPlay 2 技术结论：macOS 到 HomePod mini 立体声组

日期：2026-06-26，2026-06-28 更新确认路由选择抓包结论。

目标：macOS sender 到名为 `卧室` 的 HomePod mini 立体声组。

本文保留协议字段、设备能力、抓包事实和推断边界；逆向过程、命令步骤和工具操作细节已删去。

## 1. 结论摘要

- HomePod mini 立体声组在局域网中暴露为两个 AirPlay/RAOP receiver：`卧室` 和 `卧室 (2)`，不是单一黑盒 endpoint。
- 两个 receiver 共享 `gid`、`pgid`、`gpn` 和 `tsid`，表明它们属于同一立体声播放组。
- 两个 receiver 各自拥有独立的 `deviceid`、`pi`、`psi`、`pk`、`featuresEx`、`statusFlags` 和网络身份。
- 两个 receiver 均监听 TCP `7000`，`OPTIONS *` 返回 `AirTunes/950.7.1`，支持 `ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET, PUT`。
- `GET /info` 返回 `application/x-apple-binary-plist`，包含 `supportedFormats`、`supportedAudioFormatsExtended`、`playbackCapabilities`、`features/featuresEx`、音量、设备身份和 sender 地址。
- `/info` 能力矩阵显示两个 HomePod mini 的 `supportedFormats`、`supportedAudioFormatsExtended` 和 `playbackCapabilities` 完全相同；差异集中在身份、角色或状态字段。
- `featuresEx` 分别为 `AMp/StBLNTwQoS54` 和 `AMp/StBrNTwQoS54`；本地左右声道验证已确认 `StBL` 对应物理 left，`StBr` 对应物理 right。
- 多次真实播放抓包确认：Mac 同时向两个 HomePod 成员发送逐字节完全相同的 RTP-like UDP 音频流，RTP payload type 为 `97`，RTP timestamp 每包递增 `352`。
- RTP 时间戳和墙钟时长匹配 44.1 kHz、每包 352 sample frames。
- PTP 同步在现有 route-selection、confirmed-output 和 playback captures 中均只出现在 Mac 与 `192.168.2.197` 之间，说明 `卧室` / `192.168.2.197` 在当前本地配置中稳定承担 timing leader 或至少 timing peer 角色；`192.168.2.117` 收到音频数据但未在这些 pcap 中直接参与 PTP。
- 本地 confirmed route-selection pcap 捕获到了切换、`GET /info`、PTP 和真实 RTP-like 媒体流，但没有明文 stream `SETUP`；控制通道在该路径上进入二进制或加密形态。
- 因此，本地抓包事实能证明 `spf=352`、44.1 kHz、RTP payload type `97`、双发同包和 PTP timing peer；`ct=2`、`audioFormat=262144`、`streams[].type=96` 属于与开源 AirPlay 2 文档和 receiver 实现相匹配的推断，而不是本地明文 `SETUP` 直接证据。

## 2. 设备与发现信息

本地网络上下文：

| 项 | 值 |
| --- | --- |
| Active LAN interface | `en0` |
| Mac IPv4 | `192.168.2.206` |
| AWDL interface | `awdl0`, active |

AirPlay instances：

| Instance | Host | IP | Port | Model | Source version | OS version |
| --- | --- | --- | ---: | --- | --- | --- |
| `卧室` | `woshi.local.` | `192.168.2.197` | 7000 | `AudioAccessory5,1` | `950.7.1` | `26.5` |
| `卧室 (2)` | `woshi-0499B95BC204.local.` | `192.168.2.117` | 7000 | `AudioAccessory5,1` | `950.7.1` | `26.5` |

RAOP instances：

| Instance | Host | Port | `am` | `vs` | Transport |
| --- | --- | ---: | --- | --- | --- |
| `5EB9F5399D7F@卧室` | `woshi.local.` | 7000 | `AudioAccessory5,1` | `950.7.1` | `tp=UDP` |
| `A6C9681350A8@卧室 (2)` | `woshi-0499B95BC204.local.` | 7000 | `AudioAccessory5,1` | `950.7.1` | `tp=UDP` |

关键 AirPlay TXT 与 `/info` 身份字段：

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

解释：

- 共享 `gid`、`pgid`、`gpn` 和 `tsid` 将两个 endpoint 绑定为同一 stereo group。
- `features`、`flags`、`fex`、`featuresEx` 和 `statusFlags` 是最值得关注的 role/channel/leader/member 字段。
- 本地验证已确认 `StBL` / `StBr` 对应物理左右角色：`192.168.2.197` / `卧室` / `StBL` 是 left member，`192.168.2.117` / `卧室 (2)` / `StBr` 是 right member。

## 3. RTSP 与 `/info` 能力

两个 HomePod endpoint 的 `OPTIONS *` 返回：

```text
RTSP/1.0 200 OK
Content-Length: 0
Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET, PUT
Server: AirTunes/950.7.1
```

观测细节：

- `Server` 与 mDNS `srcvers` / RAOP `vs` 一致：`AirTunes/950.7.1`。
- 两个 stereo member 暴露相同 RTSP method set。
- 样本中出现 `X-Apple-ProcessingTime`，约 `3-4 ms`。
- 样本中出现 `X-Apple-RequestReceivedTimestamp`，可用于 timing correlation。

`GET /info` 返回 `application/x-apple-binary-plist`。关键解码字段：

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

两个 endpoint 均报告相同的 `supportedFormats`：

```python
supportedFormats = {
    "lowLatencyAudioStream": 33554432,
    "screenStream": 21235712,
    "audioStream": 21235712,
    "bufferStream": -577021992844656640,
}
```

两个 endpoint 均报告相同的 `supportedAudioFormatsExtended`：

```python
supportedAudioFormatsExtended = {
    "bufferStream": [
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
        60, 61, 62, 19, 23, 21, 22, 63, 65, 66,
        70, 71, 72, 73, 33, 34, 35, 74, 75, 39, 40,
    ]
}
```

两个 endpoint 均报告相同的 `playbackCapabilities`：

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

`/info` 字段对比结论：

- 两台 receiver 均有 27 个 `/info` keys。
- 17 个 capability/state keys 相同，10 个 identity/status keys 不同。
- 差异字段包括 `deviceID`、`features`、`featuresEx`、`macAddress`、`name`、`pi`、`pk`、`psi` 和 `statusFlags`。
- 共享能力字段包括 `model`、`sourceVersion`、`protocolVersion`、`supportedFormats`、`supportedAudioFormatsExtended` 和 `playbackCapabilities`。
- `senderAddress` 中出现 Mac 的 LAN IP 和 transient client port，说明 receiver 记录 sender connection origin。

能力矩阵：

| Field family | `192.168.2.197` | `192.168.2.117` | Interpretation |
| --- | --- | --- | --- |
| `supportedFormats.audioStream` | `0x0000000001440800`, bits `11,18,22,24` | same | Same realtime/audio capability bitmask. |
| `supportedFormats.lowLatencyAudioStream` | `0x0000000002000000`, bit `25` | same | Same low-latency capability bitmask. |
| `supportedFormats.bufferStream` | `0xf7fe018e00e80000`, bits `19,21,22,23,33,34,35,39,40,49,50,51,52,53,54,55,56,57,58,60,61,62,63` | same | Same buffered-stream capability bitmask. |
| `supportedAudioFormatsExtended.bufferStream` | 31 IDs | same 31 IDs | Same receiver-advertised extended buffered-audio profile IDs. |
| `playbackCapabilities` | same booleans | same booleans | No evidence of asymmetric media capability between stereo members. |
| `features/featuresEx/statusFlags` | differs | differs | Likely identity, role, or state bits rather than codec support. |

其中 `featuresEx` 的 `StBL` / `StBr` 已经由本地左右声道测试确认对应物理 left/right。`features` 与 `statusFlags` 也随左右 member 不同，但当前只将 `featuresEx` 的 `StB[L/R]` 子串作为已验证的左右角色标记；其余 bit 仍不做逐位语义声明。

这证明两个 HomePod mini member 广告相同的 stream-format capability surface，但不证明 macOS 在真实播放中选择了哪个 codec；codec 选择仍需 stream `SETUP` plist 或等价证据。

## 4. 协议模型

本目标的协议层次：

1. Discovery
   - `_airplay._tcp.local` 与 `_raop._tcp.local`。
   - TXT fields 广告 model、version、features、group identifiers、flags 和 key material。

2. Control channel
   - TCP port `7000`。
   - RTSP/1.0-like messages，Apple 使用 HTTP-like endpoints 和 binary plists。
   - 相关 method/endpoint 包括 `OPTIONS`、`GET /info`、`POST /pair-setup`、`POST /pair-verify`、`POST /fp-setup`、`SETUP`、`RECORD`、`FLUSH`、`TEARDOWN`、`SET_PARAMETER`、`GET_PARAMETER` 和 `POST /feedback`。

3. Pairing and authentication
   - AirPlay 2 可涉及 HomeKit transient pairing、persistent HomeKit pairing、FairPlay v3 和部分 MFi-related path。
   - 本地设备在 mDNS 中暴露 `pk` public-key-like material。

4. Stream setup
   - 公开 AirPlay 2 RTSP notes 描述两个重要 `SETUP` 阶段：
     - initial setup：携带 sender/device/timing/group/encryption metadata，receiver 返回 event/timing information。
     - stream setup：携带 `streams[]` entries，例如 `audioFormat`、`ct`、`spf`、`shk`、`latencyMin`、`latencyMax`、`controlPort` 和 stream `type`。
   - 公开 notes 将 `streams[].type=96` 映射为 realtime general audio，将 `streams[].type=103` 映射为 buffered general audio。
   - Compression type values：`1=LPCM`、`2=ALAC`、`4=AAC`、`8=AAC ELD`、`32=OPUS`。

5. Audio data and control
   - RTP carries data packets。
   - RTCP carries control/timing/retransmission messages。
   - 公开 AirPlay 2 notes 描述 observed data path 中 RTP payload encryption 使用 ChaCha20-Poly1305；packet 包含 12-byte RTP header，后接 encrypted payload，再后接 24-byte trailer，即 8-byte nonce 和 16-byte tag 相关材料。

6. Timing and synchronization
   - Stereo group playback 需要紧密同步。
   - Public projects 指向 PTP 和/或 NTP timing。Shairport Sync 的 AirPlay 2 path 使用 NQPTP 和 ports `319/320`。
   - 本地 TXT field `tsid` 在两台 HomePod 之间共享。

## 5. Encoding 与 stream fields

`/info` 不直接暴露 macOS 真实播放时选择的 codec。真实编码选择位于 playback setup 的 `SETUP` plist，尤其是 `streams[]`。

需要关注的 `SETUP` fields：

| Field | Expected type | Meaning |
| --- | --- | --- |
| `streams[].type` | integer | Stream class。公开 notes：`96` realtime audio，`103` buffered audio。 |
| `streams[].ct` | integer bit/value | Compression。当前 map：`1` PCM/LPCM，`2` ALAC，`4` AAC-LC，`8` AAC-ELD，`32` OPUS。 |
| `streams[].audioFormat` | integer bitfield/code | Concrete sample format/rate/channel profile。 |
| `streams[].spf` | integer | Sample frames per packet。 |
| `streams[].latencyMin` / `latencyMax` | integer frames | Sender latency window；除以 sample rate 得到秒。 |
| `streams[].controlPort` | integer | Sender RTCP/control port；receiver response 可包含 receiver-side `controlPort`。 |
| `streams[].dataPort` | integer in response | UDP transport 中的 receiver RTP/data port。 |
| `streams[].shk` / `shiv` / `ekey` / `eiv` | bytes | Keying material 或 wrapped key/IV。 |
| `timingProtocol` | string | `PTP` vs legacy/NTP path。 |
| `timingPeerInfo` / `timingPeerList` | plist dict/list | Multi-room timing peer graph。 |
| `groupUUID`, `groupContainsGroupLeader`, `isMultiSelectAirPlay` | plist fields | Group routing and leader/member behavior。 |

Open-source `SETUP` field map：

| Field | Open-source meaning | Values relevant to this target |
| --- | --- | --- |
| `streams[].type` | AirPlay stream class / RTP payload namespace。Cozzi RTSP example uses `96` for realtime audio；openairplay stores it as stream payload/type。 | Wire RTP payload type is `97`，不一定与 RTSP `streams[].type` 同 namespace。HomePod system audio 最接近 `type=96` realtime example；`103` 常见于 public notes 中的 buffered audio。 |
| `streams[].ct` | Compression type。openairplay maps `0x1=PCM`, `0x2=ALAC`, `0x4=AAC_LC`, `0x8=AAC_ELD`；Cozzi example uses `ct=2`。 | 结合 44.1 kHz、`spf=352` 和 realtime-like RTP behavior，`ct=2` / ALAC 是最强 open-source-matching hypothesis，但不是本地 decrypted/local plaintext fact。 |
| `streams[].audioFormat` | Audio format bitmask/code。Cozzi audio table maps bit `18` / `0x40000` to `ALAC/44100/16/2`；RTSP example shows `audioFormat=262144`。 | 与 observed 44.1 kHz stereo-style path 和 `ct=2` example 匹配。 |
| `streams[].spf` | Sample frames per packet。openairplay passes it through as `self.sdp.spf`；Cozzi RTSP example shows `spf=352`。 | 本地 pcap 直接支持：所有成功 HomePod playback captures 中 RTP timestamps 每个 media packet 递增 `352`。 |
| `latencyMin` / `latencyMax` | Sender latency window in sample frames。Cozzi example shows `11025` and `88200`，即 44.1 kHz 下 0.25 s 和 2.0 s。 | 本地未直接抽取，但与 public realtime example 一致。 |
| `shk` / `shiv` | Stream key/IV material。 | 本地媒体 packets 显示 16-byte auth tag + 8-byte nonce trailer，与 encrypted RTP 一致。 |

当前 HomePod `/info` 报告相同的 `supportedAudioFormatsExtended.bufferStream` IDs：

```text
49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
60, 61, 62, 19, 23, 21, 22, 63, 65, 66,
70, 71, 72, 73, 33, 34, 35, 74, 75, 39, 40
```

这些数字不应被直接当作 `ct`；在缺少 `SETUP` 和 RTP correlation 前，应视为 receiver-specific supported profile IDs。

可保守映射的格式信息分两类：

| Source field | Locally observed values | Conservative interpretation |
| --- | --- | --- |
| `supportedFormats.audioStream` | bits `11,18,22,24` | 按公开 AirPlay 2 audio bitmask，可对应 `PCM/44100/16/2`、`ALAC/44100/16/2`、`AAC-LC/44100/2`、`AAC-ELD/44100/2`。这是 capability bitmask，不是播放时实际选择。 |
| `supportedFormats.lowLatencyAudioStream` | bit `25` | 按公开 bitmask，可对应 `AAC-ELD/48000/2`。 |
| `supportedFormats.bufferStream` | bits `19,21,22,23,33,34,35,39,40,49,50,51,52,53,54,55,56,57,58,60,61,62,63` | bits `19,21,22,23` 可按公开 bitmask解释为 `ALAC/44100/24/2`、`ALAC/48000/24/2`、`AAC-LC/44100/2`、`AAC-LC/48000/2`；bits `33+` 超出 Cozzi 公开表，不能仅凭该表映射。 |
| `supportedAudioFormatsExtended.bufferStream` | IDs `19,21,22,23,33,34,35,39,40,49..58,60..63,65,66,70..75` | 与 capability bitmask 部分重叠，但属于 extended profile ID list；目前不能完整映射为 `(codec, sample format, sample rate, channels)`，只能说两个 members 完全相同。 |

公开 AirPlay 2 音频格式表覆盖 bit `2..32`，因此只能解释低位 bitmask。`supportedAudioFormatsExtended` 中的 `49+` 等 high IDs 很可能表示 Apple/HomePod 扩展 profile，但当前本地 plaintext `SETUP` 未暴露这些 ID 与真实 `audioFormat` 的绑定关系。

本 Mac -> HomePod mini stereo-group path 中最稳妥的 codec inference：

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

`spf=352` 和 44.1 kHz 是本地 pcap 直接事实。`ct=2` 和 `audioFormat=262144` 来自 Cozzi documented `SETUP` example 与 openairplay compression map 的匹配推断，因为本地 control channel 未暴露明文 stream `SETUP`。

## 6. 真实播放抓包事实

### 6.1 Playback-stage capture: `airplay-playback-2026-06-26.pcap`

Capture summary：

| Field | Value |
| --- | --- |
| packets captured | `4082` |
| duration | `13.986829 s` |
| plaintext RTSP markers on TCP 7000 | none |

Main media flows：

| Flow | Packets | Payload bytes | RTP payload type | RTP sequence | RTP timestamp delta | Payload length |
| --- | ---: | ---: | --- | --- | --- | --- |
| `192.168.2.206:51297 -> 192.168.2.117:49761` | 1756 | 1762251 | `97` | `18748..20503`, gaps `0` | `352` for 1755 intervals | `720..1452` |
| `192.168.2.206:62010 -> 192.168.2.197:56052` | 1756 | 1762251 | `97` | `18748..20503`, gaps `0` | `352` for 1755 intervals | `720..1452` |

RTP comparison：

- 两条 RTP-like UDP streams 在全部 1756 对 packet 中逐字节完全相同。
- 两个 streams 拥有相同 12-byte RTP header、相同 encrypted payload 和相同 24-byte trailer。
- `allPacketsByteIdentical=true`。
- `fullPacketSame=1756`。
- paired packets 的最大 observed send-time offset 约 `0.000247 s`。
- stereo role/channel split 在此 capture 的 LAN RTP payload bytes 中不可见。

RTP packet layout：

| Component | Bytes | Observed detail |
| --- | ---: | --- |
| RTP header | 12 | Version `2`, payload type `97`, SSRC `0`, continuous sequence/timestamp. |
| Encrypted payload | `684..1416` | Variable-length encrypted audio payload. |
| Auth tag | 16 | First 16 bytes of the trailing 24 bytes. |
| Nonce | 8 | Last 8 bytes of the trailing 24 bytes. All 1756 nonces are unique. |

First media packet trailer：

```text
trailer24 = cb9b2c5ca63fdfa32d1b3f89384a73d8 ea4b040000000000
tag16     = cb9b2c5ca63fdfa32d1b3f89384a73d8
nonce8    = ea4b040000000000
nonce8 LE = 281578
```

RTP timing inference：

```text
RTP packets: 1756
RTP timestamp step: 352
timestamp span: 617760 frames
617760 / 44100 = 14.008 s
617760 / 48000 = 12.870 s
wall-clock capture span for stream = 13.980 s
```

这强匹配 44.1 kHz audio with `spf=352`。wire 上观测到的 RTP payload type 是 `97`；它不是 AirPlay 2 RTSP `streams[].type` values `96` 或 `103` 的同一命名空间。

PTP/timing flows：

| Flow | Packets | Payload bytes | Notes |
| --- | ---: | ---: | --- |
| `192.168.2.197:319 -> 192.168.2.206:319` | 114 | 5016 | PTP sync messages |
| `192.168.2.206:319 -> 192.168.2.197:319` | 114 | 5016 | PTP delay requests |
| `192.168.2.197:320 -> 192.168.2.206:320` | 257 | 19814 | PTP follow-up, delay response, announce, signalling |

没有任何涉及 `192.168.2.117` 的 PTP packets。该事实支持 `192.168.2.197` 在此 session 中是 timing leader/peer，而 `192.168.2.117` 接收同步媒体但不直接与 Mac 协商 PTP。

PTP identities：

| Flow | Message types | Clock identity | Source port id |
| --- | --- | --- | ---: |
| `192.168.2.197:320 -> 192.168.2.206:320` | `Delay_Resp=115`, `Follow_Up=114`, `Announce=14`, `Signaling=14` | `94ea3246bb640008` | `32777` |
| `192.168.2.197:319 -> 192.168.2.206:319` | `Sync=114` | `94ea3246bb640008` | `32777` |
| `192.168.2.206:319 -> 192.168.2.197:319` | `Delay_Req=114` | `f68cba224c6c0008` | `32770` |

TCP 7000 control：

| Flow | Packets | Payload bytes | Payload pattern |
| --- | ---: | ---: | --- |
| `192.168.2.206:53695 -> 192.168.2.197:7000` | 14 | 602 | 7 client payloads of 86 bytes |
| `192.168.2.197:7000 -> 192.168.2.206:53695` | 14 | 2142 | 7 server payloads of 306 bytes |
| `192.168.2.206:53696 -> 192.168.2.117:7000` | 14 | 602 | 7 client payloads of 86 bytes |
| `192.168.2.117:7000 -> 192.168.2.206:53696` | 14 | 2142 | 7 server payloads of 306 bytes |

TCP 7000 payloads 中未发现 plaintext `RTSP/1.0`、`SETUP`、`GET /info` 或 `bplist00` markers。该 capture 捕获的是 playback-stage encrypted/binary control frames，而不是 initial RTSP setup。

Frame-level TCP 7000 pattern：

| Direction | Flows compared | Frame length sequence | Byte-identical frames | Stable prefix |
| --- | --- | --- | ---: | --- |
| Mac -> HomePod | `192.168.2.206:53696 -> 192.168.2.117:7000` vs `192.168.2.206:53695 -> 192.168.2.197:7000` | seven `86` byte payloads on each flow | `0 / 7` | first two bytes match on all frames: `4400` |
| HomePod -> Mac | `192.168.2.117:7000 -> 192.168.2.206:53696` vs `192.168.2.197:7000 -> 192.168.2.206:53695` | seven `306` byte payloads on each flow | `0 / 7` | first two bytes match on all frames: `2001` |

TCP 7000 控制帧在两个成员之间长度序列相同、前两个字节 prefix pattern 相同，但 payload 不逐字节相同；这与 RTP media stream 的双成员逐字节相同形成对比。

### 6.2 Confirmed route-selection capture: `airplay-route-selection-confirmed-2026-06-28.pcap`

Capture summary：

| Field | Value |
| --- | --- |
| packets captured | `2527` |
| duration | `36.672354 s` |
| TCP 7000 plaintext markers | `RTSP/1.0=20`, `GET /info=7`, `bplist00=7`, `SETUP=0` |

Main media flows：

| Flow | Packets | Payload bytes | RTP payload type | RTP sequence | RTP timestamp delta | Best sample rate |
| --- | ---: | ---: | --- | --- | --- | ---: |
| `192.168.2.206:54384 -> 192.168.2.197:50622` | 375 | 476686 | `97` | `45578..45952`, gaps `0` | `352` for 374 intervals | `44100` |
| `192.168.2.206:59793 -> 192.168.2.117:50963` | 375 | 476686 | `97` | `45578..45952`, gaps `0` | `352` for 374 intervals | `44100` |

RTP comparison：

- `allPacketsByteIdentical=true` for all 375 paired media packets。
- 第一个 RTP-like packet 具有 24-byte trailer，可拆为 16-byte tag 和 8-byte nonce。
- first nonce 为 `0000000000000000`。
- stream 内 nonces unique。

TCP 7000 / plist result：

| Evidence | Result |
| --- | --- |
| `GET /info` | Present; binary plist bodies extracted and decoded for both HomePods. |
| Stream `SETUP` plaintext | Not present: `SETUP=0` in reassembled TCP 7000 streams. |
| Extracted `streams[]` plist | Not present. Decoded plist summary contains `/info` capability plists only. |
| Control channel after route selection | Binary/high-entropy payloads without parseable RTSP method names for stream setup. |

该 pcap 是最强本地 route-selection 证据：即使 capture 从切换到 `卧室` 之前开始，macOS 在此路径上也没有以 plaintext 暴露 stream `SETUP`。因此 field-level `ct/audioFormat/type/spf` 模型来自 open-source AirPlay 2 receiver 文档和代码；`spf=352` 与 44.1 kHz 来自本地 RTP timestamp 事实。

### 6.3 Cross-capture stability

现有本地 captures 的稳定项：

| Capture | Media RTP payload type | RTP timestamp step | Best sample rate | PTP peer observed |
| --- | --- | --- | --- | --- |
| `airplay-playback-2026-06-26.pcap` | `97` | `352` | `44100` | `192.168.2.197` |
| `airplay-confirmed-output-2026-06-28.pcap` | `97` | `352` | `44100` | `192.168.2.197` |
| `airplay-route-selection-confirmed-2026-06-28.pcap` | `97` | `352` | `44100` | `192.168.2.197` |

因此，在已观察的本地 stereo group 配置和 `say`/system-output playback 路径中，wire RTP payload type `97`、timestamp step `352`、44.1 kHz 和 `192.168.2.197` timing peer 都是稳定事实。该结论仍不外推到 Apple Music buffered path、视频 AirPlay path 或 reboot/左右角色重新配置后的所有状态。

## 7. 本地证据与开源模型边界

本地证据已确认：

- macOS 在 route selection 和 playback 期间向两个 HomePod members 打开 TCP 7000 control sessions。
- 两个 members 的 `/info` binary plists 已解码并比较。
- 两个 members 广告相同 stream-format capability surface。
- confirmed HomePod-output captures 包含两条 direct UDP RTP-like media streams，源为 Mac，目的分别为两个 members。
- 两条 media streams 在所有 captured packets 中逐字节相同，包括 RTP header、encrypted payload 和 24-byte trailer。
- RTP payload type 是 `97`。
- RTP sequence numbers 连续。
- RTP timestamps 每 packet 递增 `352`。
- RTP timing 推断为 44.1 kHz、每包 352 sample frames。
- PTP timing traffic 使用 UDP `319/320`，并只出现在 Mac 与 `192.168.2.197` 之间；captures 中未出现与 `192.168.2.117` 的 PTP exchange。
- TCP 7000 stream reassembly 找到 `/info` RTSP/plist bodies，但在 confirmed route-selection path 中未找到 plaintext stream `SETUP`。

开源模型支持：

- `SETUP streams[].ct` map：`1=PCM`、`2=ALAC`、`4=AAC-LC`、`8=AAC-ELD`；Cozzi 还在 audio format table 中记录 OPUS。
- Cozzi realtime audio `SETUP` example 使用 `type=96`、`ct=2`、`audioFormat=262144`、`spf=352`、`latencyMin=11025` 和 `latencyMax=88200`。
- `audioFormat=262144` 是 `0x40000`，匹配 Cozzi table entry `ALAC/44100/16/2`。
- Shairport Sync AirPlay 2 notes 列出 working macOS/HomePod-class combinations，包括 `ALAC/S16/44100/2` realtime audio 和 AAC/ALAC buffered variants。

明确边界：

- 本地 HomePod path 没有在这些 pcap 中以 plaintext 形式暴露 stream `SETUP`。
- `spf=352` 和 44.1 kHz 是本地事实。
- `ct=2`、`streams[].type=96` 和 `audioFormat=262144` 是 open-source-matched inference。
- wire RTP payload type `97` 不应与 RTSP `streams[].type` 混为同一字段。
- `supportedAudioFormatsExtended.bufferStream` 的 numeric IDs 不应直接解释为 `ct`。



## 8. 最终技术结论

HomePod mini 立体声组在 LAN 上表现为两个 AirPlay/RAOP receivers，它们共享 group identifiers，但拥有独立的 receiver identity 和 role/status fields。两个 members 的 codec/format capability surface 相同；目前没有证据表明两个成员在支持的媒体格式上存在不对称。`featuresEx` 中的 `StBL` / `StBr` 已被本地左右声道测试确认为物理 left/right：`192.168.2.197` 是 left，`192.168.2.117` 是 right。

真实播放与 confirmed route-selection pcap 均表明，macOS 向两个 HomePod members 直接发送两条 UDP RTP-like media streams。两条 streams 在 packet 级别逐字节完全相同，使用 wire RTP payload type `97`，sequence 连续，timestamp 每包递增 `352`，与 44.1 kHz、352 sample frames per packet 匹配。LAN 上看不到左右声道在 RTP payload bytes 中分离为不同 payload。

PTP timing 在已观察 sessions 中只发生于 Mac 与 `192.168.2.197`，因此 `192.168.2.197` 是当前配置下稳定的 observed timing peer/leader。`192.168.2.117` 同步接收媒体，但未直接出现在 PTP exchange 中。

confirmed route-selection pcap 捕获到了 `/info`、PTP、binary/encrypted TCP 7000 control 和 RTP media，但没有 plaintext stream `SETUP`。因此本文将本地 packet observations 与 open-source SETUP semantics 分开处理：本地事实证明 `spf=352` 和 44.1 kHz；公开 receiver code 和文档支持最可能的 realtime model 为 `streams[].type ~= 96`、`ct ~= 2` / ALAC、`audioFormat ~= 262144` / `ALAC/44100/16/2`。
