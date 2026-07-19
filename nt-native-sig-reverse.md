# 撕开 28 字节动态短签名

> 脱敏说明：业务名、库名、字段名、样本名、脚本名全部替换过。保留的是真实地址、真实汇编片段、真实追踪顺序和真实踩坑经过。

---

移动端的"签名算法"，大多数时候拆开看就是几段材料拼一起再过个哈希，没什么花头。

这次碰到的不是这路数。

28 个字节，三段式结构。前 12 字节把每次调用做成动态的；中间 12 字节里有 1 字节结构约束，剩下 11 字节把请求体材料重新做了一次投影；最后 4 字节再收一次口。

真正恶心的地方不在数学——它把材料层、结果层、旁路线程、VM 调度层、尾部封装层拆散了摆在不同位置。追踪顺序错一步，就会把热函数认成核心函数，把材料哈希认成最终签名，把最后一个 blob 认成整个算法。

能把它拆干净，不是因为一开始就认出了算法名。是因为我先把它当成一条**结果发布链**来追，然后倒着把中间态一段段钉死。

---

## 起手：不猜算法，先找热区

第一天没急着啃大函数，也没沉迷伪代码。

先做的事很土：把样本喂给本地脚本，看哪几个地址反复出现在同一批 28B 输出附近。

手里常用的东西就这些：IDA 双库（`bak` 看原始 asm，`main` 辅助阅读）、KSU 侧硬件断点采样、Frida 轻量对照日志、angr deflat、一堆临时 Python 脚本。

```bash
python scripts/aggregate_runtime_samples.py samples/run_a.jsonl samples/run_b.jsonl
python scripts/runtime_flow_splitter.py --auto ksusamples/trace_a.jsonl
python scripts/profiled_deflat.py --func C6060
```

第一轮聚合出来的热点地址很稳定：

```
0xC6060
0xC7E60
0xD1A20
0xC87E8
0xC9F30
```

这里有个关键判断——这 5 个点只能当阶段锚点用，不能直接当线性调用图看。热点高不代表它就是核心，只代表它值得当路标。

在 `bak` 里把角色初步拆开：

```
0xC6060  入口包装器 / 主状态机
  -> 0xC7E60  材料门控与打包
  -> 0xC87E8  结果预提交段
       -> 0xD1A20  旁路异步投递
       -> 0xC8E28  extra 构造器
            -> 0xC9F30  extra 尾门
```

这一步最有价值的收获不是找到了答案，是把后面会反复踩的坑先隔离了：热点函数不等于核心算法，离输出近不等于负责生成输出，线程行为明显不等于一定在算东西。

---

## 第一刀：砍在结果发布点

最容易被误导的地址是 `0xD1A20`。

它很热，分线程，会分配对象，还贴着结果阶段出现。在逆向现场这几乎就是"很像核心"的全部表征了。

但把它和 `0xC87E8` 的 holder 写回段摆到同一屏 asm 上之后，结论立刻反过来了。

真正贴着结果对象写的这段：

```asm
0xC8D8C  X10 = [X19 + 0x80]
0xC8D90  Q0  = [X19 + 0x390 .. +0x39F]
0xC8D9C  [X10 + 0x00 .. +0x0F] <- Q0
0xC8DA8  X8  = [X19 + 0x3A0]
0xC8DB0  [X10 + 0x10] <- X8
```

业务意义很直接：`X19` 是本地状态大对象，`[X19 + 0x80]` 是结果 holder 指针，`[X19 + 0x390 .. +0x3A0]` 是已经准备好的结果块。发布动作就在这里。

而我一度误判成核心的那段：

```asm
0xC8A48  X20 = sub_D18D8()
0xC8A5C  sub_800FC(X19 + 0x3A8, [X19 + 0x228])
0xC8A64  BL  0xD1A20
```

`0xD1A20` 是在 `0xC87E8` 阶段里被旁路调起来的。它不是先于结果组装独立存在的一条主算法链。

把这个地址的别名从 "state writer" 划掉，改成 `async_dispatch_queue`。这次勘误直接少走了很多弯路——只要结果发布点没钉住，前面看到的任何 MD5、任何 blob、任何字符串槽，都可能只是材料中转站。

---

## 入口那组 MD5：很重要，但它只是材料

结果发布点稳住以后，下一刀去钉入口包装器里的那组 MD5。不是因为觉得它就是最终签名——恰恰相反，是想尽快证明它不是。

`0xC6060` 里有一段很硬的 MD5 证据：

```asm
0xC64BC..0xC64D8  取输入串和长度
0xC64D8           BL 0x4F7EEC   // update
0xC64E4           BL 0x4F819C   // final
```

结果搬到 `[X19 + 0x6D0]` → `[X19 + 0x90]` → 再通过虚表方法挂进对象体系。

把这组小核单独抽出来自测：

```bash
python scripts/primitives_selftest.py selftest
```

标准向量全部通过。身份确认：

```
body_hash = MD5([0x12, 0x1c] + client_tag + body)
```

它和请求体强绑定，后面会被中段原语消费，但它不是最终 28B 的直接字节拷贝。先把成熟原语打实，后面很多看似复杂的缓冲区都会自动降级成普通中间态。

---

## 真正卡住我的坑：时钟 hook 简化过头了

这条链让我实打实卡过一次的，不是轮函数，是前缀的动态化来源。

早期做过一个很典型的偷懒操作：`hookRet(clock_gettime, 0)`。以为把返回值改成 0 就够了。结果样本一批批对不上，前缀行为始终飘。

后来翻日志才发现，VM 分支实际读的不是返回码，而是 `timespec` 结构体本身。只改 `x0 = 0` 没用，还得把 `tv_sec / tv_nsec` 真写回去，不然 VM 读到的是栈上未初始化的旧值。

补完这个坑以后前缀链才稳定下来。两颗相关地址也坐实了：

```
0x538A44  prefix_seed_builder
0x18517C  mt_extract_u32
```

顺便打掉了一个误判——前 12 字节不是"一个随机数重复三次"的死板结构。实际情况是：前 8 字节直接贴着 MT19937 输出走，第 3 个 32 位字是后续分支写回的，前 12 字节整体还会继续参与中段状态布置。

所以前缀不只是个"动态头"，它本身就是中段原语的种子面板。

---

## VM 主路的突破口：不是返回值，是 side effect

中段 VM 那一坨东西，如果只盯 `X0 return`，越看越乱。

真正把主路缩出来，是因为后来不看 return 了，改盯 **caller 栈上的 `src / src+4`**。

这段 asm 是决定性的：

```asm
53D4C8  STR WZR, [SP,#src]
53D4D8  STP Q0, Q0, [SP,#src+4]
53D594  ADD X12, SP, #src
53D598  ADD X13, SP, #src+4
53D5C4  BL  sub_53D8D0
53D5C8  LDR W20, [SP,#src]
53D60C  ADD X1, SP, #src+4
53D618  BL  memcpy
```

说明很硬：真正被后续消费的不是某个"神秘返回值"，而是 VM 写回到 caller 栈上的 `src`（长度）和 `src+4`（数据）。

思路从这里收敛：

```
0x53D124 -> 0x53D49C -> 0x53907C
```

在 IDA 里反复补的就是 `analyze_function(0x53907C)` 和 `xrefs_to(0x53D8D0)`，加上那份带 profile 的 deflat 脚本：

```python
"C6060": TargetProfile(
    key="C6060",
    addr=0xC6060,
    size=46488,
    dispatchers=(0xC9B44, 0xC9D5C),
    max_steps=2000,
)
```

这类很丑的临时脚本，在真实逆向现场比优雅架构有用得多。它能快速回答一个现实问题：这条路到底该继续往哪颗地址压。

---

## 三个 blob 不是平级关系

另一个大误判：一度把 `552` 当成"整个 28B 算法的答案"。原因很朴素——它离最终输出最近，扩散感也最强，很像最后的大杀器。

后来把嵌套调用顺序和日志对齐：

```
BLOB_ENTER 1712
CALL_53D8D0 blob=1712
BLOB_ENTER 1020
CALL_53D8D0 blob=1020
BLOB_ENTER 552
... tail materialize ...
```

顺序一出来角色就清楚了：`1712` 更像状态初始化和工作区预填充；`1020` 负责把 body 相关材料打进中段字节；`552` 负责尾部 4 字节收口。

最大的收获是终于敢把一句旧话划掉——"最后一个 blob 就是整个算法"。不是这样的。最后一个 blob 只是最靠近尾部，不代表它吞掉了全部上游语义。

---

## tail 这 4 字节：从结果侧硬反追出来的

尾部 4 字节之前也猜过。Murmur 风格 finalizer？Jenkins 风格混合？某种自定义 32 位 avalanche？都不对。

真正打穿它，是先从 `sign[0:24]` 反推，追到了 `1020` 那次 hash 调用和后面的 8 字节私有缓冲区。

日志里最值钱的几行：

```
CALL_5780A4 blob=1020 lr=0x578548 x0=0xe4ff2984 x1=28 x2=0x0
call_buf = d4cc7a3d || sign[0:24]

CALL_53D8D0 blob=1020
  x4 = hash32
  x5 = 0xe4ffeab8
  x6 = sign[8:12]
  x7 = aux
```

batch 对账给了更硬的结论：

```
hash1020_ret == internal8[4:8]        20/20
hash1020_input28 == d4cc7a3d || sign[0:24]   20/20
```

尾部链收成：

```
hash32    = XXH32(d4cc7a3d || sign[0:24], seed=0)
internal8 = bea61057 || LE32(hash32)
tail4     = XXH32(internal8, seed=0x279537A4)
```

这里最容易骗到人的是 `internal8`。如果只盯最终 sign buffer 很容易把它误认成 `sign[0:8]`，实际上不是——它是 tail 自己的私有中间态。正因为这一层被藏起来了，尾部看起来才像完全没规律。

---

## 样本怎么帮我排除"恰好撞上"

我一直不信"单样本刚好对上"这种胜利。每拿到一个说法，立刻找样本批量压一遍。

几条脱敏后的 28B 结果（命令名换成别名，只保留长度和输出结构）：

```
[case-A] payload_len=33  seq4=0000b48b
sign = 34cb772fbb104ebf0101b9f63405651366399eb05937144f48a2c9fb
check: sign[0] = 0x34, sign[12] = 0x34

[case-B] payload_len=47  seq4=0000b490
sign = ef1c4450a6535050f5861409ef2dfa6f2893ae2be902ce40869ab320
check: sign[0] = 0xef, sign[12] = 0xef

[case-C] payload_len=9   seq4=0000b492
sign = a9c4854362eed06135c37ca2a9ac6e0d13dec71216193f197fb19348
check: sign[0] = 0xa9, sign[12] = 0xa9

[case-D] payload_len=26  seq4=0000b49c
sign = 6b9279c546bbf04857d02d036b3b5c1ba75452d7a0879a507fe889e5
check: sign[0] = 0x6b, sign[12] = 0x6b
```

这批样本帮我钉住了几件事：

1. `sign[12] == sign[0]` 是稳定结构约束，最后压到 344/344 全部一致
2. 改 `seq4` 不影响那 12 字节 MAC 区——快速排掉"序号参与签名"的错误假设
3. 改 body 或版本串，中后段会跟着变——中段确实绑定请求材料
4. 另一条 96B 分支不满足这个约束——所以不能误写成"所有签名都这样"

这一步逼着我把"看起来像规律"变成"批量可回归的规律"。结构约束、差分行为、批量一致性，这三件事比单次命中更能说明问题。

---

## 我实际在跑的那些脏工具

不打算堆最终实现代码。比起一次性贴满，更想把真正起作用的工具和切片方法说清楚。

**热点聚合器**——把多份运行时样本吃进去，算哪些地址总和 28B 结果同时出现：

```python
def resolve_input_files(inputs, prefer_wrapper):
    resolved = []
    for raw in inputs:
        path = Path(raw)
        if path.is_file():
            resolved.append(path)
            continue
        if path.is_dir() and (path / "runtime.events.jsonl").exists():
            resolved.append(path / "runtime.events.jsonl")
    return resolved
```

**流程切片器**——按入口断点把一次完整调用切出来，再看内部 hit 序列：

```python
if hook_name == "sig_entry_flat" and current_flow:
    flows.append(current_flow)
    current_flow = [obj]
else:
    current_flow.append(obj)
```

**profile 化 deflat**——给几个关键函数单独建档，快速知道改动是不是跑偏了：

```python
"C6060": TargetProfile(
    key="C6060",
    addr=0xC6060,
    size=46488,
    dispatchers=(0xC9B44, 0xC9D5C),
    max_steps=2000,
)
```

**小核自测**——每拆出一个基础原语，第一件事不是继续猜，而是立刻写自测跑标准向量。

这套工作流没什么惊艳的地方，但它能持续收敛：热点聚合 → 切调用片段 → 钉结果发布点 → 单独验证小核 → 再回到 VM 主路。最有用的往往不是最漂亮的脚本，而是最能缩小搜索空间的那个。

---

## 收成公式

到能落字的这一步，下面这组链已经被多层证据反复压过了：

```
输入:
  body, client_tag, random_u32, epoch_seconds

流程:
  1. seed = random_u32 ^ epoch_ms_low32
  2. MT19937(seed) -> 3 个 32-bit word
  3. 每个 word 再 XOR seed，得到 prefix12
  4. body_hash = MD5([0x12,0x1C] + client_tag + body)
  5. prefix12 -> state16
  6. state16 -> 自定义 4 轮 Salsa-like core -> cks19
  7. sign[12] = sign[0]
  8. sign[13:16] = cks19[0:3] XOR [1A,0B,00]
  9. body_side = [1A,0B,00] + body_hash
 10. cipher_stream = body_side XOR cks19
 11. sign[16:24] = cipher_stream[[4,5,6,8,11,16,9,7]]
 12. sign[24:28] = XXH32(bea61057 || LE32(XXH32(d4cc7a3d || sign24, 0)), 0x279537A4)
```

压成结构图：

```
random_u32 + epoch_ms
        │
        ▼
   seed / w21
        │
        ▼
    MT19937 x3
        │
        ▼
     prefix12 ───────────────┐
        │                    │
        ▼                    │
      state16                │
        │                    │
        ▼                    │
      cks19                  │
        │                    │
        ├──> sign[13:16]     │
        │                    │
body -> MD5 -> body_hash ----┘
        │
        ▼
  body_side XOR cks19
        │
        ▼
   sign[16:24]
        │
        ▼
   XXH32 -> XXH32
        │
        ▼
   sign[24:28]
```

这 28 字节不是某个 hash 一把算出来的，是一条分层发布链。真正的复杂度不在最终导出点，而在前缀动态化和中段那个 `state16 -> cks19` 的变换。

---

## 验证：三层交叉，不靠单点成功

这类文章最容易犯的错，是把"能写出一份像样的 Python"当成"逆向完成"。

我对这条链的验证拆成三层：

**静态层**——把每个原语单独坐实。MD5 四个函数用标准常量和 padding 确认；MT19937 用 state 大小、twist、tempering 确认；自定义 core 用 state 布局和汇编级更新顺序确认；XXH32 用 prime 常量和小输入路径确认。

**动态层**——追运行时写入。追最终发布点确认 28B 写入时序；追中段缓冲确认 `body_side XOR cks19`；追 tail 内部 8 字节确认它不是 `sign[0:8]`；追逐字节写入确认 `internal8 = bea61057 || LE32(hash1020)`。

**批量层**——最终站住的结果：

- `body_hash` 公式批量一致
- `state16 -> cks19` 对齐通过
- `sign[13:16]` 与 `sign[16:24]` 批量一致
- `tail` 的 XXH32 路径批量一致

验证的对象不是"最终 28 字节恰好对上一组"，而是每一段中间态、每一段变换、每一段拼装都能各自对上。单样本成功最多叫线索，不叫闭环。

---

## 我明确撤回过的判断

真实逆向不是一路直线，更像不断撤回错误标签。这次明确撤回过的几条：

1. **`0xD1A20` 是核心 state writer** → 撤回。它是 `async_dispatch_queue`。
2. **入口那组 MD5 就是最终 28B** → 撤回。它只是材料层 digest。
3. **最后一个 `552` blob 就是全部算法** → 撤回。它只是尾部收口层。
4. **只看 `X0 return` 就能知道 VM 产物** → 撤回。真正该盯的是 `src / src+4` side effect。
5. **只 hook `clock_gettime` 返回值就够了** → 撤回。必须连 `timespec` 内容一起写回。

被撤回的判断不是失败记录，是路线收敛记录。

---

## 结语

这次 28B 签名最让我有感触的不是哪颗常量也不是哪轮 XOR，而是一个事实：

一个真实可过检的逆向过程，往往不是从"认出算法名"开始，而是从"先把结果发布点找准"开始。然后一点点往回走：结果发布点 → 材料层 → 动态前缀 → 中段原语 → 尾部私有中间态。

只有每一段都能找到真实地址、拿出真实 asm、对上真实样本、跑过批量回归，这条"动态短签名"才会从一个看起来很玄的黑盒，退化成一条清晰、可复现、可验证的数据流。

能把黑盒撕开的从来不是"知道很多算法名"，是能把数据流一段段钉死。

---

## 参考实现（脱敏）

```python
import hashlib
import struct

BODY_HASH_PREFIX = b"\x12\x1c"
BODY_TAG_PREFIX = b"\x1a\x0b\x00"
CKS_INDEX = (4, 5, 6, 8, 11, 16, 9, 7)
HASH1020_PREFIX = bytes.fromhex("d4cc7a3d")
HASH552_HEAD = bytes.fromhex("bea61057")
HASH552_SEED = 0x279537A4

MT_N = 624
MT_M = 397
MT_A = 0x9908B0DF
MT_F = 1812433253


def _u32(x):
    return x & 0xFFFFFFFF


def _rotl32(x, r):
    return _u32((x << r) | (x >> (32 - r)))


def _xxh32_round(acc, lane):
    p1, p2 = 0x9E3779B1, 0x85EBCA77
    return _u32(_rotl32(_u32(acc + _u32(lane * p2)), 13) * p1)


def _xxh32_avalanche(h):
    h = _u32(h ^ (h >> 15))
    h = _u32(h * 0x85EBCA77)
    h = _u32(h ^ (h >> 13))
    h = _u32(h * 0xC2B2AE3D)
    h = _u32(h ^ (h >> 16))
    return h


def xxhash32(data: bytes, seed: int = 0) -> int:
    p1, p2, p3, p4, p5 = (
        0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1,
    )
    i, n = 0, len(data)
    if n >= 16:
        v1 = _u32(seed + p1 + p2)
        v2 = _u32(seed + p2)
        v3 = _u32(seed)
        v4 = _u32(seed - p1)
        while i + 16 <= n:
            v1 = _xxh32_round(v1, struct.unpack_from("<I", data, i)[0])
            v2 = _xxh32_round(v2, struct.unpack_from("<I", data, i + 4)[0])
            v3 = _xxh32_round(v3, struct.unpack_from("<I", data, i + 8)[0])
            v4 = _xxh32_round(v4, struct.unpack_from("<I", data, i + 12)[0])
            i += 16
        h = _u32(
            _rotl32(v1, 1) + _rotl32(v2, 7)
            + _rotl32(v3, 12) + _rotl32(v4, 18)
        )
    else:
        h = _u32(seed + p5)
    h = _u32(h + n)
    while i + 4 <= n:
        lane = struct.unpack_from("<I", data, i)[0]
        h = _u32(_rotl32(_u32(h + _u32(lane * p3)), 17) * p4)
        i += 4
    while i < n:
        h = _u32(_rotl32(_u32(h + _u32(data[i] * p5)), 11) * p1)
        i += 1
    return _xxh32_avalanche(h)


def compute_body_hash(body: bytes, client_tag: str) -> bytes:
    return hashlib.md5(BODY_HASH_PREFIX + client_tag.encode("ascii") + body).digest()


class MT19937:
    def __init__(self, seed: int = 0):
        self.mt = [0] * MT_N
        self.idx = MT_N + 1
        self.seed(seed)

    def seed(self, s: int):
        self.mt[0] = _u32(s)
        for i in range(1, MT_N):
            self.mt[i] = _u32(MT_F * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i)
        self.idx = MT_N

    def _twist(self):
        for i in range(MT_N):
            y = (self.mt[i] & 0x80000000) | (self.mt[(i + 1) % MT_N] & 0x7FFFFFFF)
            self.mt[i] = self.mt[(i + MT_M) % MT_N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= MT_A
        self.idx = 0

    def next_u32(self) -> int:
        if self.idx >= MT_N:
            self._twist()
        y = self.mt[self.idx]
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        self.idx += 1
        return _u32(y)


def generate_prefix12(random_u32: int, epoch_sec: int) -> bytes:
    epoch_ms = _u32(epoch_sec * 1000)
    seed = _u32(random_u32 ^ epoch_ms)
    mt = MT19937(seed)
    w0 = _u32(mt.next_u32() ^ seed)
    w1 = _u32(mt.next_u32() ^ seed)
    w2 = _u32(mt.next_u32() ^ seed)
    return struct.pack("<III", w0, w1, w2)


def build_state_words_from_prefix12(prefix12: bytes) -> list:
    seed8 = prefix12[:8]

    def le32(chunk: bytes) -> int:
        return struct.unpack("<I", chunk)[0]

    return [
        0xC6096C57,
        le32(seed8[3:7]),
        le32(seed8[4:8]),
        le32(seed8[1:5]),
        le32(seed8[2:6]),
        0x37A6C743,
        le32(prefix12[8:12]),
        0x6CA444EF,
        0, 0,
        0x694CE16A,
        le32(seed8[0:4]),
        le32(seed8[4:8]),
        le32(seed8[3:7]),
        le32(seed8[2:6]),
        0xAF511CA1,
    ]


def _cks1020_one_loop(state_words: list) -> list:
    sp = [_u32(w) for w in state_words]

    w12, w15 = sp[0], sp[1]
    w13, w11 = sp[2], sp[3]
    w2, w3 = sp[4], sp[5]
    w14, w16 = sp[6], sp[7]
    w5, w17 = sp[8], sp[9]
    w4, w7 = sp[10], sp[11]
    w6, w19 = sp[12], sp[13]
    w20, w21 = sp[14], sp[15]

    w13 ^= _rotl32(_u32(w12 + w11), 7)
    w3 ^= _rotl32(_u32(w16 + w14), 7)
    w5 ^= _rotl32(_u32(w4 + w17), 7)
    w21 ^= _rotl32(_u32(w19 + w6), 7)

    w15 ^= _rotl32(_u32(w13 + w11), 9)
    w2 ^= _rotl32(_u32(w3 + w14), 9)
    w7 ^= _rotl32(_u32(w5 + w17), 9)
    w20 ^= _rotl32(_u32(w21 + w6), 9)

    w12 ^= _rotl32(_u32(w15 + w13), 13)
    w16 ^= _rotl32(_u32(w2 + w3), 13)
    w4 ^= _rotl32(_u32(w7 + w5), 13)
    w19 ^= _rotl32(_u32(w20 + w21), 13)

    w11 ^= _rotl32(_u32(w12 + w15), 18)
    w14 ^= _rotl32(_u32(w16 + w2), 18)
    w17 ^= _rotl32(_u32(w4 + w7), 18)
    w6 ^= _rotl32(_u32(w19 + w20), 18)

    w16 ^= _rotl32(_u32(w21 + w11), 7)
    w4 ^= _rotl32(_u32(w14 + w13), 7)
    w19 ^= _rotl32(_u32(w17 + w3), 7)
    w12 ^= _rotl32(_u32(w6 + w5), 7)

    w7 ^= _rotl32(_u32(w16 + w11), 9)
    w20 ^= _rotl32(_u32(w4 + w14), 9)
    w15 ^= _rotl32(_u32(w19 + w17), 9)
    w2 ^= _rotl32(_u32(w12 + w6), 9)

    tmp4 = _u32(w20 + w4)
    tmp23 = _u32(w7 + w16)
    w13 ^= _rotl32(tmp4, 13)

    tmp4b = _u32(w15 + w19)
    tmp12 = _u32(w2 + w12)
    w21 ^= _rotl32(tmp23, 13)
    w3 ^= _rotl32(tmp4b, 13)
    w5 ^= _rotl32(tmp12, 13)

    w14 ^= _rotl32(_u32(w13 + w20), 18)
    w11 ^= _rotl32(_u32(w21 + w7), 18)
    w17 ^= _rotl32(_u32(w3 + w15), 18)
    w6 ^= _rotl32(_u32(w5 + w2), 18)

    return [
        w12, w15, w13, w11,
        w2, w3, w14, w16,
        w5, w17, w4, w7,
        w6, w19, w20, w21,
    ]


def compute_cks19(state_words: list) -> bytes:
    original = [_u32(w) for w in state_words]
    post = list(original)
    for _ in range(4):
        post = _cks1020_one_loop(post)
    scratch = [_u32(post[i] + original[i]) for i in range(16)]
    buf = b"".join(struct.pack("<I", w) for w in scratch)
    return buf[:19]


def compute_sign28_tail(sign24: bytes) -> bytes:
    h1020 = xxhash32(HASH1020_PREFIX + sign24, seed=0)
    internal8 = HASH552_HEAD + struct.pack("<I", h1020)
    return struct.pack("<I", xxhash32(internal8, seed=HASH552_SEED))


def build_sign28(prefix12: bytes, body: bytes, client_tag: str) -> bytes:
    body_hash = compute_body_hash(body, client_tag)
    sign_12 = prefix12[:1]

    state = build_state_words_from_prefix12(prefix12)
    cks19 = compute_cks19(state)

    sign_13_16 = bytes(cks19[i] ^ BODY_TAG_PREFIX[i] for i in range(3))
    body_side = BODY_TAG_PREFIX + body_hash
    cipher_stream = bytes(body_side[i] ^ cks19[i] for i in range(19))
    mac = bytes(cipher_stream[idx] for idx in CKS_INDEX)

    sign24 = prefix12 + sign_12 + sign_13_16 + mac
    tail = compute_sign28_tail(sign24)
    return sign24 + tail
```

调用入口：

```python
prefix12 = generate_prefix12(random_u32, epoch_sec)
sign28 = build_sign28(prefix12, body, client_tag)
```

---

## 附录：地址对照表

| 地址 | 别名 | 角色 |
|---|---|---|
| `0xC6060` | `sig_entry_wrapper` | 入口包装器 / 主状态机 |
| `0xC7E60` | `material_gate_pack` | 材料门控与装箱 |
| `0xC87E8` | `result_precommit` | 结果预提交，贴着 holder 写回 |
| `0xC8E28` | `extra_blob_builder` | 扩展字段构造器 |
| `0xC9F30` | `extra_tail_gate` | 扩展字段尾门 |
| `0xD1A20` | `async_dispatch_queue` | 旁路异步投递 |
| `0x4F7468` | `md5_init` | MD5 初始化 |
| `0x4F7EEC` | `md5_update` | MD5 update |
| `0x4F819C` | `md5_final` | MD5 final |
| `0x4F747C` | `md5_transform` | MD5 transform |
| `0x538A44` | `prefix_seed_builder` | 前缀 seed 构造 |
| `0x18517C` | `mt_extract_u32` | MT19937 取数 |
| `0x52AB84` | `mode_classifier` | 模式分类器 |
| `0x53D124` | `route_wrapper` | 路由包装层 |
| `0x53D49C` | `local_b_resolver` | 主走分支本地解析器 |
| `0x53907C` | `nested_helper_body` | 下一层 helper 主体 |
| `0x53D8D0` | `vm_call_wrapper` | VM 调用包装器 |
| `0x546AE4` | `vm_main_entry` | VM 主入口 |
| `0x5780A4` | `hash32_stage` | sign[0:24] 的 hash32 阶段 |
| `0x572F70` | `tail_inner_materializer` | tail 内层字节物化 |

---

*一切开发皆在学习，请勿用于非法用途。*
