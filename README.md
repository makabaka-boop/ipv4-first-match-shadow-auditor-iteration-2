# fw-audit — 首匹配防火墙规则审计器

按规则**次序首匹配**的 IPv4 allow/deny 策略审计器。防火墙里后面的 CIDR 可能只剩
一小段有效地址，甚至被前面的规则完全遮蔽；抽查几个 IP 无法证明覆盖范围，因此本工具
对每条规则给出**精确**的覆盖地址数和状态，并对每对相邻规则计算**交换次序后决策改变
的地址数**——全程不枚举 2³² 个地址，而是把地址集表示为排序、不相交的闭区间列表
（`src/intervals.ts`）。

## 功能

- 输入 1～300 条按序规则：唯一 `id`、`action`（`allow`/`deny`）、规范 IPv4 CIDR。
- 至多 100 个查询地址；未命中任何规则时默认 **deny**。
- 严格校验并拒绝：
  - 非规范网络地址（主机位非零，如 `10.0.0.1/24`）；
  - 越界八位组（如 `256.0.0.1`、前导零 `010.0.0.0/8`）；
  - 重复或缺失的 `id`；
  - 未知字段（根对象与规则对象两级）、未知 `action`、前缀越界（`/33`）。
- 每条规则输出：
  - `exposedAddresses`：未被先前规则覆盖（即真正由该规则决策）的地址数；
  - `witness`：最小见证 IP（`shadowed` 时为 `null`）；
  - `status`：
    - `active` — 整条 CIDR 都仍有效；
    - `partial` — 只剩部分地址有效；
    - `shadowed` — 完全被先前规则遮蔽；
  - `shadowed` 规则额外包含 `coverageCertificate`：用最少数目前规则构成的
    覆盖证书；`ruleIds` 是所选规则 ID，`steps` 给出每一步新覆盖的闭区间，
    所有区间并集恰好等于被遮蔽的目标 CIDR；`active`/`partial` 不包含该字段。
- 每对相邻规则输出交换次序后 `changedAddresses` 与最小见证：
  - 只有两条规则 CIDR 交集内、且未被更早规则覆盖的地址可能变化；
  - 两规则动作相同（同为 allow 或同为 deny）时变化数恒为 0。
- 查询结果列出**命中的首条规则**（id、index、action），未命中为默认 deny。

## 输入格式

```json
{
  "rules": [
    { "id": "web", "action": "allow", "cidr": "10.0.0.0/24" },
    { "id": "block", "action": "deny", "cidr": "10.0.0.128/25" },
    { "id": "catch-all", "action": "deny", "cidr": "0.0.0.0/0" }
  ],
  "queries": ["10.0.0.5", "8.8.8.8"]
}
```

`queries` 可省略。示例见 [`examples/policy.json`](examples/policy.json)。

## CLI

```bash
npm install
npm run build

node dist/cli.js examples/policy.json      # 从文件读
cat policy.json | node dist/cli.js         # 或从 stdin 读
```

输出审计报告 JSON；输入非法时以退出码 `1` 退出，并在 stderr 给出带 JSON 路径的
错误（如 `$.rules[3].cidr: non-canonical CIDR (host bits set)`）。

## HTTP policy 服务（Docker Compose）

```bash
docker compose up --build
```

- `GET /healthz` — 健康检查；
- `POST /audit` — 请求体与 CLI 的 JSON 输入相同，响应体与 CLI 输出相同；
  校验失败返回 `400`。

本地直接运行：`npm run build && PORT=3000 node dist/server.js`。

```bash
curl -s -X POST http://localhost:3000/audit \
  -H 'content-type: application/json' \
  -d '{"rules":[{"id":"a","action":"allow","cidr":"10.0.0.0/30"},{"id":"b","action":"deny","cidr":"10.0.0.2/31"}],"queries":["10.0.0.2"]}'
```

## 算法

- IP 表示为 32 位无符号整数；CIDR 解析时强制网络位规范（`base & mask === base`）。
- 地址集 = 排序、不相交、相邻合并的 `[lo, hi]` 区间数组：
  - 规则的有效地址 = `本规则区间 − 先前所有规则的并集`；
  - 相邻交换的影响集 = `(A ∩ B) − 更早规则的并集`（动作不同时）。
  - `shadowed` 证书按地址从左到右生成：在每个最小未覆盖地址，选择与目标
    CIDR 相交且覆盖该地址、右端最远的先前规则；右端并列选更早序号。该区间
    贪心给出最少规则数，每步只记录相对已选规则新覆盖的闭区间。
  交集对两个 IPv4 CIDR 而言要么为空，要么是一个整区间，所以无需区间拆分。
- 地址总数与见证都在区间上直接求和/取最小值，最大仅 2³²，双精度整数可精确表示。

## 测试

```bash
npm test          # vitest run
```

- `test/ip.test.ts` — CIDR/IP 解析与规范校验；
- `test/validation.test.ts` — 数量上限、重复 id、未知字段、越界八位组等；
- `test/semantics.test.ts` — 手算断言：`/0`（2³² 计数）、完全遮蔽、分片残留、
  相邻交换（含同动作无影响）、查询首匹配、默认 deny 与覆盖证书；
- `test/bruteforce.test.ts` — **对拍测试**：在 `10.13.0.0/24` 小子网内逐地址
  穷举（256 个地址全部线性扫描），与审计器输出逐条规则、逐对相邻交换、逐查询
  比较；含 300 个固定随机种子策略；对带 `/0` 的策略，用规则端点划分的最大恒定
  区间（run-length）在全 32 位空间等价穷举交换影响；在小子网内枚举先前规则
  子集核对证书条数最小、每段由对应前序规则覆盖且重复运行结果一致；另含区间
  集合 `union`/`subtract` 对 `Set` 预言机的 200 组随机对拍。

覆盖的场景包括：`/0`、完全遮蔽、部分相交（残留被切成两段）、不相交、相同动作
交换无影响。
