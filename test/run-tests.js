// run-tests.js — 逻辑测试：围绕有效链与受限域名拒绝等场景验证 chain.js 行为。
import { createHash } from 'node:crypto';
import { verifyChainSet, hostMatch, dnsWithin } from '../src/chain.js';
import { derEcdsaToRaw } from '../src/der.js';
import { makeCert, makeKeys, extn, OCT, SEQ } from './certgen.js';

const T = Date.parse('2026-10-01T12:00:00Z'); // 验证时刻（有效期内）
const NB = new Date('2026-01-01T00:00:00Z');
const NA = new Date('2027-01-01T00:00:00Z');

let passed = 0;
let failed = 0;

function ok(name, cond, detail = '') {
  if (cond) {
    passed++;
    console.log(`PASS ${name}`);
  } else {
    failed++;
    console.error(`FAIL ${name}${detail ? ` —— ${detail}` : ''}`);
  }
}

function assertOk(res, what) {
  return res.ok === true || `期望成功但失败：${what} → [${res.stage}] ${res.message}`;
}

function assertFail(res, stage, what) {
  if (res.ok) return `期望失败(${stage})但成功：${what}`;
  if (res.stage !== stage) return `期望阶段 ${stage}，实际 ${res.stage}：${what} → ${res.message}`;
  return true;
}

// 构造 root → (inter) → leaf 的证书世界；inter 为 null 时 leaf 直接由 root 签发。
function buildWorld({ root = {}, inter = {}, leaf = {} } = {}) {
  const rootK = makeKeys();
  const anchor = makeCert({
    subjectCN: 'Root CA', issuerCN: 'Root CA',
    subjectPubKey: rootK.publicKey, issuerPrivKey: rootK.privateKey,
    isCA: true, keyUsage: { keyCertSign: true, crlSign: true },
    serial: 100, notBefore: NB, notAfter: NA, ...root,
  });
  let interDer = null;
  let interK = null;
  if (inter !== null) {
    interK = makeKeys();
    interDer = makeCert({
      subjectCN: 'Inter CA', issuerCN: 'Root CA',
      subjectPubKey: interK.publicKey, issuerPrivKey: rootK.privateKey,
      isCA: true, pathLen: 0, keyUsage: { keyCertSign: true },
      serial: 200, notBefore: NB, notAfter: NA, ...inter,
    });
  }
  const leafK = makeKeys();
  const issuerK = inter === null ? rootK : interK;
  const leafDer = makeCert({
    subjectCN: 'app.example.com',
    issuerCN: inter === null ? 'Root CA' : 'Inter CA',
    subjectPubKey: leafK.publicKey, issuerPrivKey: issuerK.privateKey,
    keyUsage: { digitalSignature: true },
    sanDns: ['app.example.com'],
    serial: 300, notBefore: NB, notAfter: NA, ...leaf,
  });
  return { anchor, inter: interDer, leaf: leafDer, rootK, interK, leafK };
}

const run = (anchor, certs, dns = 'app.example.com', at = T) =>
  verifyChainSet({ anchorDer: anchor, certDers: certs, dnsName: dns, verifyTime: at });

// ---------- 单元：DER ECDSA 签名转换 ----------
{
  // r 带 0x00 符号填充（33 字节），s 仅 1 字节 → 输出 64 字节并正确补零
  const r = Uint8Array.from([0x00, ...Array(32).fill(0xab)]);
  const s = Uint8Array.of(0x7f);
  const der = SEQ(tlvInt(r), tlvInt(s));
  const raw = derEcdsaToRaw(der, 32);
  ok('单元：DER→raw 签名转换（去填充/补零）',
    raw.length === 64 && raw[0] === 0xab && raw[31] === 0xab && raw[32] === 0 && raw[63] === 0x7f);
  let threw = false;
  try {
    derEcdsaToRaw(Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x01), 32); // 缺 s
  } catch { threw = true; }
  ok('单元：畸形 DER 签名被拒绝', threw);

  function tlvInt(v) {
    const tag = Uint8Array.of(0x02, v.length);
    const out = new Uint8Array(2 + v.length);
    out.set(tag, 0);
    out.set(v, 2);
    return out;
  }
}

// ---------- 单元：主机名与约束匹配 ----------
{
  ok('单元：通配 SAN 单层匹配',
    hostMatch('*.example.com', 'foo.example.com')
    && !hostMatch('*.example.com', 'a.b.example.com')
    && !hostMatch('*.example.com', 'example.com'));
  ok('单元：DNS 约束语义',
    dnsWithin('a.example.com', 'example.com')
    && dnsWithin('example.com', 'example.com')
    && !dnsWithin('badexample.com', 'example.com')
    && dnsWithin('a.example.com', '.example.com')
    && !dnsWithin('example.com', '.example.com'));
}

// ---------- 场景 1：有效三级链 ----------
{
  const w = buildWorld();
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景1：有效三级链成立', assertOk(res, '三级链') === true,
    res.ok ? '' : res.message);
  if (res.ok) {
    ok('场景1：链结构 叶→中间→锚',
      res.chain.length === 3 && res.chain[0].subject.includes('app.example.com')
      && res.chain[2].isAnchor && res.chain.every((c) => c.notes.length > 0));
  }
}

// ---------- 场景 2：有效二级链（叶直签于锚） ----------
{
  const w = buildWorld({ inter: null });
  const res = await run(w.anchor, [w.leaf]);
  ok('场景2：有效二级链成立', assertOk(res, '二级链') === true, res.ok ? '' : res.message);
}

// ---------- 场景 3：permitted 名称约束命中 ----------
{
  const w = buildWorld({ root: { nameConstraints: { permitted: ['example.com'] } } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景3：permitted 约束覆盖目标名 → 成立', assertOk(res, 'permitted 命中') === true,
    res.ok ? '' : res.message);
}

// ---------- 场景 4：permitted 未覆盖 → 拒绝 ----------
{
  const w = buildWorld({
    root: { nameConstraints: { permitted: ['example.com'] } },
    leaf: { subjectCN: 'app.other.org', sanDns: ['app.other.org'] },
  });
  const res = await run(w.anchor, [w.leaf, w.inter], 'app.other.org');
  ok('场景4：目标名不在 permitted 内 → 拒绝(nameconstraint)',
    assertFail(res, 'nameconstraint', 'permitted 未覆盖') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 5：excluded 命中 → 拒绝 ----------
{
  const w = buildWorld({
    root: { nameConstraints: { permitted: ['example.com'], excluded: ['bad.example.com'] } },
    leaf: { subjectCN: 'bad.example.com', sanDns: ['bad.example.com'] },
  });
  const res = await run(w.anchor, [w.leaf, w.inter], 'bad.example.com');
  ok('场景5：目标名命中 excluded → 拒绝(nameconstraint)',
    assertFail(res, 'nameconstraint', 'excluded 命中') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 6：中间 CA 的 excluded 约束同样生效 ----------
{
  const w = buildWorld({
    inter: { nameConstraints: { excluded: ['bad.example.com'] } },
    leaf: { subjectCN: 'bad.example.com', sanDns: ['bad.example.com'] },
  });
  const res = await run(w.anchor, [w.leaf, w.inter], 'bad.example.com');
  ok('场景6：中间 CA excluded 累积生效 → 拒绝(nameconstraint)',
    assertFail(res, 'nameconstraint', '中间 CA excluded') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 7：前导点约束仅覆盖子域 ----------
{
  const w = buildWorld({ root: { nameConstraints: { permitted: ['.example.com'] } } });
  const sub = await run(w.anchor, [w.leaf, w.inter], 'app.example.com');
  ok('场景7a：".example.com" 覆盖子域 → 成立', assertOk(sub, '子域') === true,
    sub.ok ? '' : sub.message);
  const w2 = buildWorld({
    root: { nameConstraints: { permitted: ['.example.com'] } },
    leaf: { subjectCN: 'example.com', sanDns: ['example.com'] },
  });
  const apex = await run(w2.anchor, [w2.leaf, w2.inter], 'example.com');
  ok('场景7b：".example.com" 不覆盖裸域 → 拒绝(nameconstraint)',
    assertFail(apex, 'nameconstraint', '裸域') === true,
    apex.ok ? '意外成功' : `[${apex.stage}] ${apex.message}`);
}

// ---------- 场景 8：pathLenConstraint 违约 ----------
{
  const w = buildWorld({ root: { pathLen: 0 } }); // 锚不允许下级 CA，但存在中间 CA
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景8：锚 pathLen=0 存在中间 CA → 拒绝(pathlen)',
    assertFail(res, 'pathlen', 'pathLen 违约') === true && res.level === 2,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 9：pathLenConstraint 恰好满足 ----------
{
  const w = buildWorld({ root: { pathLen: 1 } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景9：锚 pathLen=1 恰覆盖一级中间 CA → 成立', assertOk(res, 'pathLen 满足') === true,
    res.ok ? '' : res.message);
}

// ---------- 场景 10：签名被篡改 ----------
{
  const w = buildWorld({ leaf: { tamperSig: true } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景10：叶证书签名篡改 → 拒绝(signature)',
    assertFail(res, 'signature', '篡改签名') === true && res.level === 0,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 11：有效期不覆盖验证时刻 ----------
{
  const w = buildWorld({ leaf: { notAfter: new Date('2026-06-01T00:00:00Z') } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景11a：叶证书已过期 → 拒绝(validity)',
    assertFail(res, 'validity', '过期') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
  const w2 = buildWorld({ inter: { notBefore: new Date('2026-12-01T00:00:00Z') } });
  const res2 = await run(w2.anchor, [w2.leaf, w2.inter]);
  ok('场景11b：中间 CA 尚未生效 → 拒绝(validity)',
    assertFail(res2, 'validity', '未生效') === true && res2.level === 1,
    res2.ok ? '意外成功' : `[${res2.stage}] L${res2.level} ${res2.message}`);
}

// ---------- 场景 12：中间证书非 CA ----------
{
  const w = buildWorld({ inter: { isCA: false, pathLen: null, keyUsage: { digitalSignature: true } } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景12：中间证书非 CA → 拒绝(ca)',
    assertFail(res, 'ca', '非 CA 签发者') === true && res.level === 1,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 13：CA 的 keyUsage 缺 keyCertSign ----------
{
  const w = buildWorld({ inter: { keyUsage: { digitalSignature: true } } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景13：CA 缺 keyCertSign → 拒绝(keyusage)',
    assertFail(res, 'keyusage', '缺 keyCertSign') === true && res.level === 1,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 14：未知关键扩展 ----------
{
  const w = buildWorld({
    leaf: { extraExtensions: [extn('1.3.6.1.4.1.55555.1', true, OCT(Uint8Array.of(5, 0)))] },
  });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景14：未知关键扩展 → 拒绝(extension) 并定位证书',
    assertFail(res, 'extension', '未知关键扩展') === true && res.label === '证书#1',
    res.ok ? '意外成功' : `[${res.stage}] ${res.label} ${res.message}`);
}

// ---------- 场景 15：截断 DER ----------
{
  const w = buildWorld();
  const truncated = w.leaf.slice(0, w.leaf.length - 10);
  const res = await run(w.anchor, [truncated, w.inter]);
  ok('场景15：截断 DER → 拒绝(parse) 并定位证书',
    assertFail(res, 'parse', '截断') === true && res.label === '证书#1',
    res.ok ? '意外成功' : `[${res.stage}] ${res.label} ${res.message}`);
}

// ---------- 场景 16：循环签发 ----------
{
  const kA = makeKeys();
  const kB = makeKeys();
  const kLeaf = makeKeys();
  const certA = makeCert({
    subjectCN: 'A', issuerCN: 'B', subjectPubKey: kA.publicKey, issuerPrivKey: kB.privateKey,
    isCA: true, keyUsage: { keyCertSign: true }, serial: 401, notBefore: NB, notAfter: NA,
  });
  const certB = makeCert({
    subjectCN: 'B', issuerCN: 'A', subjectPubKey: kB.publicKey, issuerPrivKey: kA.privateKey,
    isCA: true, keyUsage: { keyCertSign: true }, serial: 402, notBefore: NB, notAfter: NA,
  });
  const leaf = makeCert({
    subjectCN: 'app.example.com', issuerCN: 'A',
    subjectPubKey: kLeaf.publicKey, issuerPrivKey: kA.privateKey,
    keyUsage: { digitalSignature: true }, sanDns: ['app.example.com'],
    serial: 403, notBefore: NB, notAfter: NA,
  });
  const w = buildWorld(); // 锚与 A/B 环无关
  const res = await run(w.anchor, [leaf, certA, certB]);
  ok('场景16：A↔B 循环签发 → 拒绝(cycle)',
    assertFail(res, 'cycle', '循环签发') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 17：主机名未列入 SAN ----------
{
  const w = buildWorld();
  const res = await run(w.anchor, [w.leaf, w.inter], 'nosuch.example.com');
  ok('场景17：主机名未列入 SAN → 拒绝(hostname)',
    assertFail(res, 'hostname', '主机名不在 SAN') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 18：多链成立 → 按 SHA-256 摘要序稳定选择 ----------
{
  const rootK = makeKeys();
  const anchor = makeCert({
    subjectCN: 'Root CA', issuerCN: 'Root CA',
    subjectPubKey: rootK.publicKey, issuerPrivKey: rootK.privateKey,
    isCA: true, keyUsage: { keyCertSign: true }, serial: 100, notBefore: NB, notAfter: NA,
  });
  const mkLeaf = (serial) => {
    const k = makeKeys();
    return makeCert({
      subjectCN: 'app.example.com', issuerCN: 'Root CA',
      subjectPubKey: k.publicKey, issuerPrivKey: rootK.privateKey,
      keyUsage: { digitalSignature: true }, sanDns: ['app.example.com'],
      serial, notBefore: NB, notAfter: NA,
    });
  };
  const leafA = mkLeaf(501);
  const leafB = mkLeaf(502);
  const dA = createHash('sha256').update(leafA).digest('hex');
  const dB = createHash('sha256').update(leafB).digest('hex');
  const expectLeaf = dA < dB ? dA : dB;
  const res1 = await run(anchor, [leafA, leafB]);
  const res2 = await run(anchor, [leafB, leafA]); // 打乱输入顺序
  ok('场景18：多链成立时按摘要序稳定选择',
    res1.ok && res2.ok && res1.chain[0].sha256 === expectLeaf && res2.chain[0].sha256 === expectLeaf,
    `期望叶摘要 ${expectLeaf}，实际 ${res1.ok ? res1.chain[0].sha256 : res1.message}`);
}

// ---------- 场景 19：通配 SAN ----------
{
  const w = buildWorld({ leaf: { sanDns: ['*.example.com'] } });
  const sub = await run(w.anchor, [w.leaf, w.inter], 'foo.example.com');
  ok('场景19a：通配 SAN 命中单层子域 → 成立', assertOk(sub, '通配') === true,
    sub.ok ? '' : sub.message);
  const deep = await run(w.anchor, [w.leaf, w.inter], 'a.b.example.com');
  ok('场景19b：通配 SAN 不跨层 → 拒绝(hostname)',
    assertFail(deep, 'hostname', '跨层通配') === true,
    deep.ok ? '意外成功' : `[${deep.stage}] ${deep.message}`);
}

// ---------- 场景 20：锚非 CA / 输入超限 ----------
{
  const w = buildWorld({ inter: null, root: { isCA: false, keyUsage: { keyCertSign: true } } });
  const res = await run(w.anchor, [w.leaf]);
  ok('场景20a：锚非 CA → 拒绝(ca)',
    assertFail(res, 'ca', '锚非 CA') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
  const res2 = await run(w.anchor, Array(8).fill(w.leaf), 'app.example.com');
  ok('场景20b：候选证书超过 7 张 → 拒绝(input)',
    assertFail(res2, 'input', '超过上限') === true,
    res2.ok ? '意外成功' : `[${res2.stage}] ${res2.message}`);
}

// ---------- 场景 21：有效期边界（含端点） ----------
{
  const w = buildWorld();
  const atNotAfter = await run(w.anchor, [w.leaf, w.inter], 'app.example.com', NA.getTime());
  ok('场景21：验证时刻取 notAfter 端点 → 成立', assertOk(atNotAfter, '边界') === true,
    atNotAfter.ok ? '' : atNotAfter.message);
}

// ---------- 场景 22~26：同名中间 CA（续期 / 密钥轮换） ----------
// 构造：信任锚 + 两张主体同名（Ground Relay CA）的中间 CA + 目标 ground.example.com 的叶证书。
// front / back 按 DER SHA-256 摘要排序（front 摘要更小）；sameKey 模拟续期未换钥。
function makeGroundWorld({ sameKey = false } = {}) {
  const rootK = makeKeys();
  const anchor = makeCert({
    subjectCN: 'Ground Root CA', issuerCN: 'Ground Root CA',
    subjectPubKey: rootK.publicKey, issuerPrivKey: rootK.privateKey,
    isCA: true, keyUsage: { keyCertSign: true, crlSign: true },
    serial: 100, notBefore: NB, notAfter: NA,
  });
  const kA = makeKeys();
  const kB = sameKey ? kA : makeKeys();
  const mkInter = (k, serial) => makeCert({
    subjectCN: 'Ground Relay CA', issuerCN: 'Ground Root CA',
    subjectPubKey: k.publicKey, issuerPrivKey: rootK.privateKey,
    isCA: true, pathLen: 0, keyUsage: { keyCertSign: true },
    serial, notBefore: NB, notAfter: NA,
  });
  const cand = [
    { der: mkInter(kA, 201), k: kA },
    { der: mkInter(kB, 202), k: kB },
  ].map((c) => ({ ...c, d: createHash('sha256').update(c.der).digest('hex') }));
  cand.sort((x, y) => (x.d < y.d ? -1 : 1));
  const [front, back] = cand;
  const mkLeaf = (issuerPrivKey, extra = {}) => makeCert({
    subjectCN: 'ground.example.com', issuerCN: 'Ground Relay CA',
    subjectPubKey: makeKeys().publicKey, issuerPrivKey,
    keyUsage: { digitalSignature: true }, sanDns: ['ground.example.com'],
    serial: 300, notBefore: NB, notAfter: NA, ...extra,
  });
  return { anchor, front, back, mkLeaf };
}

// ---------- 场景 22：同名中间 CA 仅一张可用 → 选中实际签发者 ----------
{
  const w = makeGroundWorld();
  // 22a：叶证书仅由摘要靠后的中间 CA 签发（密钥轮换后的新证书），
  //      摘要靠前者无法验证叶签名，但不应妨碍备用链成立
  const leafBack = w.mkLeaf(w.back.k.privateKey);
  const resBack = await run(w.anchor, [leafBack, w.front.der, w.back.der], 'ground.example.com');
  ok('场景22a：同名 CA 中叶由摘要靠后者签发 → 备用链成立',
    assertOk(resBack, '备用链') === true && resBack.chain[1].sha256 === w.back.d,
    resBack.ok ? `L1=${resBack.chain[1].sha256}` : `[${resBack.stage}] ${resBack.message}`);
  // 22b：叶证书由摘要靠前者签发（对照方向）
  const leafFront = w.mkLeaf(w.front.k.privateKey);
  const resFront = await run(w.anchor, [leafFront, w.front.der, w.back.der], 'ground.example.com');
  ok('场景22b：同名 CA 中叶由摘要靠前者签发 → 链成立',
    assertOk(resFront, '前排签发') === true && resFront.chain[1].sha256 === w.front.d,
    resFront.ok ? `L1=${resFront.chain[1].sha256}` : `[${resFront.stage}] ${resFront.message}`);
  // 22c：备用链保留逐级签名与策略依据
  ok('场景22c：备用链保留逐级签名与策略依据',
    resBack.ok && resBack.chain.length === 3
    && resBack.chain[0].notes.some((n) => n.includes('签名经 L1'))
    && resBack.chain[1].notes.some((n) => n.includes('CA=true'))
    && resBack.chain[1].notes.some((n) => n.includes('keyCertSign'))
    && resBack.chain[2].isAnchor);
}

// ---------- 场景 23：同名中间 CA 下输入顺序变化不改变结论 ----------
{
  const w = makeGroundWorld();
  const leaf = w.mkLeaf(w.back.k.privateKey);
  const orders = [
    [leaf, w.front.der, w.back.der],
    [w.back.der, leaf, w.front.der],
    [w.front.der, w.back.der, leaf],
  ];
  const keys = [];
  let allOk = true;
  for (const certs of orders) {
    const res = await run(w.anchor, certs, 'ground.example.com');
    allOk &&= res.ok;
    if (res.ok) keys.push(res.chain.map((c) => c.sha256).join('|'));
  }
  ok('场景23：候选证书录入顺序变化 → 选中链一致',
    allOk && keys.length === 3 && keys.every((k) => k === keys[0]) && keys[0].includes(w.back.d),
    keys.join(' vs '));
}

// ---------- 场景 24：同名同钥续期、两条链均有效 → 按完整链摘要稳定择链 ----------
{
  const w = makeGroundWorld({ sameKey: true }); // 续期未换钥：叶签名对两张同名 CA 均有效
  const leaf = w.mkLeaf(w.front.k.privateKey);
  const res1 = await run(w.anchor, [leaf, w.front.der, w.back.der], 'ground.example.com');
  const res2 = await run(w.anchor, [w.back.der, w.front.der, leaf], 'ground.example.com');
  ok('场景24：两条同名链均有效 → 稳定选中摘要更小者（与顺序无关）',
    res1.ok && res2.ok
    && res1.chain[1].sha256 === w.front.d
    && res2.chain[1].sha256 === w.front.d,
    `期望 L1=${w.front.d}，实际 ${res1.ok ? res1.chain[1].sha256 : res1.message}`
    + ` / ${res2.ok ? res2.chain[1].sha256 : res2.message}`);
}

// ---------- 场景 25：同名中间 CA 均无法验证叶签名 → 拒绝 ----------
{
  const w = makeGroundWorld();
  const ghost = makeKeys(); // 叶的实际签发者不在证书包中
  const leaf = w.mkLeaf(ghost.privateKey);
  const res = await run(w.anchor, [leaf, w.front.der, w.back.der], 'ground.example.com');
  ok('场景25：同名 CA 均非实际签发者 → 拒绝(signature)',
    assertFail(res, 'signature', '同名均不可用') === true && res.level === 0,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 26：证书包中无可用签发者 → 拒绝(chain) ----------
{
  const w = makeGroundWorld();
  const leaf = w.mkLeaf(w.front.k.privateKey, { issuerCN: 'Ghost CA' });
  const res = await run(w.anchor, [leaf, w.front.der, w.back.der], 'ground.example.com');
  ok('场景26：签发者名称不在证书包中 → 拒绝(chain)',
    assertFail(res, 'chain', '无可用签发者') === true && res.message.includes('找不到'),
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

console.log(`\n${passed} 项通过，${failed} 项失败`);
process.exit(failed === 0 ? 0 : 1);
