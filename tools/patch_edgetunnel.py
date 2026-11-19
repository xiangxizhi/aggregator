#!/usr/bin/env python3
from pathlib import Path

p = Path("dist/_worker.js")
s = p.read_text(encoding="utf-8")

helper = r'''
// EdgeTunnel multi-protocol + country quota selector (generated build)
const EdgeTunnel国家缓存 = new Map();
async function 查询节点国家代码(ip) {
  const now = Date.now();
  const cached = EdgeTunnel国家缓存.get(ip);
  if (cached && now - cached.time < 86400000) return cached.country;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4500);
  try {
    const response = await fetch("https://api.country.is/" + encodeURIComponent(ip), {
      signal: controller.signal,
      headers: { "Accept": "application/json" }
    });
    if (!response.ok) return null;
    const data = await response.json();
    const country = typeof data.country === "string" ? data.country.toUpperCase() : null;
    if (country && /^[A-Z]{2}$/.test(country)) {
      EdgeTunnel国家缓存.set(ip, { country, time: now });
      return country;
    }
  } catch (e) {
    console.warn("[国家筛选] IP国家查询失败:", ip, e && e.message ? e.message : e);
  } finally {
    clearTimeout(timer);
  }
  return null;
}

async function 按国家配额筛选优选IP(候选列表) {
  const 配额 = [["US", 20], ["JP", 5], ["IT", 5], ["VN", 5], ["SG", 5]];
  const 待查列表 = [];
  const 已见IP = new Set();
  for (const 原始地址 of 候选列表 || []) {
    const m = String(原始地址).match(/^\[([0-9a-fA-F:]+)\](?::\d+)?(?:#|$)|^((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:#|$)/);
    const ip = m && (m[1] || m[2]);
    if (!ip || 已见IP.has(ip)) continue;
    已见IP.add(ip);
    待查列表.push({ 原始地址: String(原始地址), ip });
    if (待查列表.length >= 500) break;
  }

  const 已分类 = new Map();
  for (let i = 0; i < 待查列表.length; i += 8) {
    const batch = 待查列表.slice(i, i + 8);
    const countries = await Promise.all(batch.map(item => 查询节点国家代码(item.ip)));
    batch.forEach((item, index) => {
      const country = countries[index];
      if (!country) return;
      if (!已分类.has(country)) 已分类.set(country, []);
      已分类.get(country).push(item);
    });
  }

  const 结果 = [];
  for (const [country, count] of 配额) {
    const list = 已分类.get(country) || [];
    for (const item of list.slice(0, count)) {
      const hash = item.原始地址.indexOf("#");
      const endpoint = hash >= 0 ? item.原始地址.slice(0, hash) : item.原始地址;
      const oldRemark = hash >= 0 ? item.原始地址.slice(hash + 1) : item.ip;
      结果.push(endpoint + "#" + country + "-" + oldRemark);
    }
    console.log("[国家筛选]", country, "目标", count, "实际", Math.min(list.length, count));
  }
  console.log("[国家筛选] 最终节点数:", 结果.length, "/ 40");
  return 结果;
}
'''

anchor = "async function 生成随机IP(request, count = 16, 指定端口 = -1) {"
if "async function 按国家配额筛选优选IP" not in s:
    if anchor not in s:
        raise SystemExit("PATCH FAILED: cannot find 生成随机IP insertion point")
    s = s.replace(anchor, helper + "\n" + anchor, 1)

old = """完整优选IP = 完整优选IP.concat(优选生成器IP数组);
\t\t\t\t\t\t\t\t其他节点LINK += 优选生成器其他节点;"""
new = """完整优选IP = 完整优选IP.concat(优选生成器IP数组);
\t\t\t\t\t\t\t\t// 本构建固定输出40个经IP地理库核验的目标国家节点；不混入来源中未经筛选的额外节点
\t\t\t\t\t\t\t\t其他节点LINK = '';"""
if old not in s:
    raise SystemExit("PATCH FAILED: cannot find best-sub source block")
s = s.replace(old, new, 1)

old = """\t\t\t\t\t\t\tconst ECHLINK参数 = config_JSON.ECH ?"""
new = """\t\t\t\t\t\t\t完整优选IP = await 按国家配额筛选优选IP(完整优选IP);
\t\t\t\t\t\t\tconst ECHLINK参数 = config_JSON.ECH ?"""
if old not in s:
    raise SystemExit("PATCH FAILED: cannot find ECHLINK insertion point")
s = s.replace(old, new, 1)

old = "订阅内容 = 其他节点LINK + 完整优选IP.map(原始地址 => {"
new = "订阅内容 = 其他节点LINK + 完整优选IP.map((原始地址, 节点序号) => {"
if old not in s:
    raise SystemExit("PATCH FAILED: cannot find node map callback")
s = s.replace(old, new, 1)

old = """\t\t\t\t\t\t\t\tif (协议类型 === 'ss' && !作为优选订阅生成器) {"""
new = """\t\t\t\t\t\t\t\t// 三种原生支持的协议按节点轮换分配，整条订阅同时包含 VLESS / Trojan / Shadowsocks
\t\t\t\t\t\t\t\tconst 当前协议类型 = ['vless', 'trojan', 'ss'][节点序号 % 3];
\t\t\t\t\t\t\t\tif (当前协议类型 === 'ss') {"""
if old not in s:
    raise SystemExit("PATCH FAILED: cannot find SS branch")
s = s.replace(old, new, 1)

# Only the two generated-link template expressions inside the mixed-node map need this substitution.
start = s.index("订阅内容 = 其他节点LINK + 完整优选IP.map((原始地址, 节点序号) => {")
end = s.index("}).filter(item => item !== null).join('\\n');", start)
section = s[start:end]
section = section.replace(r"return `${协议类型}://", r"return `${当前协议类型}://")
section = section.replace(r"return `${协议类型}://", r"return `${当前协议类型}://")
if "return `${当前协议类型}://" not in section:
    raise SystemExit("PATCH FAILED: link protocol substitution did not apply")
s = s[:start] + section + s[end:]

p.write_text(s, encoding="utf-8")
print("Patched _worker.js")
print("Country quota selector: US20 JP5 IT5 VN5 SG5")
print("Protocols: VLESS / Trojan / Shadowsocks")
print("Output target: 40 nodes maximum; fewer if country-qualified candidates are insufficient")
