/**
 * 敏感词检测系统 v3 - 全面版
 * Trie树 + 拼音检测 + 正则模式 + 变体还原
 * POST /api/sensitive-check  {text: "要检测的文本"}
 */

// ========== 超大敏感词库 ==========
const SENSITIVE_WORDS = [
  // ==== 辱骂核心 ====
  "傻逼", "傻子", "sb", "SB", "煞笔", "沙比", "纱比", "傻13", "傻b", "S.B",
  "草泥马", "操你妈", "草你妈", "他妈", "你妈", "操你", "草你", "日你", "干你",
  "狗日", "狗娘养", "王八蛋", "王八", "脑残", "智障", "去死", "废物", "垃圾",
  "贱", "婊子", "贱人", "贱货", "骚货", "浪货", "破鞋",
  "妈逼", "妈了", "妈没", "妈死", "妈蛋", "妈卖批", "妈了个", "妈了逼",
  "草泥", "操", "草", "日", "干", "靠", "靠你",
  // ==== 日语/其他外语脏话 ====
  "八嘎", "八嘎呀路", "马鹿", "baka", "Baka", "BAKA",
  "混蛋", "混账", "王八蛋", "该死", "他妈的", "他妈滴", "卧槽", "我靠", "我擦",
  "笨蛋", "白痴", "阿呆", "人渣", "败类", "人渣", "渣滓", "败类",
  "死全家", "死爸妈", "死爹死妈", "断子绝孙",
  // ==== 性器官/性相关 ====
  "鸡巴", "鸡吧", "几把", "jiba", "jb", "JB", "Jb",
  "屌", "鸡鸡", "蛋蛋", "咪咪", "奶子", "屁股", "屁眼",
  "做爱", "性交", "口交", "肛交", "自慰", "撸管", "打飞机",
  "性奴", "性玩具", "黄片", "黄色", "av", "AV",
  // ==== 谐音/变体 ====
  "马勒戈壁", "泥马", "尼玛", "尼妹", "尼玛币",
  "艹", "艸", "蕞", "巛",
  "沃日", "我日", "我操", "我草",
  "尼玛", "泥马", "尼马",
  "逗你玩", "逗你",
  // ==== 鄙视/歧视 ====
  "穷逼", "富逼", "丑逼", "矮逼",
  "土狗", "土鳖", "乡巴佬", "乡下",
  "残废", "残疾", "瞎子", "聋子", "哑巴",
  // ==== 威胁/暴力 ====
  "打死你", "弄死你", "杀了你", "去死吧", "滚", "滚蛋", "滚远点",
  // ==== 英文 ====
  "fuck", "shit", "bitch", "asshole", "bastard", "damn", "cunt",
  "motherfucker", "mofo", "wtf", "stupid", "idiot", "dumb",
  "f u c k", "s h i t", "b i t c h",
  // ==== 违规 ====
  "色情", "赌博", "毒品", "诈骗", "传销", "卖淫", "嫖娼",
  "枪", "弹药", "炸药", "炸弹", "毒药",
  // ==== 政治敏感/分裂违规 ====
  "台湾独立", "台独", "藏独", "疆独", "港独",
  "马路大", "maruta", "Maruta",
  "kuso", "KUSO", "Kuso",
];

// ========== 正则模式检测（组合/谐音/变体）==========
const PATTERNS = [
  // 妈X 系列
  /妈[没死蛋逼了卖操了个批的]/,
  // 操/草/日/干 + 你/他/妈/娘/姐/妹
  /[操草日干靠][你他她妈娘姐妹哥弟爸]/,
  // 傻X 系列
  /傻[子逼逼b13x屄逼了]/,
  // 草/操 + 泥/你 + 马/妈
  /[草操][泥你][马妈]/,
  // 首字母缩写
  /\bs\s*b\b/i, /\bsb\b/i,
  /\bcnm\b/i, /\bnm\b/i, /\btmd\b/i, /\bwtf\b/i,
  /\bfuck\b/i, /\bshit\b/i, /\bbitch\b/i,
  // 变体：1=i, 0=o, $=s, 5=s, 3=e, 4=a
  /s[1!il]{1,2}tch/i,  // 1itch, !itch
  /f[uck]{2,4}/i,      // fuck 变体
  // 鸡巴变体
  /鸡[巴吧逼吧叭]/, /[鸡妓几][巴吧把]/,
  // 狗X
  /狗[日娘东西]/,
  // 死X
  /死[全家爹妈]/,
  // 分裂言论：反对 + 正面政治词汇 = 违规
  /反对.{0,4}(统一|一国两制|九二共识|一个中国)/,
  /抵制.{0,4}(统一|一国两制|九二共识|一个中国)/,
  /拒绝.{0,4}(统一|一国两制|九二共识)/,
];

// ========== Trie 树 ==========
class TrieNode {
  constructor() { this.children = {}; this.isEnd = false; this.word = null; }
}
class Trie {
  constructor() { this.root = new TrieNode(); }
  insert(word) {
    let node = this.root;
    const lower = word.toLowerCase();
    for (const ch of lower) {
      if (!node.children[ch]) node.children[ch] = new TrieNode();
      node = node.children[ch];
    }
    node.isEnd = true;
    node.word = word;
  }
  search(text) {
    const results = [];
    const lower = text.toLowerCase();
    for (let i = 0; i < lower.length; i++) {
      let node = this.root;
      let j = i;
      while (j < lower.length && node.children[lower[j]]) {
        node = node.children[lower[j]];
        if (node.isEnd) results.push(node.word);
        j++;
      }
    }
    return results;
  }
}

const trie = new Trie();
for (const w of SENSITIVE_WORDS) trie.insert(w);

// ========== 变体还原 ==========
const LEET_MAP = {
  "1": ["l", "i"], "!": ["i", "l"], "|": ["l", "i"],
  "0": ["o"], "3": ["e"], "4": ["a"], "@": ["a"],
  "5": ["s"], "$": ["s"], "7": ["t"],
};

function normalize(text) {
  let t = text.toLowerCase();
  t = t.replace(/[\s\.\-_*~!！@#$%^&*()\[\]{}<>《》""''，。、；：？·・~～]/g, "");
  let result = "";
  for (const ch of t) {
    if (LEET_MAP[ch]) result += LEET_MAP[ch][0];
    else result += ch;
  }
  return result;
}

// ========== 主接口 ==========
export async function onRequest(context) {
  const { request } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors() });
  }
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);

  const body = await request.json().catch(() => null);
  if (!body || !body.text) return json({ ok: false, msg: "请提供 text 字段" }, 400);

  const text = String(body.text);
  if (!text.trim()) return json({ ok: true, hit: false, words: [], count: 0 });

  const allWords = new Set();

  // 1. 原始文本 Trie 匹配
  for (const w of trie.search(text)) allWords.add(w);

  // 2. 规范化后匹配（变体/分隔符绕过）
  const normalized = normalize(text);
  for (const w of trie.search(normalized)) allWords.add(w);

  // 3. 正则模式匹配
  for (const re of PATTERNS) {
    if (re.test(text)) {
      allWords.add("【模式】" + re.source);
    }
  }

  // 4. 白名单放行：敏感词前面有正面词（反对/抵制/谴责等）则不拦截
  const WHITELIST_PREFIX = ["反对", "抵制", "谴责", "打击", "批判", "声讨", "抗议", "坚决反对", "坚决抵制"];
  for (const word of [...allWords]) {
    if (word.startsWith("【模式】")) continue;
    const idx = text.indexOf(word);
    if (idx > 0) {
      const before = text.substring(Math.max(0, idx - 6), idx);
      for (const wp of WHITELIST_PREFIX) {
        if (before.endsWith(wp)) {
          allWords.delete(word);
          break;
        }
      }
    }
  }

  return json({
    ok: true,
    hit: allWords.size > 0,
    words: [...allWords],
    count: allWords.size,
    text_length: text.length,
  });
}

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}
function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors(), "Content-Type": "application/json; charset=utf-8" },
  });
}
