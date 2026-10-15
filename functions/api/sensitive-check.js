/**
 * 敏感词检测系统 v2 - Trie 树 + 拼音谐音检测
 * POST /api/sensitive-check  {text: "要检测的文本"}
 */

// ========== 敏感词库 ==========
const SENSITIVE_WORDS = [
  // 辱骂核心词
  "傻子", "傻逼", "sb", "SB", "sb2", "s b",
  "草泥马", "操你妈", "他妈", "你妈", "操你", "狗日",
  "王八蛋", "脑残", "智障", "去死", "废物", "垃圾", "贱", "婊子",
  "妈逼", "妈了", "妈没", "妈死", "妈蛋", "妈卖批",
  "草泥", "操你", "草你", "日你", "干你",
  // 性器官/性相关脏话
  "鸡巴", "鸡吧", "几把", "jiba", "jb", "Jb", "JB",
  "屌", "鸡鸡", "蛋蛋", "咪咪", "奶子", "屁股",
  "做爱", "性交", "口交", "肛交", "自慰",
  // 谐音变体
  "马勒戈壁", "妈了个", "泥马", "尼玛", "尼妹",
  "煞笔", "沙比", "纱比", "傻13", "傻b",
  "草", "操", "日", "干", "靠",
  // 英文
  "fuck", "shit", "bitch", "asshole", "bastard", "damn", "cunt",
  "f u c k", "s h i t",
  // 违规
  "色情", "赌博", "毒品", "诈骗", "传销", "卖淫", "嫖娼",
];

// ========== 拼音检测 ==========
// 汉字→拼音映射（脏话相关）
const HANZI2PINYIN = {
  "草": "cao", "操": "cao", "曹": "cao", "槽": "cao", "槽": "cao",
  "泥": "ni", "你": "ni", "尼": "ni", "尼": "ni", "逆": "ni",
  "马": "ma", "妈": "ma", "麻": "ma", "码": "ma", "玛": "ma", "骂": "ma",
  "傻": "sha", "煞": "sha", "沙": "sha", "纱": "sha", "杀": "sha",
  "逼": "bi", "比": "bi", "鼻": "bi", "笔": "bi", "闭": "bi", "币": "bi",
  "狗": "gou", "够": "gou", "沟": "gou", "苟": "gou",
  "日": "ri", "二": "er", "耳": "er",
  "他": "ta", "她": "ta", "它": "ta", "踏": "ta",
  "妈": "ma", "马": "ma", "麻": "ma",
  "死": "si", "四": "si", "思": "si", "斯": "si", "丝": "si",
  "亡": "wang", "王": "wang", "忘": "wang",
  "八": "ba", "巴": "ba", "吧": "ba", "扒": "ba",
  "蛋": "dan", "但": "dan", "淡": "dan", "弹": "dan",
  "脑": "nao", "闹": "nao", "挠": "nao",
  "残": "can", "参": "can", "餐": "can",
  "智": "zhi", "之": "zhi", "只": "zhi", "指": "zhi",
  "障": "zhang", "张": "zhang", "章": "zhang", "长": "zhang",
  "去": "qu", "取": "qu", "曲": "qu",
  "废": "fei", "费": "fei", "飞": "fei",
  "物": "wu", "无": "wu", "五": "wu", "舞": "wu",
  "垃": "la", "拉": "la", "啦": "la",
  "圾": "ji", "机": "ji", "鸡": "ji", "积": "ji",
  "贱": "jian", "见": "jian", "建": "jian", "键": "jian",
  "婊": "biao", "表": "biao", "裱": "biao",
  "子": "zi", "字": "zi", "自": "zi", "紫": "zi",
  "卖": "mai", "买": "mai", "麦": "mai",
  "批": "pi", "皮": "pi", "屁": "pi", "脾": "pi",
  "勒": "le", "了": "le", "乐": "le",
  "戈": "ge", "哥": "ge", "歌": "ge", "格": "ge",
  "壁": "bi", "必": "bi", "避": "bi", "闭": "bi",
};

// 脏话拼音组合（检测拼音序列中是否包含）
const DIRTY_PINYIN = [
  "caonima", "cnm", "nima", "tmd", "wocao", "wo cao",
  "shabi", "shǎ bi", "sb", "gouri", "gou ri",
  "wángbadàn", "wbd", "nǎocán", "nc",
  "zhizhang", "zz", "qu si", "qusi",
  "feiwu", "fe iwu", "laji", "lj",
  "jianhuo", "jian huo", "biaoz i",
  "ni ma", "cao ni", "caoni",
  "ma le", "malege", "malegebi", "mlgb",
  "ni ma bi", "nmb", "caoni ma",
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
        if (node.isEnd) results.push({ word: node.word, start: i, end: j + 1 });
        j++;
      }
    }
    return results;
  }
}

const trie = new Trie();
for (const w of SENSITIVE_WORDS) trie.insert(w);

// ========== 变体/分隔符清理 ==========
const LEET_MAP = {
  "1": ["l", "i"], "!": ["i", "l"],
  "0": ["o"], "3": ["e"], "4": ["a"], "@": ["a"],
  "5": ["s"], "$": ["s"], "7": ["t"], "|": ["l"],
};

function normalize(text) {
  let t = text.toLowerCase();
  t = t.replace(/[\s\.\-_*~!！@#$%^&*()\[\]{}<>《》""''，。、；：？·・]/g, "");
  let result = "";
  for (const ch of t) {
    if (LEET_MAP[ch]) result += LEET_MAP[ch][0];
    else result += ch;
  }
  return result;
}

// ========== 拼音转换 ==========
function toPinyin(text) {
  let pinyin = "";
  for (const ch of text) {
    if (HANZI2PINYIN[ch]) pinyin += HANZI2PINYIN[ch];
    else if (/[a-zA-Z0-9]/.test(ch)) pinyin += ch.toLowerCase();
    // 其他字符跳过
  }
  return pinyin;
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
  for (const h of trie.search(text)) allWords.add(h.word);

  // 2. 规范化后匹配（变体/分隔符绕过）
  const normalized = normalize(text);
  for (const h of trie.search(normalized)) allWords.add(h.word);

  // 3. 拼音检测
  const pinyin = toPinyin(text);
  for (const dp of DIRTY_PINYIN) {
    if (pinyin.includes(dp.replace(/\s/g, ""))) {
      allWords.add("【拼音】" + dp);
    }
  }

  // 4. 特殊模式："妈" + 任何负面字
  if (/妈[没死蛋逼了卖]/.test(text)) {
    allWords.add("妈X谐音");
  }
  // 5. "操/草/日" + 你/他/妈
  if (/(操|草|日|干)(你|他|她|妈|娘|姐|妹)/.test(text)) {
    allWords.add("辱骂组合");
  }

  return json({
    ok: true,
    hit: allWords.size > 0,
    words: [...allWords],
    count: allWords.size,
    pinyin: pinyin,
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
