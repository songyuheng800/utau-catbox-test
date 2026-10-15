/**
 * 敏感词检测系统 - Trie 树引擎
 * POST /api/sensitive-check  {text: "要检测的文本"}
 * 返回 {ok: true, hit: true/false, words: ["命中的词"], positions: [{word, start, end}]}
 */

// 敏感词库（可扩展）
const SENSITIVE_WORDS = [
  // 辱骂类
  "傻子", "傻逼", "sb", "SB", "草泥马", "他妈", "你妈", "操你", "狗日",
  "王八蛋", "脑残", "智障", "去死", "废物", "垃圾", "贱", "婊子",
  // 英文辱骂
  "fuck", "shit", "bitch", "asshole", "bastard", "damn", "cunt",
  // 政治敏感（占位，按需添加）
  // "xxx",
  // 其他违规
  "色情", "赌博", "毒品", "诈骗", "传销",
];

// 拼音映射（用于谐音检测）
const PINYIN_MAP = {
  "草": "cao", "操": "cao", "曹": "cao",
  "泥": "ni", "你": "ni", "尼": "ni",
  "马": "ma", "妈": "ma", "麻": "ma",
  "傻": "sha", "煞": "sha",
  "逼": "bi", "比": "bi", "鼻": "bi",
  "狗": "gou", "够": "gou",
  "日": "ri", "二": "er",
  "你": "ni", "拟": "ni",
  "妈": "ma", "马": "ma",
};

// 变体字符映射（1=!, l=I, 0=o, 3=e, 4=a, 5=s, 7=t 等）
const LEET_MAP = {
  "1": ["l", "i", "!"], "!": ["i", "l", "1"],
  "0": ["o", "O"], "o": ["0", "O"],
  "3": ["e", "E"], "e": ["3"],
  "4": ["a", "A"], "@": ["a", "A"],
  "5": ["s", "S"], "$": ["s", "S"],
  "7": ["t", "T"],
  "|": ["l", "I"],
};

class TrieNode {
  constructor() {
    this.children = {};
    this.isEnd = false;
    this.word = null;
  }
}

class Trie {
  constructor() {
    this.root = new TrieNode();
  }
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
  // 在文本中查找所有命中
  search(text) {
    const results = [];
    const lower = text.toLowerCase();
    for (let i = 0; i < lower.length; i++) {
      let node = this.root;
      let j = i;
      while (j < lower.length && node.children[lower[j]]) {
        node = node.children[lower[j]];
        if (node.isEnd) {
          results.push({ word: node.word, start: i, end: j + 1 });
        }
        j++;
      }
    }
    return results;
  }
}

// 构建 Trie
const trie = new Trie();
for (const w of SENSITIVE_WORDS) trie.insert(w);

// 预处理文本：去除空格、标点、变体字符
function normalize(text) {
  let t = text.toLowerCase();
  // 去除常见分隔符
  t = t.replace(/[\s\.\-_*~!！@#$%^&*()\[\]{}<>《》""''，。、；：？]/g, "");
  // 变体字符还原
  let result = "";
  for (const ch of t) {
    if (LEET_MAP[ch]) {
      result += LEET_MAP[ch][0]; // 取第一个映射
    } else {
      result += ch;
    }
  }
  return result;
}

export async function onRequest(context) {
  const { request } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors() });
  }
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);

  const body = await request.json().catch(() => null);
  if (!body || !body.text) return json({ ok: false, msg: "请提供 text 字段" }, 400);

  const text = String(body.text);
  if (!text.trim()) return json({ ok: true, hit: false, words: [], positions: [] });

  // 原始文本检测
  const rawHits = trie.search(text);

  // 预处理后检测（变体/分隔符绕过）
  const normalized = normalize(text);
  const normHits = trie.search(normalized);

  // 合并去重
  const allWords = new Set();
  for (const h of rawHits) allWords.add(h.word);
  for (const h of normHits) allWords.add(h.word);

  const hit = allWords.size > 0;

  return json({
    ok: true,
    hit,
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
