/**
 * 敏感词检测系统 v3 - 全面版
 * Trie树 + 拼音检测 + 正则模式 + 变体还原
 * POST /api/sensitive-check  {text: "要检测的文本"}
 */

// ========== 超大敏感词库（全量版）==========
const SENSITIVE_WORDS = [
  // ==== 辱骂核心 ====
  "傻逼","傻子","sb","SB","煞笔","沙比","纱比","傻13","傻b","S.B","傻X","傻x","煞笔","煞b",
  "草泥马","操你妈","草你妈","他妈","你妈","操你","草你","日你","干你","操他","草他",
  "狗日","狗娘养","王八蛋","王八","脑残","智障","去死","废物","垃圾","垃渣",
  "贱","婊子","贱人","贱货","骚货","浪货","破鞋","贱逼","骚逼","浪逼",
  "妈逼","妈了","妈没","妈死","妈蛋","妈卖批","妈了个","妈了逼","妈蛋的","妈了个逼",
  "草泥","操","草","日","干","靠","靠你","日他妈","操他妈","草他妈",
  // ==== 你麻痹系列全量变体 ====
  "你麻痹","你麻批","你麻皮","你麻B","你麻b","你马逼","你马匹","你马皮",
  "你妈逼","你妈B","你妈b","你他妈","你他妈的","你妈的","你妈了",
  "尼玛的","泥马的","尼马的","尼玛逼","泥马逼","尼马逼",
  "麻痹","麻批","麻皮","马逼","马批","马皮","麻痹的",
  // ==== 日语/外语脏话 ====
  "八嘎","八嘎呀路","马鹿","baka","Baka","BAKA","kuso","KUSO","Kuso",
  "混蛋","混账","王八蛋","该死","他妈的","他妈滴","卧槽","我靠","我擦","我艹",
  "笨蛋","白痴","阿呆","人渣","败类","渣滓","畜生","杂种","杂碎",
  "死全家","死爸妈","死爹死妈","断子绝孙","不得好死","天打雷劈",
  // ==== 性器官/性相关 ====
  "鸡巴","鸡吧","几把","jiba","jb","JB","Jb","鸡吧毛",
  "屌","鸡鸡","蛋蛋","咪咪","奶子","屁股","屁眼","逼","穴",
  "做爱","性交","口交","肛交","自慰","撸管","打飞机","啪啪啪",
  "性奴","性玩具","黄片","黄色","av","AV","毛片","三级片",
  // ==== 谐音/变体全量 ====
  "马勒戈壁","泥马","尼玛","尼妹","尼玛币","尼马",
  "艹","艸","蕞","巛","草泥马","操你妈",
  "沃日","我日","我操","我草","我靠","我擦",
  "逗你玩","逗你","逗你玩",
  // ==== 鄙视/歧视 ====
  "穷逼","富逼","丑逼","矮逼","胖逼",
  "土狗","土鳖","乡巴佬","乡下","土炮",
  "残废","残疾","瞎子","聋子","哑巴","瘸子",
  // ==== 威胁/暴力 ====
  "打死你","弄死你","杀了你","去死吧","滚","滚蛋","滚远点","滚开",
  "威胁","恐吓","绑架","勒索",
  // ==== 英文全量 ====
  "fuck","shit","bitch","asshole","bastard","damn","cunt","pussy",
  "motherfucker","mofo","wtf","stupid","idiot","dumb","loser","moron",
  "f u c k","s h i t","b i t c h","a s s h o l e",
  // ==== 违规 ====
  "色情","赌博","毒品","诈骗","传销","卖淫","嫖娼","吸毒",
  "枪","弹药","炸药","炸弹","毒药","危险品",
  // ==== 政治敏感/分裂违规 ====
  "台湾独立","台独","藏独","疆独","港独","蒙独","独立运动",
  "反对统一","反对一国两制","反对九二共识","反对一个中国",
  "马路大","maruta","Maruta",
  // ==== 地域/民族歧视 ====
  "河南猪","新疆猪","西藏猪","蒙古猪",
  "南蛮","北胡","东夷","西戎","鬼子","小日本","日本鬼子",
  "维吾尔族猪","藏族猪","蒙古族猪","回族猪","满族猪",
  "支那","清国奴","病夫","东亚病夫","华人与狗","黄皮猪",
  // ==== 其他常见脏话 ====
  "靠","靠啊","哇靠","哇噻","我靠",
  "屁","屁眼","狗屁","放屁",
  "鸟","鸟人","屌丝",
  "艹你","艹他妈","艹你妈",
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
  // 同音字模糊：麻/马/码、痹/逼/比/鼻 系列
  /你[麻马码][痹逼比鼻批皮B]/,
  /[麻马码][痹逼比鼻批皮B]/,
  /你妈[逼B]/,
  /你[麻马码]的/,
  // 分裂言论：反对 + 正面政治词汇 = 违规
  /反对.{0,4}(统一|一国两制|九二共识|一个中国)/,
  /抵制.{0,4}(统一|一国两制|九二共识|一个中国)/,
  /拒绝.{0,4}(统一|一国两制|九二共识)/,
  // 分裂变体：X独 / 独立运动
  /(台湾|西藏|新疆|蒙古|香港)[独独立]/,
  // 地域/民族歧视：地名 + 猪/狗/鬼
  /(河南|新疆|西藏|蒙古|维吾尔|藏|回|满|日本|韩国|越南|印度)[猪狗鬼]/,
  /(南蛮|北胡|东夷|西戎)/,
  // 辱华词汇
  /(支那|清国奴|东亚病夫|黄皮猪)/,
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
