/* 03_scan_lua.js — 在内存里扫解密后的 Lua 字节码并落盘
 *
 * 依据: Lua 5.x 预编译 chunk 头 = 0x1B 'L' 'u' 'a'（小端 1b 4c 75 61）。
 *       本包业务逻辑在 Lua（pgame.pkg 内 .luae），运行时逐块解密加载，
 *       所以在"进主界面之后"扫命中率最高。
 * 用法:
 *   frida -U -f com.lilithgame.pgame.android.cn -l scripts/frida/03_scan_lua.js --no-pause
 * 产物: /data/local/tmp/lua_<addr>.luac
 */
var MAGIC = '1b 4c 75 61';
var CHUNK = 256 * 1024;   // 每个命中点 dump 的上限
var MAX_HITS = 40;        // 避免把手机写满

function ranges() {
  var out = [];
  ['r--', 'rw-'].forEach(function (prot) {
    Process.enumerateRanges(prot).forEach(function (r) {
      if (r.size >= 4096 && r.size < 512 * 1024 * 1024) out.push(r);
    });
  });
  return out;
}

function dumpChunk(addr, idx) {
  var start = addr.sub(16);                 // 头部前面可能有 12~16 字节 chunk 元数据
  var path = '/data/local/tmp/lua_' + idx + '_' + addr + '.luac';
  try {
    var buf = start.readByteArray(CHUNK);
    var f = new File(path, 'wb');
    f.write(buf); f.flush(); f.close();
    console.log('[+] ' + path);
    return true;
  } catch (e) {
    console.log('[!] dump 失败 @ ' + addr + ': ' + e);
    return false;
  }
}

function scanOnce() {
  var rs = ranges(), saved = 0;
  for (var i = 0; i < rs.length && saved < MAX_HITS; i++) {
    var hits;
    try { hits = Memory.scanSync(rs[i].base, rs[i].size, MAGIC); } catch (e) { continue; }
    for (var j = 0; j < hits.length && saved < MAX_HITS; j++) {
      if (dumpChunk(hits[j].address, saved)) saved++;
    }
  }
  console.log('[*] 本轮落盘 ' + saved + ' 个 chunk');
  return saved;
}

/* 场景加载完再扫：先给 20 秒，之后每 15 秒扫一次，最多 6 轮 */
var round = 0;
var timer = setInterval(function () {
  round++;
  console.log('[*] 第 ' + round + ' 轮扫描');
  scanOnce();
  if (round >= 6) clearInterval(timer);
}, 15000);
