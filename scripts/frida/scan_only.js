/* scan_only.js —— gadget 内联脚本：只扫描，不碰任何 exit/kill
 *
 * 为什么不用 hook.js v2 的封锁版：
 *   v2 确实拦下了壳的自杀（hook.log 里 "blocked exit"），但代价是加载流程被卡死 ——
 *   截图 screen_03.png 是全白页，/proc/<pid>/maps 里**没有 libil2cpp.so**，
 *   说明 Unity 根本没起来，内存里自然也不会有解密后的元数据，所以 meta/lua 两轮全 0 命中。
 *
 * 结论：先不干预，让进程按自己的节奏跑起来，再扫内存。gadget 在进程内、没有独立进程可被
 * /proc 扫到，理论上不会触发之前的 anti-frida 逻辑（那套逻辑扫的是 frida-server 的 pid）。
 *
 * 产物：/data/data/com.lilithgame.pgame.android.cn/files/q_*.bin
 * 日志：同目录 scan.log
 */
var OUT = '/data/data/com.lilithgame.pgame.android.cn/files/';
var META_MAGIC = 'af 1b b1 fa';   /* 0xFAB11BAF LE：IL2CPP 元数据头 */
var LUA_MAGIC = '1b 4c 75 61';    /* "\x1bLua"：Lua 5.x 预编译块头 */

function log(s) {
  try {
    var f = new File(OUT + 'scan.log', 'ab');
    f.write(String(Date.now()) + ' [' + Process.id + '] ' + s + '\n');
    f.flush(); f.close();
  } catch (e) {}
}

function dump(kind, addr, idx, size) {
  var path = OUT + 'q_' + kind + '_' + idx + '_' + addr + '.bin';
  try {
    var f = new File(path, 'wb');
    f.write(addr.readByteArray(size));
    f.flush(); f.close();
    log('SAVED ' + path + ' (' + size + ' B)');
    return true;
  } catch (e) { log('dump fail: ' + e); return false; }
}

/* 一次扫完所有 rw- range（不分尺寸窗口），分片上报进度 */
function sweep(magic, kind, dumpSize, maxHits, chunk) {
  var rs = [], total = 0, t0 = Date.now(), saved = 0;
  Process.enumerateRanges('rw-').forEach(function (r) {
    if (r.size >= 4096) { rs.push(r); total += r.size; }
  });
  log(kind + ': ' + rs.length + ' rw- ranges / ' + (total / 1048576).toFixed(0) + ' MB');
  for (var i = 0; i < rs.length && saved < maxHits; i++) {
    var base = rs[i].base, size = rs[i].size;
    for (var off = 0; off < size && saved < maxHits; off += chunk) {
      var len = Math.min(chunk, size - off);
      var hits;
      try { hits = Memory.scanSync(base.add(off), len, magic); } catch (e) { break; }
      for (var j = 0; j < hits.length && saved < maxHits; j++) {
        var h = hits[j].address;
        var room = size - h.sub(base).toInt32();
        var n = Math.min(dumpSize, room);
        if (n > 0 && dump(kind, h, saved, n)) saved++;
      }
    }
  }
  log(kind + ' done ' + saved + ' hits / ' + ((Date.now() - t0) / 1000).toFixed(1) + 's');
  return saved;
}

function isMain() {
  try { return (Process.name || '').indexOf(':') < 0; } catch (e) { return true; }
}

log('scan_only start pid=' + Process.id + ' main=' + isMain() + ' name=' + Process.name);
if (isMain()) {
  var round = 0;
  var timer = setInterval(function () {
    round++;
    /* 先看引擎有没有起来 */
    var hasEngine = false;
    Process.enumerateModules().forEach(function (m) {
      if (m.name.indexOf('libil2cpp') === 0) hasEngine = true;
    });
    log('round ' + round + ' il2cpp=' + hasEngine);
    if (hasEngine) {
      sweep(META_MAGIC, 'meta', 12 * 1048576, 2, 16 * 1048576);
      sweep(LUA_MAGIC, 'lua', 64 * 1024, 6, 16 * 1048576);
    }
    if (round >= 15) { clearInterval(timer); log('stop'); }
  }, 5000);
}
