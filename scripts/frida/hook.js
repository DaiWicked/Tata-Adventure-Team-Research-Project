/* hook.js v2 —— gadget 内联脚本：堵自杀 + 周期扫描（不监听端口）
 *
 * v1 实测（hook.log）：
 *   - "sealed exit/_exit/abort/quick_exit" 全部成功；
 *   - 出现过一次 "blocked exit"，说明壳确实走 exit() 自杀，且被我们拦下了；
 *   - 但进程还是起落 → 还有别的出口（裸 syscall(SYS_exit_group) 或外部 watchdog kill）；
 *   - meta 扫 25 个 range / 310MB、0 命中、4.3s —— 3 秒时元数据可能还没解密完。
 *
 * v2 改动：
 *   1) 额外 hook syscall()，拦 SYS_exit(93)/SYS_exit_group(231)；
 *   2) 扫描改成每 4 秒一轮、最多 8 轮，哪一轮命中就在哪一轮拿到；
 *   3) 只让主进程跑扫描（子进程只堵出口，避免互相抢 CPU）；
 *   4) 全部输出写到 App 私有目录的 hook.log，不用 logcat（Zygote 把 stdout 丢了）。
 *
 * 产物：/data/data/com.lilithgame.pgame.android.cn/files/q_{meta,lua}_*.bin
 */
var META_MAGIC = 'af 1b b1 fa';
var LUA_MAGIC = '1b 4c 75 61';
var OUT = '/data/data/com.lilithgame.pgame.android.cn/files/';
var SYS_EXIT = 93, SYS_EXIT_GROUP = 231;

var done = {};
var state = { metaHit: false, luaHit: 0 };

function log(s) {
  try {
    var f = new File(OUT + 'hook.log', 'ab');
    f.write(String(Date.now()) + ' [' + Process.id + '] ' + s + '\n');
    f.flush();
    f.close();
  } catch (e) {}
}

function exp(n) {
  try { return Module.findGlobalExportByName(n); } catch (e) { return null; }
}

function seal(name) {
  var a = exp(name);
  if (!a || done[a]) return;
  done[a] = name;
  try {
    Interceptor.replace(a, new NativeCallback(function () { log('blocked ' + name); }, 'void', []));
  } catch (e) { log('seal fail ' + name + ': ' + e); }
}

['exit', '_exit', '_Exit', 'abort', 'quick_exit'].forEach(seal);

/* 裸 syscall：拦 exit / exit_group */
(function hookSyscall() {
  var a = exp('syscall');
  if (!a) { log('no syscall export'); return; }
  try {
    Interceptor.attach(a, {
      onEnter: function (args) {
        var nr = args[0].toInt32();
        if (nr === SYS_EXIT || nr === SYS_EXIT_GROUP) {
          this.block = true;
          log('blocked syscall ' + nr);
        }
      },
      onLeave: function (rv) { if (this.block) rv.replace(-1); }
    });
    log('sealed syscall exit paths');
  } catch (e) { log('hook syscall fail: ' + e); }
})();

/* kill/tgkill 只拦打自己的 */
['kill', 'tgkill'].forEach(function (name) {
  var a = exp(name);
  if (!a || done[a]) return;
  done[a] = name;
  try {
    Interceptor.attach(a, {
      onEnter: function (args) {
        var pid = args[0].toInt32();
        var tid = name === 'tgkill' ? args[1].toInt32() : pid;
        if (pid === Process.id || tid === Process.id) { this.block = true; log('blocked ' + name); }
      },
      onLeave: function (rv) { if (this.block) rv.replace(0); }
    });
  } catch (e) {}
});

function isMain() {
  try {
    var n = Process.name || '';
    return n.indexOf(':') < 0;
  } catch (e) { return true; }
}

function ranges(lo, hi) {
  var out = [];
  ['rw-', 'r--'].forEach(function (prot) {
    Process.enumerateRanges(prot).forEach(function (r) {
      if (r.size >= lo && r.size <= hi) out.push(r);
    });
  });
  return out;
}

function dump(kind, addr, idx, size) {
  var path = OUT + 'q_' + kind + '_' + idx + '_' + addr + '.bin';
  try {
    var f = new File(path, 'wb');
    f.write(addr.readByteArray(size));
    f.flush(); f.close();
    log('saved ' + path);
    return true;
  } catch (e) { log('dump fail ' + e); return false; }
}

function pass(magic, kind, lo, hi, dumpSize, maxHits) {
  var rs = ranges(lo, hi), t0 = Date.now(), saved = 0, total = 0;
  for (var i = 0; i < rs.length; i++) total += rs[i].size;
  log(kind + ': ' + rs.length + ' ranges / ' + (total / 1048576).toFixed(0) + ' MB');
  for (var i = 0; i < rs.length && saved < maxHits; i++) {
    var hits;
    try { hits = Memory.scanSync(rs[i].base, rs[i].size, magic); } catch (e) { continue; }
    for (var j = 0; j < hits.length && saved < maxHits; j++) {
      var off = hits[j].address.sub(rs[i].base).toInt32();
      var size = Math.min(dumpSize, rs[i].size - off);
      if (size > 0 && dump(kind, hits[j].address, saved, size)) saved++;
    }
  }
  log(kind + ' done ' + saved + ' / ' + (Date.now() - t0) + 'ms');
  return saved;
}

log('v2 start pid=' + Process.id + ' main=' + isMain());
if (isMain()) {
  var round = 0;
  var timer = setInterval(function () {
    round++;
    log('round ' + round);
    if (!state.metaHit && pass(META_MAGIC, 'meta', 8 * 1048576, 24 * 1048576, 12 * 1048576, 2) > 0) {
      state.metaHit = true;
    }
    state.luaHit += pass(LUA_MAGIC, 'lua', 32 * 1024, 8 * 1048576, 64 * 1024, 6);
    if (round >= 8) { clearInterval(timer); log('stop'); }
  }, 4000);
}
