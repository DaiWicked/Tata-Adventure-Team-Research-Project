/* 02_dump_metadata.js — 在内存里找解密后的 global-metadata.dat 并落盘
 *
 * 依据: 原生 IL2CPP 元数据 magic = 0xFAB11BAF（小端 af 1b b1 fa）。
 *       包内文件是易盾 HTPX 容器加密的，但运行时一定会出现明文副本。
 * 用法:
 *   frida -U -f com.lilithgame.pgame.android.cn -l scripts/frida/02_dump_metadata.js --no-pause
 * 产物: /data/local/tmp/global-metadata.dec  (adb pull 出来)
 */
var MAGIC = 'af 1b b1 fa';
var DUMP_SIZE = 12 * 1024 * 1024; // 包内原文件 10,033,692 B，留余量
var MAX_SCAN = 2000 * 1024 * 1024;

function ranges() {
  var out = [];
  ['r--', 'rw-'].forEach(function (prot) {
    Process.enumerateRanges(prot).forEach(function (r) {
      if (r.size >= 4096 && r.size < MAX_SCAN) out.push(r);
    });
  });
  return out;
}

function dumpAt(addr) {
  console.log('[+] metadata magic @ ' + addr);
  try {
    var buf = addr.readByteArray(DUMP_SIZE);
    var f = new File('/data/local/tmp/global-metadata.dec', 'wb');
    f.write(buf); f.flush(); f.close();
    console.log('[+] 已写出 /data/local/tmp/global-metadata.dec');
    return true;
  } catch (e) {
    console.log('[!] 读内存失败: ' + e);
    return false;
  }
}

function scanOnce() {
  var rs = ranges();
  console.log('[*] 扫描 ' + rs.length + ' 个区间');
  for (var i = 0; i < rs.length; i++) {
    var hits;
    try { hits = Memory.scanSync(rs[i].base, rs[i].size, MAGIC); } catch (e) { continue; }
    for (var j = 0; j < hits.length; j++) {
      if (dumpAt(hits[j].address)) return true;
    }
  }
  return false;
}

/* 启动期元数据还没解密，等几秒再扫；也可以手动在 REPL 里调 scanOnce() */
setTimeout(function () {
  if (!scanOnce()) {
    console.log('[!] 首轮未命中，10 秒后再试（若仍未命中，用 REPL 手动 scanOnce()）');
    setTimeout(scanOnce, 10000);
  }
}, 8000);
