/* 07_quick_dump.js —— 附着后抢跑：按尺寸窗口把扫描量压到最小
 *
 * 真机结论（见 docs/09）：
 *   - frida-server / gadget 都能进去；
 *   - 但壳在 1~3 秒内就发现并自杀，全量扫 1230 个 range 根本扫不完（实测扫到一半连接断）。
 *   ⇒ 必须按"已知目标文件大小"过滤 range，把扫描量压到几百 MB 以内。
 *
 * 两个目标：
 *   IL2CPP 元数据  magic af 1b b1 fa，文件 10,033,692 B → range 8MB~20MB
 *   Lua chunk      magic 1b 4c 75 61，单个 chunk 32KB~8MB   → range 32KB~8MB
 *
 * 产物：/data/local/tmp/q_<kind>_<i>_<addr>.bin
 */
var META_MAGIC = 'af 1b b1 fa';
var LUA_MAGIC = '1b 4c 75 61';

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
  var path = '/data/local/tmp/q_' + kind + '_' + idx + '_' + addr + '.bin';
  try {
    var f = new File(path, 'wb');
    f.write(addr.readByteArray(size));
    f.flush(); f.close();
    send('  saved ' + path);
    return true;
  } catch (e) {
    send('  dump fail @ ' + addr + ' : ' + e);
    return false;
  }
}

function pass(magic, kind, lo, hi, dumpSize, maxHits) {
  var rs = ranges(lo, hi), t0 = Date.now(), saved = 0, total = 0;
  for (var i = 0; i < rs.length; i++) total += rs[i].size;
  send('[' + kind + '] ' + rs.length + ' ranges / ' + (total / 1048576).toFixed(0) + ' MB');
  for (var i = 0; i < rs.length && saved < maxHits; i++) {
    var hits;
    try { hits = Memory.scanSync(rs[i].base, rs[i].size, magic); } catch (e) { continue; }
    for (var j = 0; j < hits.length && saved < maxHits; j++) {
      var size = Math.min(dumpSize, rs[i].size - hits[j].address.sub(rs[i].base).toInt32());
      if (size <= 0) continue;
      if (dump(kind, hits[j].address, saved, size)) saved++;
    }
  }
  send('[' + kind + '] done ' + saved + ' hits / ' + (Date.now() - t0) + 'ms');
}

send('quick dump @ ' + Date.now());
pass(META_MAGIC, 'meta', 8 * 1048576, 20 * 1048576, 12 * 1048576, 2);
pass(LUA_MAGIC, 'lua', 32 * 1024, 8 * 1048576, 64 * 1024, 8);
send('quick dump end @ ' + Date.now());
