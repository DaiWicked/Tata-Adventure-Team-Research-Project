/* 09_hide_tracer.js —— 把 TracerPid 抹成 0，让壳以为没人 ptrace
 *
 * 真机实测结论（重要）：
 *   - frida-server 常驻但不 attach  → App 活得好好的（跑满 45s 未死）
 *   - 一旦 attach                  → 1~4 秒内自杀（logcat: has died: fore TOP，无 tombstone）
 *   ⇒ 触发点是 **ptrace 附着** 本身，不是 /proc 里多了个进程。
 *   ⇒ 最省事的一刀：让 /proc/self/status 里的 TracerPid 读出来永远是 0。
 *
 * 做法：
 *   1) 启动时把 /proc/self/status 读出来，TracerPid 那行改写为 0（长度保持一致）；
 *   2) 落一份到 App 自己的私有目录（进程本身有权限写）；
 *   3) hook open/openat/fopen：路径命中 /proc/self/status 或 /proc/<pid>/status 时，
 *      换成我们那份净化过的文件。
 *
 * 注意：这只是第一层。壳还可能扫 /proc/self/task 下的 comm（frida 线程名 gum-js-loop）、
 * 扫内存里的 frida 特征串、比对 maps。所以脚本跑起来后要尽快 dump，别指望长期驻留。
 *
 * 用法：
 *   py -3 scripts/run_frida.py scripts/frida/09_hide_tracer.js --spawn --seconds 30
 */
var SELF_STATUS = ['/proc/self/status', '/proc/' + Process.id + '/status'];
var CLEAN_PATH = '/data/data/com.lilithgame.pgame.android.cn/files/st.clean';
var cleanWritten = false;

function exp(name) {
  try { return Module.findGlobalExportByName(name); } catch (e) { return null; }
}

function buildClean() {
  if (cleanWritten) return true;
  try {
    var src = new File('/proc/self/status', 'rb');
    var raw = src.readBytes(16384);
    src.close();
    var text = '';
    for (var i = 0; i < raw.length; i++) text += String.fromCharCode(raw[i] & 0xff);

    var lines = text.split('\n');
    var out = [];
    for (var j = 0; j < lines.length; j++) {
      var ln = lines[j];
      if (ln.indexOf('TracerPid:') === 0) {
        var pad = ln.length - 'TracerPid:\t0'.length;
        if (pad < 0) pad = 0;
        ln = 'TracerPid:\t0' + new Array(pad + 1).join(' ');
      }
      out.push(ln);
    }
    var dst = new File(CLEAN_PATH, 'wb');
    dst.write(out.join('\n'));
    dst.flush();
    dst.close();
    cleanWritten = true;
    send('[+] 净化版 status 已写入 ' + CLEAN_PATH);
    return true;
  } catch (e) {
    send('[!] 写净化版失败: ' + e);
    return false;
  }
}

buildClean();

function isStatusPath(s) {
  if (!s) return false;
  for (var i = 0; i < SELF_STATUS.length; i++) if (s === SELF_STATUS[i]) return true;
  return false;
}

/* 路径替身：把净化路径写成一块常驻 C 字符串 */
var cleanBuf = Memory.allocUtf8String(CLEAN_PATH);

function hookOpen(api, pathIndex) {
  var addr = exp(api);
  if (!addr) { send('[!] 无导出 ' + api); return; }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      try {
        var s = args[pathIndex].readCString();
        if (isStatusPath(s)) {
          args[pathIndex] = cleanBuf;
          send('[+] ' + api + ' 命中 status -> 净化版');
        }
      } catch (e) {}
    }
  });
}

hookOpen('open', 0);
hookOpen('openat', 1);
hookOpen('fopen', 0);

send('[i] TracerPid 遮蔽就绪');
