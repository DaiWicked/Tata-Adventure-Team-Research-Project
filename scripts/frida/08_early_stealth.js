/* 08_early_stealth.js —— spawn 模式早 hook：在壳的反调试跑起来之前先把路堵上
 *
 * 依据（真机 logcat 实测）：
 *   avc: denied { getattr } for path="/proc/<lgd pid>" ... tcontext=u:r:magisk:s0
 *   avc: denied { setopt } ... tclass=unix_stream_socket
 *   avc: denied { read/open } for name="input" /dev/input
 *   avc: denied { ioctl } for path="/proc/<self pid>/maps" ioctlcmd=6611
 * 命中即自杀（Process ... has died: fore TOP，无 tombstone）。
 *
 * 对策：
 *   1) 路径屏蔽：libc 的 open/openat/fopen/opendir/stat/lstat/access 看到
 *      frida/27042 相关路径、/proc/<lgd 相关 pid>、/data/local/tmp 一律 ENOENT；
 *   2) 符号中和：libcheck.so 加载后把 antiFile / antiProperty /
 *      antiPropertyValueContains 改成恒返回 0；
 *   3) 顺带记录壳到底读了哪些路径（只看前缀，不打印全路径避免噪声）。
 *
 * 用法（必须 spawn，不能 attach）：
 *   py -3 scripts/run_frida.py scripts/frida/08_early_stealth.js --spawn --seconds 60
 */
var HIDE_SUBSTR = ['frida', '27042', 'linjector', 'gum-js-loop', 'gmain',
                   '/data/local/tmp', 'magisk', 're.frida'];

var readPaths = {};
var reported = {};

function suspect(path) {
  if (!path) return false;
  for (var i = 0; i < HIDE_SUBSTR.length; i++) {
    if (path.indexOf(HIDE_SUBSTR[i]) >= 0) return true;
  }
  return false;
}

function note(api, path) {
  if (!path) return;
  var key = api + ' ' + path;
  if (reported[key]) return;
  reported[key] = true;
  if (Object.keys(reported).length <= 200) send('[read] ' + key);
}

function hookPath(api, argIndex) {
  var p = null;
  try { p = Module.findExportByName(null, api); } catch (e) { p = null; }
  if (!p) { send('[!] 无导出 ' + api); return; }
  Interceptor.attach(p, {
    onEnter: function (args) {
      try {
        var s = args[argIndex].readCString();
        this.path = s;
        this.hide = suspect(s);
        note(api, s);
      } catch (e) { this.hide = false; }
    },
    onLeave: function (retval) {
      if (this.hide) retval.replace(-1);
    }
  });
}

['open', 'openat', 'fopen', 'opendir', 'stat', 'lstat', 'access'].forEach(function (fn) {
  hookPath(fn, fn === 'openat' ? 1 : 0);
});

/* libcheck.so 三个 anti* 恒返回 0 */
var NEUTRAL = ['antiFile', 'antiProperty', 'antiPropertyValueContains'];
var checkHooked = false;

function modByName(name) {
  try { if (Process.getModuleByName) return Process.getModuleByName(name); } catch (e) {}
  try { if (Process.findModuleByName) return Process.findModuleByName(name); } catch (e) {}
  return null;
}

function hookCheck() {
  if (checkHooked) return;
  var mod = modByName('libcheck.so');
  if (!mod) return;
  NEUTRAL.forEach(function (name) {
    var addr = null;
    try { addr = mod.findExportByName ? mod.findExportByName(name) : null; } catch (e) {}
    if (!addr) { try { addr = mod.getExportByName ? mod.getExportByName(name) : null; } catch (e) {} }
    if (!addr) return;
    try {
      Interceptor.replace(addr, new NativeCallback(function () {
        send('[+] ' + name + ' -> 0');
        return 0;
      }, 'int', ['pointer', 'pointer', 'pointer']));
    } catch (e) {
      send('[!] replace ' + name + ' 失败: ' + e);
    }
  });
  checkHooked = true;
  send('[+] libcheck.so 已中和 @ ' + mod.base);
}

/* libcheck 可能在 spawn 后任意时刻加载：dlopen/dlopen_ext 回来时碰一次 + 轮询兜底 */
['dlopen', 'android_dlopen_ext'].forEach(function (fn) {
  var p = Module.findExportByName(null, fn);
  if (!p) return;
  Interceptor.attach(p, {
    onLeave: function () { hookCheck(); }
  });
});

var t = setInterval(function () {
  hookCheck();
}, 200);
setTimeout(function () { clearInterval(t); }, 30000);

send('[i] stealth 就绪');
