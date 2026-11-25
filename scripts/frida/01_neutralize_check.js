/* 01_neutralize_check.js — 关掉 libcheck.so 的三类检测
 *
 * 依据: libcheck.so 的导出符号是明文，直接按名挂即可（见 docs/05 §1）。
 *   antiFile / antiProperty / antiPropertyValueContains
 * 用法:
 *   frida -U -f com.lilithgame.pgame.android.cn -l scripts/frida/01_neutralize_check.js --no-pause
 */
Java.perform(function () {
  var NAMES = ['antiFile', 'antiProperty', 'antiPropertyValueContains'];

  function hookCheck() {
    var base = Module.findBaseAddress('libcheck.so');
    if (!base) { console.log('[!] libcheck.so 尚未加载，稍后重试'); return false; }
    NAMES.forEach(function (name) {
      var p = Module.findExportByName('libcheck.so', name);
      if (!p) { console.log('[!] 无导出 ' + name); return; }
      Interceptor.attach(p, {
        onEnter: function (args) {
          var s = null;
          try { s = args[0].readCString(); } catch (e) { s = String(args[0]); }
          console.log('[check] ' + name + '(' + s + ')');
        },
        onLeave: function (ret) {
          ret.replace(ptr(0)); // 一律返回"未命中"
        }
      });
      console.log('[+] hooked ' + name + ' @ ' + p);
    });
    return true;
  }

  if (!hookCheck()) {
    var tries = 0;
    var timer = setInterval(function () {
      tries++;
      if (hookCheck() || tries > 30) clearInterval(timer);
    }, 500);
  }
});

/* libigame.so 会 popen() 跑 shell 命令做环境检测，顺手把命令打出来 */
['popen', 'system'].forEach(function (name) {
  var p = Module.findExportByName(null, name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) {
      try { console.log('[' + name + '] ' + args[0].readCString()); } catch (e) {}
    }
  });
});
