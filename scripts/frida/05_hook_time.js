/* 05_hook_time.js — 时钟篡改探针（判定"离线收益"是谁算的）
 *
 * 要回答的问题: 离线收益是「服务端用自己记的 last_logout 时间算」还是
 *               「客户端上报离线秒数/本地时间」？
 *
 * 做法: 把所有时间源统一加一个可调偏移（默认 +6 小时），再断网重连看收益。
 *   收益跟着变  -> 客户端时间参与计算（可伪造，机制 2/3）
 *   收益不变    -> 服务端自己算（机制 1，不可伪造）
 *
 * 用法:
 *   frida -U -f com.lilithgame.pgame.android.cn -l scripts/frida/05_hook_time.js --no-pause
 *   # 在 REPL 里动态调整: setOffset(6*3600) / setOffset(0)
 */
var OFFSET_SEC = 6 * 3600;   // 默认 +6 小时

function now() { return Date.now() / 1000; }

function hookNative(name) {
  var p = Module.findExportByName(null, name);
  if (!p) { console.log('[!] 无导出 ' + name); return; }
  Interceptor.attach(p, {
    onLeave: function (ret) {
      // gettimeofday(struct timeval*, void*) / time(time_t*)
      try {
        if (name === 'gettimeofday' && this.args) {}
        var base = ret.toInt32 ? ret.toInt32() : 0;
      } catch (e) {}
    }
  });
  console.log('[+] hooked ' + name);
}

/* gettimeofday: 改写 timeval（更贴近游戏实际取时间的方式） */
var gtod = Module.findExportByName(null, 'gettimeofday');
if (gtod) {
  Interceptor.attach(gtod, {
    onLeave: function () {
      try {
        var tv = this.tv; // 由 onEnter 保存
        if (tv && !tv.isNull()) {
          var sec = tv.readU32();
          tv.writeU32(sec + OFFSET_SEC);
        }
      } catch (e) {}
    },
    onEnter: function (args) { this.tv = args[0]; }
  });
  console.log('[+] hooked gettimeofday (offset=' + OFFSET_SEC + 's)');
}

['time', 'clock_gettime'].forEach(function (name) {
  var p = Module.findExportByName(null, name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) { this.a0 = args[0]; this.a1 = args[1]; },
    onLeave: function (ret) {
      try {
        if (name === 'time') {
          ret.replace(ptr(ret.toInt32() + OFFSET_SEC));
          if (!this.a0.isNull()) this.a0.writeInt(ret.toInt32());
        } else if (name === 'clock_gettime') {
          // CLOCK_REALTIME(0) 才需要偏移，单调钟不动
          if (this.a0.toInt32() === 0 && !this.a1.isNull()) {
            var s = this.a1.readU64();
            this.a1.writeU64(s.add(OFFSET_SEC));
          }
        }
      } catch (e) {}
    }
  });
  console.log('[+] hooked ' + name);
});

/* Java 层（SDK 常用） */
if (Java.available) {
  Java.perform(function () {
    var S = Java.use('java.lang.System');
    var orig = S.currentTimeMillis;
    S.currentTimeMillis.implementation = function () {
      return orig.call(this) + OFFSET_SEC * 1000;
    };
    console.log('[+] hooked System.currentTimeMillis (+' + OFFSET_SEC + 's)');
  });
}

rpc.exports = {
  setOffset: function (sec) { OFFSET_SEC = sec; console.log('[*] offset -> ' + sec + 's'); },
  getOffset: function () { return OFFSET_SEC; }
};
