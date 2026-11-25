/* 06_net_watch.js — 观察登录/重连/上报报文（不解密，只看结构与流向）
 *
 * 背景（静态已知）:
 *   - libil2cpp.so 含 `UnityWebSocket.Runtime.dll`、`KCP`、`reconnect`、`session`
 *   - libigame.so 含 `KCP`
 *   => 长连接走 KCP(UDP) + WebSocket，重连逻辑在引擎层，业务报文多半是 protobuf/自定义二进制
 *
 * 用法:
 *   frida -U -f com.lilithgame.pgame.android.cn -l scripts/frida/06_net_watch.js --no-pause
 *   # 想只看某个长度阈值以上的包，改 MIN_LEN
 */
var MIN_LEN = 16;        // 小于这个长度的包多半是心跳，不打印
var SHOW_HEX = 96;       // 每个包最多打印的字节数

function blen(p) { try { return p.readU32(); } catch (e) { return 0; } }

function hook(name, argIdx, lenFromArg) {
  var p = Module.findExportByName(null, name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) {
      var buf = args[argIdx], len = args[lenFromArg];
      var n = len.toInt32();
      if (n < MIN_LEN) return;
      var hex = '';
      try { hex = buf.readByteArray(Math.min(n, SHOW_HEX)).byteLength ? '' : ''; } catch (e) {}
      try {
        var arr = new Uint8Array(buf.readByteArray(Math.min(n, SHOW_HEX)));
        hex = Array.prototype.map.call(arr, function (b) {
          return ('0' + b.toString(16)).slice(-2);
        }).join(' ');
      } catch (e) { hex = '<unreadable>'; }
      console.log('[' + name + '] len=' + n + ' fd=' + args[0].toInt32() + '  ' + hex);
    }
  });
  console.log('[+] hooked ' + name);
}

/* TCP / TLS 路径（登录、HTTP 接口） */
hook('send', 1, 2);
hook('write', 1, 2);
hook('SSL_write', 1, 2);

/* UDP 路径（KCP） */
hook('sendto', 1, 2);

console.log('[*] 现在做一次"断网 30 分钟再重连"，对比重连前后第一个大包的差异');
