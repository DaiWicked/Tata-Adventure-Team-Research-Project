/* 04_watch_signature.js — 观察请求签名（只看不伪造）
 *
 * 依据: libparkcrypto.so 的导出是明文（pyelftools 实测）:
 *   parkcrypto_generate_signature / parkcrypto_build_signature_base_string
 *   parkcrypto_url_encode / parkcrypto_rfc3986_encode / parkcrypto_get_version
 * 日志线索（so 内字符串）:
 *   get_decrypted_secret: unknown os_type=%s, using default win prod key
 *   parkcrypto_generate_signature: missing required parameter: os_type
 *
 * 目的: 拿到"参与签名的 base string 和最终 sign"，从而反推算法（排序/编码/secret）。
 *       仅用于理解协议；本项目不提供伪造签名的脚本。
 *
 * 用法:
 *   frida -U -f com.lilithgame.pgame.android.cn -l scripts/frida/04_watch_signature.js --no-pause
 */
function hookExport(mod, name, printer) {
  var p = Module.findExportByName(mod, name);
  if (!p) { console.log('[!] 未找到导出 ' + mod + '!' + name); return; }
  Interceptor.attach(p, {
    onEnter: function (args) {
      console.log('[' + name + '] a0=' + args[0] + ' a1=' + args[1] + ' a2=' + args[2] + ' a3=' + args[3]);
      if (printer) printer(args);
    },
    onLeave: function (ret) {
      try { console.log('    -> ' + ret.readCString()); } catch (e) { console.log('    -> ' + ret); }
    }
  });
  console.log('[+] hooked ' + name);
}

function waitLib() {
  if (!Module.findBaseAddress('libparkcrypto.so')) return false;

  // base string: 签名前的规范化串，最关键的一份证据
  hookExport('libparkcrypto.so', 'parkcrypto_build_signature_base_string', function (a) {
    try { console.log('    base = ' + a[1].readCString()); } catch (e) {}
  });

  // 最终签名
  hookExport('libparkcrypto.so', 'parkcrypto_generate_signature');

  // 版本号：服务端会校验，改包时必须一致
  hookExport('libparkcrypto.so', 'parkcrypto_get_version');

  console.log('[*] 现在去点一个会发请求的按钮（登录/进商店），控制台会打印签名链路');
  return true;
}

if (!waitLib()) {
  var tries = 0;
  var t = setInterval(function () {
    tries++;
    if (waitLib() || tries > 60) clearInterval(t);
  }, 500);
}
