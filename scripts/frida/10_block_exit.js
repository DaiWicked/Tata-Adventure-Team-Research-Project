/* 10_block_exit.js —— 别让它自杀：把 exit/_exit/abort/kill 全堵住
 *
 * 思路（来自 docs/09 的实测）：壳发现异常后是**进程自己退出**（AMS 只看到 has died，
 * 没有 tombstone、没有 ANR），说明走的是 exit()/abort()/kill(getpid()) 这类用户态自杀。
 * 那就把这些出口全部堵掉，进程就能活下来，然后想怎么 dump 就怎么 dump。
 *
 * 配合 wrap.<pkg> + LD_PRELOAD gadget 使用（不进 ptrace，见 docs/09 §8）：
 *   py -3 scripts/run_frida.py scripts/frida/10_block_exit.js --name Gadget --seconds 60
 */
function exp(name) {
  try { return Module.findGlobalExportByName(name); } catch (e) { return null; }
}

var hits = {};
var done = {};

function report(fn, detail) {
  hits[fn] = (hits[fn] || 0) + 1;
  if (hits[fn] <= 5) send('[block] ' + fn + ' ' + detail);
}

function blockVoid(name) {
  var addr = exp(name);
  if (!addr) { send('[!] 无导出 ' + name); return; }
  if (done[addr]) { send('[skip] ' + name + ' 与已替换地址相同'); return; }
  done[addr] = name;
  Interceptor.replace(addr, new NativeCallback(function () {
    report(name, '(已拦截)');
  }, 'void', []));
}

function blockInt(name) {
  var addr = exp(name);
  if (!addr) { send('[!] 无导出 ' + name); return; }
  if (done[addr]) { send('[skip] ' + name + ' 与已替换地址相同'); return; }
  done[addr] = name;
  Interceptor.replace(addr, new NativeCallback(function () {
    report(name, '(已拦截)');
    return 0;
  }, 'int', ['int']));
}

blockVoid('exit');
blockVoid('_exit');
blockVoid('_Exit');
blockVoid('abort');
blockVoid('quick_exit');
blockInt('raise');

/* kill / tgkill / pthread_kill：只拦"杀自己"的调用 */
['kill', 'tgkill'].forEach(function (name) {
  var addr = exp(name);
  if (!addr || done[addr]) return;
  done[addr] = name;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      var pid = args[0].toInt32();
      var tid = name === 'tgkill' ? args[1].toInt32() : pid;
      if (pid === Process.id || pid === -Process.id || tid === Process.id) {
        this.block = true;
        report(name, 'pid=' + pid + ' tid=' + tid + ' sig=' + args[name === 'kill' ? 1 : 2].toInt32());
      }
    },
    onLeave: function (retval) {
      if (this.block) retval.replace(0);
    }
  });
});

send('[i] exit 出口已封 ' + JSON.stringify(Object.keys(hits)));
