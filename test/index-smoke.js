const { PolicyIndex } = require('../server/indexer');
const root = process.argv[2] || '/tmp/selinux-policy/policy';
const idx = new PolicyIndex(console.log);
let t = Date.now();
const n = idx.scanRoots([root]);
console.log('scanned', n, 'files in', Date.now() - t, 'ms');
console.log(idx.stats());
for (const name of ['http_port_t', 'corenet_tcp_bind_http_port', 'httpd_sys_content_t', 'ntpd_t', 'files_read_etc_files', 'read_files_pattern', 'rw_file_perms', 'deny_ptrace', 'file', 'domain', 'user_home_t']) {
  const d = idx.definitionsOf(name);
  console.log(name, '->', d.slice(0, 3).map(x => `${x.what.kind}${x.what.generated ? '(via ' + x.what.via + ')' : ''} ${x.path.replace(root, '')}:${x.l + 1}`), d.length);
}
console.log('refs files_read_etc_files:', idx.referencesOf('files_read_etc_files').length);
console.log('file perms:', idx.permsOf('file').length, idx.permsOf('file').slice(0, 5));
const mem = process.memoryUsage(); console.log('heap MB', (mem.heapUsed / 1e6).toFixed(0));
t = Date.now(); idx.rebuild(); console.log('rebuild only', Date.now() - t, 'ms');
