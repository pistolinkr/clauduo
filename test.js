// node test.js : 가짜 claude로 초대→멘션→파일 수정→충돌→되돌리기→경로 차단을 끝까지 확인
const { spawn } = require('child_process'), fs = require('fs'), os = require('os'), path = require('path'), assert = require('assert');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clauduo-test-'));
const bin = path.join(tmp, 'claude');
fs.writeFileSync(bin, `#!/bin/sh\n[ "$1" = auth ] && exit 0\ncat >/dev/null\nmkdir -p bob\necho from-claude > bob/made.txt\nln -s /etc/passwd bob/link\necho done\n`, { mode: 0o755 });
const env = { ...process.env, CLAUDUO_DATA: tmp + '/d', PORT: '4399', CLAUDE_BIN: bin }, U = 'http://127.0.0.1:4399';
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const srv = spawn('node', ['clauduo.js', 'serve'], { env, cwd: __dirname });
  const owner = await new Promise(r => srv.stdout.on('data', d => { const m = /#t=(\S+)/.exec(d); if (m) r(m[1]); }));
  let wrk;
  try {
    const api = async (t, method, p, body) => { const r = await fetch(U + p, { method, headers: { authorization: 'Bearer ' + t }, body: body && JSON.stringify(body) }); return { s: r.status, j: await r.json() }; };
    const { url } = (await api(owner, 'POST', '/api/invites')).j, invite = url.split('invite=')[1];
    const bob = (await api('', 'POST', '/api/join', { invite, name: 'bob' })).j.token;
    assert(bob, 'join');
    assert.equal((await api('', 'POST', '/api/join', { invite, name: 'eve' })).s, 403, 'invite is single use');
    assert.equal((await api('', 'POST', '/api/join', { invite: '__proto__', name: 'eve' })).s, 403, 'prototype key is not an invite');
    assert.equal((await api(bob, 'POST', '/api/revert', { hist: '__proto__' })).s, 404, 'prototype key is not history');
    assert.equal((await api(bob, 'POST', '/api/invites')).s, 403, 'guest cannot invite');
    assert.equal((await api('nope', 'GET', '/api/state')).s, 401);
    for (const p of ['../x', '/etc/x', 'a/../../x', 'bob/.claude/settings.json'])
      assert.equal((await api(owner, 'PUT', '/api/file', { path: p, text: 'x' })).s, 400, p);

    wrk = spawn('node', ['clauduo.js', 'worker', U, bob], { env, cwd: __dirname });
    await sleep(2000);
    await api(owner, 'POST', '/api/messages', { text: '@bob 파일 만들어' });
    let msgs = [];
    for (let i = 0; i < 20 && !msgs.some(m => m.text === 'done'); i++) { await sleep(500); msgs = (await api(owner, 'GET', '/api/state?since=0')).j.messages; }
    assert(msgs.some(m => m.from === 'bob' && m.text === 'done'), 'reply');
    const files = (await api(owner, 'GET', '/api/files')).j;
    assert(files.includes('bob/made.txt'), 'claude edit synced');
    assert(!files.includes('bob/link'), 'symlink not synced');

    const f = (await api(owner, 'GET', '/api/file?path=bob/made.txt')).j;
    assert.equal(f.text, 'from-claude\n');
    assert.equal((await api(owner, 'PUT', '/api/file', { path: 'bob/made.txt', text: 'owner', base: f.base })).s, 200);
    assert.equal((await api(bob, 'PUT', '/api/file', { path: 'bob/made.txt', text: 'stale', base: f.base })).s, 409, 'stale edit refused');
    msgs = (await api(owner, 'GET', '/api/state?since=0')).j.messages;
    const last = msgs.filter(m => m.kind === 'change').at(-1);
    await api(bob, 'POST', '/api/revert', { hist: last.hist });
    assert.equal((await api(owner, 'GET', '/api/file?path=bob/made.txt')).j.text, 'from-claude\n', 'revert');

    // 계정 삭제: 권한, 토큰 무효화, 로컬 로그인 폴더 제거, 작업 파일 보존
    assert.equal((await api(bob, 'DELETE', '/api/members', { name: 'owner' })).s, 403, 'guest cannot remove');
    assert.equal((await api(owner, 'DELETE', '/api/members', { name: 'owner' })).s, 400, 'owner cannot be removed');
    assert.equal((await api(owner, 'POST', '/api/accounts', { name: 'carol' })).s, 200);
    const cfg = path.join(tmp, 'd/accounts/carol');
    for (let i = 0; i < 20 && !(await api(owner, 'GET', '/api/state')).j.members.some(m => m.name === 'carol'); i++) await sleep(100);
    assert(fs.existsSync(cfg), 'account folder created');
    assert.equal((await api(owner, 'DELETE', '/api/members', { name: 'carol' })).s, 200);
    await sleep(300);
    assert(!fs.existsSync(cfg), 'account login removed');
    const exited = new Promise(r => wrk.on('exit', r));
    assert.equal((await api(owner, 'DELETE', '/api/members', { name: 'bob' })).s, 200);
    assert.equal((await api(bob, 'GET', '/api/state')).s, 401, 'removed token revoked');
    await exited;
    assert((await api(owner, 'GET', '/api/files')).j.includes('bob/made.txt'), 'work kept');
    console.log('ok');
  } finally { srv.kill(); wrk && wrk.kill(); fs.rmSync(tmp, { recursive: true, force: true }); }
})().catch(e => { console.error(e); process.exit(1); });
