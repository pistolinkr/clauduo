// DATABASE_URL=postgres://... node test-saas.js : 실제 Postgres, 가짜 Claude/Anthropic API로 전체 흐름을 확인한다
const { spawn } = require('child_process'), fs = require('fs'), os = require('os'), path = require('path'), http = require('http'), assert = require('assert');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clauduo-saas-'));
const bin = path.join(tmp, 'claude');
fs.writeFileSync(bin, '#!/bin/sh\ncat >/dev/null\nmkdir -p work\necho from-worker > work/made.txt\nln -s /etc/passwd work/link\necho worker-done\n', { mode: 0o755 });
const PORT = 4398, MOCK = 4397, U = `http://localhost:${PORT}`;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const sent = [];

// 가짜 Anthropic API: 파일을 쓰게 한 뒤 끝낸다
const mock = http.createServer(async (req, res) => {
  const chunks = []; for await (const c of req) chunks.push(c);
  const reply = o => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (req.headers.authorization !== 'Bearer sk-ant-good') { res.writeHead(401, { 'content-type': 'application/json' }); return res.end('{"type":"error","error":{"type":"authentication_error","message":"bad"}}'); }
  if (req.method === 'GET') return reply({ id: 'claude-opus-5-5', type: 'model' });
  const b = JSON.parse(Buffer.concat(chunks)); sent.push(b);
  const base = { id: 'msg', type: 'message', role: 'assistant', model: b.model, usage: { input_tokens: 1, output_tokens: 1 } };
  if (b.messages.length === 1) return reply({ ...base, stop_reason: 'tool_use', content: [
    { type: 'tool_use', id: 't1', name: 'write_file', input: { path: 'api/note.md', content: 'from-api' } },
    { type: 'tool_use', id: 't2', name: 'write_file', input: { path: '../escape', content: 'x' } }] });
  reply({ ...base, stop_reason: 'end_turn', content: [{ type: 'text', text: 'api-done' }] });
});

(async () => {
  await new Promise(r => mock.listen(MOCK, r));
  const env = { ...process.env, PORT, BASE_URL: U, CLAUDE_BIN: bin, ANTHROPIC_BASE_URL: `http://localhost:${MOCK}`, CLAUDUO_SECRET: 'test-secret' };
  const srv = spawn('node', ['server.js'], { env, cwd: __dirname });
  let out = ''; srv.stdout.on('data', d => out += d); srv.stderr.on('data', d => out += d);
  let wrk;
  try {
    for (let i = 0; i < 50 && !out.includes('listening'); i++) await sleep(100);
    assert(out.includes('listening'), out);
    const client = () => {
      let cookie = '';
      return async (method, p, body) => {
        const r = await fetch(U + p, { method, headers: { 'content-type': 'application/json', cookie }, body: method === 'GET' ? undefined : JSON.stringify(body || {}) });
        const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
        return { s: r.status, j: await r.json() };
      };
    };
    const login = async (c, email, invite) => {
      assert.equal((await c('POST', '/api/auth/request', { email, invite })).s, 200);
      await sleep(100);
      const m = [...out.matchAll(new RegExp(`login link for ${email}: \\S+#login=([\\w-]+)`, 'g'))].at(-1);
      const v = await c('POST', '/api/auth/verify', { token: m[1] });
      assert.equal(v.s, 200, 'verify');
      assert.equal((await client()('POST', '/api/auth/verify', { token: m[1] })).s, 403, 'link is single use');
    };
    const stamp = Date.now();
    const A = client(), B = client(), C = client();
    assert.equal((await A('GET', '/api/me')).s, 401, 'no session');
    await login(A, `a${stamp}@x.io`); await login(B, `b${stamp}@x.io`); await login(C, `c${stamp}@x.io`);

    const r0 = await fetch(`${U}/api/me`, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: '{}' });
    assert.equal(r0.status, 403, 'cross origin rejected');

    const ws = (await A('POST', '/api/workspaces', { name: 'Team' })).j.id, W = p => `/api/w/${ws}${p}`;
    assert.equal((await B('GET', W('/state'))).s, 404, 'tenant isolation');
    assert.equal((await B('GET', W('/files'))).s, 404, 'tenant isolation: files');

    const inv = (await A('POST', W('/invites'))).j.url.split('invite=')[1];
    assert.equal((await B('POST', '/api/invites/accept', { token: '__proto__' })).s, 403, 'fake invite');
    assert.equal((await B('POST', '/api/invites/accept', { token: inv })).s, 200);
    assert.equal((await C('POST', '/api/invites/accept', { token: inv })).s, 403, 'invite single use');
    assert.equal((await B('POST', W('/invites'))).s, 403, 'member cannot invite');
    assert.equal((await B('DELETE', W(''))).s, 403, 'member cannot delete workspace');

    for (const p of ['../x', '/etc/x', 'a/../../x', 'a/.claude/settings.json'])
      assert.equal((await A('PUT', W('/file'), { path: p, text: 'x' })).s, 400, p);

    // 내 컴퓨터 방식
    const added = (await B('POST', W('/agents'), { name: 'wk', mode: 'worker' })).j;
    assert.equal((await A('POST', W('/agents'), { name: 'wk', mode: 'worker' })).s, 400, 'duplicate name');
    const token = added.command.split(' ').at(-1);
    wrk = spawn('node', ['worker.js', U, token], { env, cwd: __dirname });
    await sleep(2200);
    const waitFor = async (text) => { for (let i = 0; i < 40; i++) { const s = (await A('GET', W('/state'))).j; if (s.messages.some(m => m.text === text)) return s; await sleep(250); } assert.fail('timeout waiting for ' + text); };
    await A('POST', W('/messages'), { text: '@wk 파일 만들어' });
    await waitFor('worker-done');
    const files = (await A('GET', W('/files'))).j;
    assert(files.includes('work/made.txt'), 'worker sync');
    assert(!files.includes('work/link'), 'symlink excluded');

    // 동시 수정 충돌과 되돌리기
    const f = (await A('GET', W('/file?path=work/made.txt'))).j;
    assert.equal((await A('PUT', W('/file'), { path: 'work/made.txt', text: 'edited', base: f.base })).s, 200);
    assert.equal((await B('PUT', W('/file'), { path: 'work/made.txt', text: 'stale', base: f.base })).s, 409, 'stale edit');
    const change = (await A('GET', W('/state'))).j.messages.filter(m => m.kind === 'change').at(-1);
    await B('POST', W('/revert'), { hist: change.hist });
    assert.equal((await A('GET', W('/file?path=work/made.txt'))).j.text, 'from-worker\n', 'revert');
    assert.equal((await C('POST', W('/revert'), { hist: change.hist })).s, 404, 'revert isolated');

    // API 키 방식
    assert.equal((await A('POST', W('/agents'), { name: 'bad', mode: 'api', apiKey: 'sk-ant-bad' })).s, 400, 'bad key');
    assert.equal((await A('POST', W('/agents'), { name: 'ap', mode: 'api', apiKey: 'sk-ant-good' })).s, 200);
    await A('POST', W('/messages'), { text: '@ap 노트 써줘' });
    await waitFor('api-done');
    assert.equal((await A('GET', W('/file?path=api/note.md'))).j.text, 'from-api', 'api write');
    assert(!(await A('GET', W('/files'))).j.includes('../escape'), 'api path blocked');
    const req = sent[0];
    assert.equal(req.model, 'claude-opus-5-5'); assert.equal(req.fallbacks, 'default');
    assert.equal(req.tools.every(t => t.strict), true);
    assert(!out.includes('sk-ant-good'), 'key not logged');
    const state = (await A('GET', W('/state'))).j;
    assert(!JSON.stringify(state).includes('sk-ant'), 'key not returned');

    // 제거
    const wk = state.agents.find(a => a.name === 'wk'), ap = state.agents.find(a => a.name === 'ap');
    const bMember = state.members.find(m => m.role === 'member');
    assert.equal((await B('DELETE', W('/agents/' + ap.id))).s, 403, 'cannot remove others agent');
    const exited = new Promise(r => wrk.on('exit', r));
    assert.equal((await B('DELETE', W('/agents/' + wk.id))).s, 200, 'creator removes own');
    await exited;
    assert.equal((await A('DELETE', W('/agents/' + ap.id))).s, 200);
    assert((await A('GET', W('/files'))).j.includes('api/note.md'), 'work kept');
    assert.equal((await B('DELETE', W('/members/' + state.members.find(m => m.role === 'owner').id))).s, 400, 'owner stays');
    assert.equal((await A('DELETE', W('/members/' + bMember.id))).s, 200);
    assert.equal((await B('GET', W('/state'))).s, 404, 'removed member loses access');
    assert.equal((await A('POST', '/api/auth/logout')).s, 200);
    assert.equal((await A('GET', '/api/me')).s, 401, 'logout');
    console.log('ok');
  } finally { srv.kill(); wrk && wrk.kill(); mock.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
})().catch(e => { console.error(e); process.exit(1); });
