// node test-saas.js : wrangler dev(로컬 D1·Durable Object)와 가짜 Claude/Anthropic API로 전체 흐름을 확인한다
const { spawn } = require('child_process'), fs = require('fs'), os = require('os'), path = require('path'), http = require('http'), assert = require('assert');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'clauduo-saas-'));
const bin = path.join(tmp, 'claude');
fs.writeFileSync(bin, `#!/bin/sh
cat >/dev/null
echo "cfg=$CLAUDE_CONFIG_DIR args=$*" >> "${tmp}/cfg.log"
mkdir -p work
echo from-worker > work/made.txt
ln -s /etc/passwd work/link
mkdir -p artifacts; echo '<h1>hi</h1>' > artifacts/report.html
case "$*" in
  *stream-json*)
    echo '{"type":"system","subtype":"init","session_id":"sess-1"}'
    echo '{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"ls -la"}},{"type":"text","text":"partial"}]}}'
    echo '{"type":"result","is_error":false,"result":"worker-done","session_id":"sess-1"}' ;;
  *) echo worker-done ;;
esac
`, { mode: 0o755 });
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
  if (JSON.stringify(b.messages).includes('artifact-please') && b.messages.length === 1) return reply({ ...base, stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'a1', name: 'create_artifact', input: { title: 'cloud-art', html: '<p>x</p>' } }] });
  if (JSON.stringify(b.messages).includes('chat-only')) return reply({ ...base, stop_reason: 'end_turn', content: [{ type: 'text', text: b.tools.some(t => t.name === 'write_file') ? 'has-files' : 'no-files' }] });
  if (b.messages.length === 1) return reply({ ...base, stop_reason: 'tool_use', content: [
    { type: 'tool_use', id: 't1', name: 'write_file', input: { path: 'api/note.md', content: 'from-api' } },
    { type: 'tool_use', id: 't2', name: 'write_file', input: { path: '../escape', content: 'x' } }] });
  reply({ ...base, stop_reason: 'end_turn', content: [{ type: 'text', text: 'api-done' }] });
});

(async () => {
  await new Promise(r => mock.listen(MOCK, r));
  const env = { ...process.env, CLAUDE_BIN: bin };
  const vars = path.join(tmp, 'vars'), persist = path.join(tmp, 'state');
  fs.writeFileSync(vars, `BASE_URL=${U}\nDEV_LOG_MAIL=1\nANTHROPIC_BASE_URL=http://localhost:${MOCK}\nCLAUDUO_SECRET=test-secret\n`);
  require('child_process').execFileSync('npx', ['wrangler', 'd1', 'execute', 'clauduo', '--local', '--persist-to', persist, '--file', 'schema.sql'], { cwd: __dirname, stdio: 'ignore' });
  const srv = spawn('npx', ['wrangler', 'dev', '--port', String(PORT), '--persist-to', persist, '--env-file', vars], { env, cwd: __dirname, detached: true });
  let out = ''; srv.stdout.on('data', d => out += d); srv.stderr.on('data', d => out += d);
  let wrk;
  try {
    for (let i = 0; i < 300 && !out.includes('Ready on'); i++) await sleep(100);
    assert(out.includes('Ready on'), out);
    await sleep(1000);
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
      await sleep(400);
      const m = [...out.matchAll(new RegExp(`login link for ${email}: \\S+#login=([\\w-]+)`, 'g'))].at(-1);
      const v = await c('POST', '/api/auth/verify', { token: m[1] });
      assert.equal(v.s, 200, 'verify');
      assert.equal((await client()('POST', '/api/auth/verify', { token: m[1] })).s, 403, 'link is single use');
    };
    const stamp = Date.now();
    const A = client(), B = client(), C = client();
    assert.equal((await A('GET', '/api/me')).s, 401, 'no session');
    const CODE = client(), codeMail = `code${stamp}@x.io`;
    await CODE('POST', '/api/auth/request', { email: codeMail }); await sleep(400);
    const code = new RegExp(`login link for ${codeMail}: \\S+ code=(\\d{6})`).exec(out)[1];
    assert.equal((await CODE('POST', '/api/auth/verify', { email: codeMail, code: code === '000000' ? '111111' : '000000' })).s, 403, 'wrong code');
    assert.equal((await CODE('POST', '/api/auth/verify', { email: codeMail, code })).s, 200, 'code login');
    assert.equal((await CODE('GET', '/api/me')).s, 200, 'code session');
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
    wrk = spawn('node', ['public/worker.js', U, token], { env, cwd: __dirname });
    await sleep(2200);
    const waitFor = async (text) => { for (let i = 0; i < 40; i++) { const s = (await A('GET', W('/state'))).j; if (s.messages.some(m => m.text === text)) return s; await sleep(250); } assert.fail('timeout waiting for ' + text); };
    await A('POST', W('/messages'), { text: '@wk 파일 만들어' });
    await waitFor('worker-done');
    const files = (await A('GET', W('/files'))).j;
    assert(files.includes('work/made.txt'), 'worker sync');
    assert(!files.includes('work/link'), 'symlink excluded');

    // 하나의 공간: 로컬 실행 환경 권한
    const proj = path.join(tmp, 'proj'); fs.mkdirSync(proj); fs.writeFileSync(path.join(proj, 'old.txt'), 'old\n');
    const wkId = (await B('GET', W('/state'))).j.agents.find(a => a.name === 'wk').id;
    assert.equal((await B('POST', W('/threads'), { text: 'x', agentId: wkId, folder: proj })).s, 400, 'folder must be allowed');
    assert.equal((await fetch(`${U}/api/worker/folders`, { method: 'POST', headers: { authorization: 'Bearer nope.x', 'content-type': 'application/json' }, body: '{}' })).status, 401, 'folders auth');
    // 여러 계정 동시 실행: 계정별로 병렬, 같은 폴더는 순서대로
    const acct = async (name, folder) => {
      const add = (await B('POST', W('/agents'), { name, mode: 'worker' })).j, t = add.command.split(' ').at(-1);
      await fetch(`${U}/api/worker/folders`, { method: 'POST', headers: { authorization: `Bearer ${t}`, 'content-type': 'application/json' }, body: JSON.stringify({ folders: [folder] }) });
      return { id: add.id, t, folder, poll: async () => (await fetch(`${U}/api/worker/job?caps=local`, { headers: { authorization: `Bearer ${t}` } })).json(), done: id => fetch(`${U}/api/worker/job`, { method: 'POST', headers: { authorization: `Bearer ${t}`, 'content-type': 'application/json' }, body: JSON.stringify({ id, reply: 'ok' }) }) };
    };
    const [a1, a2, a3] = [await acct('acct1', '/f1'), await acct('acct2', '/f2'), await acct('acct3', '/f1')];
    for (const a of [a1, a2, a3]) assert.equal((await B('POST', W('/threads'), { text: 'go', agentId: a.id, folder: a.folder })).s, 200);
    const [j1, j2, j3] = [await a1.poll(), await a2.poll(), await a3.poll()];
    assert(j1.id && j2.id, 'accounts run in parallel');
    assert(!j3.id, 'same folder waits');
    await a1.done(j1.id);
    const j3b = await a3.poll();
    assert(j3b.id, 'same folder runs after release');
    await a2.done(j2.id); await a3.done(j3b.id);
    for (const a of [a1, a2, a3]) await B('DELETE', W('/agents/' + a.id));

    if (process.env.MAC_BIN) { // Mac 앱 엔진을 실제 바이너리로 확인
      wrk.kill(); await sleep(500);
      fs.mkdirSync(path.join(proj, 'artifacts')); fs.writeFileSync(path.join(proj, 'artifacts/old.html'), '<p>old</p>');
      wrk = spawn(process.env.MAC_BIN, ['--worker', U, token], { env: { ...env, CLAUDUO_FOLDERS: proj, CLAUDUO_CONFIG_DIR: '/acct-a', CLAUDE_CODE_OAUTH_TOKEN: 'leak' }, cwd: tmp });
      for (let i = 0; i < 40 && !(await B('GET', W('/state'))).j.agents.find(a => a.name === 'wk').folders.includes(proj); i++) await sleep(250);
      assert.equal((await A('POST', W('/threads'), { text: 'x', agentId: wkId, folder: proj })).s, 403, 'only the Mac owner can run');
      const made = await B('POST', W('/threads'), { text: 'mac-local-task', agentId: wkId, folder: proj });
      assert.equal(made.s, 200, 'local thread');
      let turns = [];
      for (let i = 0; i < 60 && turns.length < 2; i++) { turns = (await B('GET', W('/threads/' + made.j.id))).j.turns; await sleep(250); }
      assert.equal(turns[1].text, 'worker-done', 'local reply');
      assert(fs.readFileSync(path.join(tmp, 'cfg.log'), 'utf8').includes('cfg=/acct-a'), 'account login folder used');
      assert(turns[1].files.some(f => f.path === 'work/made.txt' && f.status === 'added' && f.diff.includes('from-worker')), 'local diff');
      assert(!turns[1].files.some(f => f.path === 'work/link'), 'symlink skipped');
      assert.equal((await A('GET', W('/threads/' + made.j.id))).j.turns.length, 2, 'teammates can see local work');
      assert.equal((await A('POST', W('/threads/' + made.j.id + '/messages'), { text: 'x' })).s, 403, 'only starter continues');
      assert.equal((await C('GET', W('/threads/' + made.j.id))).s, 404, 'thread isolated');
      assert(fs.existsSync(path.join(proj, 'work/made.txt')), 'ran in real folder');
      assert(turns[1].tools.some(x => x.includes('Bash: ls -la')), 'tool activity recorded');
      assert((await B('GET', W('/artifacts'))).j.some(a => a.title === 'proj/artifacts/report' && a.source === 'local'), 'local artifact');
      assert((await B('GET', W('/artifacts'))).j.some(a => a.title === 'proj/artifacts/old' && a.source === 'local'), 'existing local artifact imported');
      const lc = await B('POST', W('/threads'), { text: '맥 채팅', agentId: wkId, kind: 'chat' });
      assert.equal(lc.s, 200, 'local chat');
      let lt = []; for (let i = 0; i < 60 && lt.length < 2; i++) { lt = (await B('GET', W('/threads/' + lc.j.id))).j.turns; await sleep(250); }
      assert.equal(lt[1].text, 'worker-done', 'local chat reply'); assert.equal(lt[1].files.length, 0, 'chat hides files');
      assert(!/--tools|--strict-mcp|--setting-sources/.test(fs.readFileSync(path.join(tmp, 'cfg.log'), 'utf8').split('\n').filter(l => l.includes('stream-json')).join('')), 'full Claude Code');
      assert.equal((await B('POST', W('/threads/' + made.j.id + '/messages'), { text: '이어서' })).s, 200);
      for (let i = 0; i < 60 && turns.length < 4; i++) { turns = (await B('GET', W('/threads/' + made.j.id))).j.turns; await sleep(250); }
      assert(fs.readFileSync(path.join(tmp, 'cfg.log'), 'utf8').includes('--resume sess-1'), 'session resumed');
      const bp = await B('POST', W('/threads'), { text: 'x', agentId: wkId, folder: proj, mode: 'bypassPermissions' });
      let bt = [];
      for (let i = 0; i < 60 && bt.length < 2; i++) { bt = (await B('GET', W('/threads/' + bp.j.id))).j.turns; await sleep(250); }
      assert(bt[1].role === 'error' && bt[1].text.includes('전체 권한'), 'bypass needs Mac opt-in');
      const sid = '11111111-2222-3333-4444-555555555555', imp = path.join(tmp, 'imp/projects/-p');
      fs.mkdirSync(imp, { recursive: true });
      const u = (type, content, extra = {}) => JSON.stringify({ type, cwd: proj, sessionId: sid, message: { content }, ...extra });
      fs.writeFileSync(path.join(imp, sid + '.jsonl'), [
        u('user', '가져올 첫 질문'),
        u('user', [{ type: 'text', text: '<system-reminder>숨김</system-reminder>' }]),
        u('user', '서브에이전트 내용', { isSidechain: true }),
        u('assistant', [{ type: 'thinking', thinking: 'x' }]),
        u('assistant', [{ type: 'text', text: '답변 일부' }]),
        u('assistant', [{ type: 'tool_use', name: 'Bash', input: { command: 'pwd' } }]),
        JSON.stringify({ type: 'custom-title', customTitle: '내 세션 제목' }),
      ].join('\n') + '\n');
      require('child_process').execFileSync(process.env.MAC_BIN, ['--import', U, token, path.join(tmp, 'imp')], { env, stdio: 'ignore' });
      const impId = 'imp-' + sid, it = (await B('GET', W('/threads/' + impId))).j;
      assert.equal(it.turns.length, 2, 'import filters hidden events');
      assert.equal(it.turns[0].text, '가져올 첫 질문'); assert.equal(it.turns[1].text, '답변 일부');
      assert(it.turns[1].tools.some(x => x.includes('Bash: pwd')), 'import tools');
      assert((await B('GET', W('/state'))).j.threads.find(t => t.id === impId).title === '내 세션 제목', 'import title');
      assert.equal((await A('GET', W('/threads/' + impId))).s, 404, 'imported session is private');
      assert(!(await A('GET', W('/state'))).j.threads.some(t => t.id === impId), 'hidden from teammates');
      assert.equal((await A('GET', W('/search?q=') + encodeURIComponent('가져올'))).j.length, 0, 'hidden from search');
      assert.equal((await B('POST', W('/threads/' + impId + '/messages'), { text: '이어서' })).s, 200);
      for (let i = 0; i < 60 && it.turns.length < 4; i++) { Object.assign(it, (await B('GET', W('/threads/' + impId))).j); await sleep(250); }
      assert(fs.readFileSync(path.join(tmp, 'cfg.log'), 'utf8').includes('--resume ' + sid), 'imported session resumes');

      await A('POST', W('/messages'), { text: '@wk 다시 만들어' });
      for (let i = 0; i < 40; i++) { if ((await A('GET', W('/state'))).j.messages.filter(m => m.text === 'worker-done').length >= 2) break; await sleep(250); }
      assert((await A('GET', W('/state'))).j.messages.filter(m => m.text === 'worker-done').length >= 2, 'mac room job');
    }

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
    assert.equal(req.tools.filter(t => t.input_schema).every(t => t.strict), true);
    assert(req.tools.some(t => t.name === 'web_search'), 'cloud web tools');
    assert(!out.includes('sk-ant-good'), 'key not logged');
    const state = (await A('GET', W('/state'))).j;
    assert(!JSON.stringify(state).includes('sk-ant'), 'key not returned');
    const apId = state.agents.find(a => a.name === 'ap').id;
    const ct = (await A('POST', W('/threads'), { text: '클라우드 노트', agentId: apId })).j.id;
    let ctTurns = [];
    for (let i = 0; i < 60 && ctTurns.length < 2; i++) { ctTurns = (await A('GET', W('/threads/' + ct))).j.turns; await sleep(250); }
    assert.equal(ctTurns[1].text, 'api-done', 'cloud thread');
    const listed = (await A('GET', W('/state'))).j.threads.find(t => t.id === ct);
    assert.equal(listed.env, 'cloud'); assert.equal(listed.busy, false);
    const waitTurns = async id => { let t = []; for (let i = 0; i < 60 && t.length < 2; i++) { t = (await A('GET', W('/threads/' + id))).j.turns || []; await sleep(250); } return t; };
    const chatT = (await A('POST', W('/threads'), { text: 'chat-only 질문', agentId: apId, kind: 'chat' })).j.id;
    assert.equal((await waitTurns(chatT))[1].text, 'no-files', 'chat has no file tools');
    assert.equal((await A('GET', W('/state'))).j.threads.find(t => t.id === chatT).kind, 'chat');
    const artT = (await A('POST', W('/threads'), { text: 'artifact-please', agentId: apId })).j.id;
    await waitTurns(artT);
    const arts = (await A('GET', W('/artifacts'))).j, art = arts.find(a => a.title === 'cloud-art');
    assert(art && art.source === 'cloud', 'cloud artifact');
    await A('PUT', W('/file'), { path: 'site/page.html', text: '<p>shared</p>' });
    const sh = (await A('GET', W('/artifacts'))).j.find(a => a.title === 'site/page.html');
    assert(sh && sh.source === 'cloud', 'shared html listed');
    assert.equal((await A('GET', W('/artifacts/' + encodeURIComponent(sh.id)))).j.html, '<p>shared</p>', 'shared html opens'); assert.equal((await A('GET', W('/artifacts/' + art.id))).j.html, '<p>x</p>');
    assert.equal((await C('GET', W('/artifacts'))).s, 404, 'artifacts isolated');
    assert.equal((await A('GET', W('/search?q=') + encodeURIComponent('클라우드'))).j[0].id, ct, 'search');
    assert.equal((await A('GET', W('/search?q=%25'))).j.length, 0, 'search escapes wildcards');
    assert.equal((await B('POST', W('/instructions'), { text: 'x' })).s, 403, 'instructions owner only');
    assert.equal((await A('POST', W('/instructions'), { text: '항상 존댓말' })).s, 200);
    const sch = await A('POST', W('/schedules'), { prompt: '예약 실행', agentId: apId, interval: 60, nextAt: Date.now() + 500 });
    assert.equal(sch.s, 200, 'schedule');
    assert.equal((await A('POST', W('/schedules'), { prompt: 'x', agentId: apId, interval: 7, nextAt: Date.now() })).s, 400, 'bad interval');
    let fired;
    for (let i = 0; i < 40 && !(fired = (await A('GET', W('/state'))).j.threads.find(t => t.title === '예약 실행')); i++) await sleep(250);
    assert(fired, 'schedule fired');
    assert((await waitTurns(fired.id)).length >= 2, 'scheduled run finished');
    assert(sent.some(r => r.system.includes('항상 존댓말')), 'instructions applied');
    const list = (await A('GET', W('/schedules'))).j[0];
    assert(list.next_at > Date.now() + 50 * 60e3, 'schedule rescheduled');
    assert.equal((await A('DELETE', W('/schedules/' + sch.j.id))).s, 200);
    assert.equal((await A('DELETE', W('/threads/' + ct))).s, 200);

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
  } finally { try { process.kill(-srv.pid); } catch {} wrk && wrk.kill(); mock.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
})().catch(e => { console.error(e); process.exit(1); });
