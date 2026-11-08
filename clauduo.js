#!/usr/bin/env node
// Clauduo: 여러 Claude 계정이 한 방에서 대화하고 같은 작업공간을 고치는 앱. 의존성 없음.
//   node clauduo.js serve                 서버 + 로컬 계정 실행
//   node clauduo.js worker <url> <token>  초대받은 쪽: 내 Claude 로그인으로 참여
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const crypto = require('crypto'), { execFile, spawn } = require('child_process');

const DATA = process.env.CLAUDUO_DATA || path.join(__dirname, 'data');
const WS = path.join(DATA, 'workspace'), HIST = path.join(DATA, 'history'), ACC = path.join(DATA, 'accounts');
const STATE = path.join(DATA, 'state.json');
const CLAUDE = process.env.CLAUDE_BIN || 'claude';
const MAX_FILE = 5e6, MAX_BODY = 1e8, MAX_CHAIN = 6, JOB_TIMEOUT = 10 * 60e3, INVITE_TTL = 24 * 3600e3;
const NAME = /^[\w가-힣-]{1,30}$/;

const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const rand = () => crypto.randomBytes(24).toString('base64url');
const sleep = ms => new Promise(r => setTimeout(r, ms));

// 서버와 워커 양쪽의 신뢰 경계. .claude/.git 차단: 공유 파일이 남의 Claude 설정(훅)이 되면 코드 실행이 된다.
function safeRel(p) {
  if (typeof p !== 'string' || !p || p.length > 500 || /[\\\0]/.test(p) || p.startsWith('/')) return null;
  const parts = p.split('/');
  return parts.every(s => s && s !== '.' && s !== '..' && s !== '.claude' && s !== '.git' && s !== '.mcp.json') ? p : null;
}

function walk(root, rel = '', out = Object.create(null)) {
  for (const e of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
    const r = rel ? rel + '/' + e.name : e.name;
    if (!safeRel(r)) continue;
    if (e.isDirectory()) walk(root, r, out);
    else if (e.isFile()) out[r] = fs.readFileSync(path.join(root, r)); // 심볼릭 링크는 일부러 제외
  }
  return out;
}

// ---- 서버 ----
function serve() {
  for (const d of [WS, HIST, ACC]) fs.mkdirSync(d, { recursive: true });
  const db = fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, 'utf8'))
    : { seq: 0, members: [{ name: 'owner', token: rand(), owner: true }], invites: {}, messages: [], history: {} };
  const save = () => { fs.writeFileSync(STATE + '.tmp', JSON.stringify(db), { mode: 0o600 }); fs.renameSync(STATE + '.tmp', STATE); };
  save();

  const seen = {}, queue = []; let running = null;
  const running_ok = () => { if (running && Date.now() - running.at > JOB_TIMEOUT) running = null; return !running; };
  const online = n => Date.now() - (seen[n] || 0) < 5000;
  const post = (from, text, extra = {}) => { const m = { id: ++db.seq, at: Date.now(), from, text, ...extra }; db.messages.push(m); save(); return m; };

  function mentions(from, text, depth) {
    if (depth > MAX_CHAIN) return post('system', `대화 연쇄가 ${MAX_CHAIN}번을 넘어 멈췄어요. 이어가려면 다시 멘션해 주세요.`);
    const names = db.members.filter(m => m.name !== from && m.claude).map(m => m.name);
    const hit = /@(all|모두)(?![\w가-힣-])/.test(text) ? names.filter(online)
      : names.filter(n => new RegExp(`@${n}(?![\\w가-힣-])`).test(text));
    for (const to of hit) if (!queue.some(j => j.to === to)) queue.push({ to, depth });
  }

  function write(rel, buf, by) { // buf=null이면 삭제. 이전 내용은 항상 남겨서 되돌릴 수 있게 한다.
    const abs = path.join(WS, rel), existed = fs.existsSync(abs), id = ++db.seq;
    if (existed) fs.copyFileSync(abs, path.join(HIST, String(id)));
    db.history[id] = { path: rel, existed };
    if (buf) { fs.mkdirSync(path.dirname(abs), { recursive: true }); fs.writeFileSync(abs, buf); }
    else if (existed) fs.unlinkSync(abs);
    post(by, `${rel} ${buf ? (existed ? '수정' : '생성') : '삭제'}`, { kind: 'change', hist: id });
  }

  function addMember(name, extra) {
    const m = { name, token: rand(), ...extra };
    db.members.push(m); fs.mkdirSync(path.join(WS, name), { recursive: true });
    post('system', `${name} 님이 참여했어요.`);
    return m;
  }

  function buildJob(me, j) {
    const files = walk(WS), base = Object.create(null), wire = Object.create(null);
    for (const [k, v] of Object.entries(files)) { base[k] = sha(v); wire[k] = v.toString('base64'); }
    const log = db.messages.slice(-40).map(m => m.kind === 'change' ? `[변경] ${m.from}: ${m.text}` : `${m.from}: ${m.text}`).join('\n');
    const others = db.members.filter(m => m.name !== me.name).map(m => m.name).join(', ');
    const prompt = `너는 공유 작업방 Clauduo의 멤버 "${me.name}"야. 다른 멤버: ${others}.
현재 디렉터리가 공유 작업공간이고, 멤버별 폴더가 있어(네 폴더: ${me.name}/). 요청받으면 다른 멤버 폴더도 읽고 고칠 수 있어.
다른 Claude 멤버의 답이 꼭 필요할 때만 답변에 @이름을 써. 할 말이 끝났으면 멘션하지 마.
답변은 대화방에 그대로 올라가니 짧게 써. 아래는 대화 기록이고, 너를 멘션한 가장 최근 메시지에 답해.

${log}`;
    running = { id: rand(), to: me.name, depth: j.depth, base, at: Date.now() };
    return { id: running.id, prompt, files: wire };
  }

  function finishJob(me, b) {
    const job = running; running = null;
    for (const c of Array.isArray(b.changes) ? b.changes : []) {
      let rel = safeRel(c.path); if (!rel || (c.data != null && typeof c.data !== 'string')) continue;
      const buf = c.data == null ? null : Buffer.from(c.data, 'base64');
      if (buf && buf.length > MAX_FILE) continue;
      try { // 파일 하나가 실패해도(파일↔폴더 충돌 등) Claude의 답변은 잃지 않는다
        const abs = path.join(WS, rel), cur = fs.existsSync(abs) ? sha(fs.readFileSync(abs)) : undefined;
        if (cur !== job.base[rel]) { // 작업 중 다른 사람이 고친 파일은 덮어쓰지 않는다
          if (!buf) continue;
          rel = `${rel}.${me.name}-conflict`;
        }
        write(rel, buf, me.name);
      } catch (e) { post('system', `${rel} 반영 실패: ${e.code || '오류'}`); }
    }
    const reply = String(b.reply || '').slice(0, 20000);
    post(me.name, reply || '(답변 없음)', b.error ? { kind: 'error' } : {});
    if (!b.error) mentions(me.name, reply, job.depth + 1);
  }

  function loginAccount(name, email) {
    const config = path.join(ACC, name);
    fs.mkdirSync(config, { recursive: true, mode: 0o700 });
    const args = ['auth', 'login', ...(email ? ['--email', email] : [])];
    const c = spawn(CLAUDE, args, { env: accountEnv(config), stdio: 'ignore' });
    const done = ok => {
      if (!ok) { fs.rmSync(config, { recursive: true, force: true }); return post('system', `${name} 로그인에 실패했어요.`); }
      const m = addMember(name, { local: true, claude: true }); save();
      worker(`http://127.0.0.1:${PORT}`, m.token, config);
    };
    c.on('exit', code => done(code === 0)); c.on('error', () => done(false));
  }

  function removeMember(m) {
    db.members = db.members.filter(x => x !== m); // 토큰이 무효화되면 워커는 스스로 종료한다
    for (let i = queue.length - 1; i >= 0; i--) if (queue[i].to === m.name) queue.splice(i, 1);
    if (running && running.to === m.name) running = null;
    post('system', `${m.name} 님을 제거했어요. ${m.name}/ 폴더의 파일은 남아 있어요.`);
    if (!m.local) return;
    const config = path.join(ACC, m.name), wipe = () => fs.rmSync(config, { recursive: true, force: true });
    const c = spawn(CLAUDE, ['auth', 'logout'], { env: accountEnv(config), stdio: 'ignore' });
    c.on('exit', wipe); c.on('error', wipe);
  }

  const server = http.createServer(async (req, res) => {
    const send = (code, o) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    try {
      const u = new URL(req.url, 'http://x'), p = u.pathname;
      if (req.method === 'GET' && p === '/') { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(path.join(__dirname, 'index.html'))); }
      if (req.method === 'GET' && p === '/clauduo.js') { res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }); return res.end(fs.readFileSync(__filename)); }

      let body = {};
      if (req.method !== 'GET') {
        const chunks = []; let n = 0;
        for await (const c of req) { n += c.length; if (n > MAX_BODY) return send(413, { error: '너무 커요' }); chunks.push(c); }
        body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
      }

      if (p === '/api/join' && req.method === 'POST') {
        // hasOwn 필수: "__proto__" 같은 값이 초대 코드로 통과하면 안 된다
        const valid = typeof body.invite === 'string' && Object.hasOwn(db.invites, body.invite);
        if (!valid || Date.now() - db.invites[body.invite] > INVITE_TTL) return send(403, { error: '초대 링크가 만료됐거나 이미 사용됐어요' });
        if (!NAME.test(body.name || '') || ['all', '모두', 'system'].includes(body.name) || db.members.some(m => m.name === body.name)) return send(400, { error: '쓸 수 없는 이름이에요' });
        delete db.invites[body.invite];
        const m = addMember(body.name, { claude: true }); save();
        return send(200, { token: m.token });
      }

      const token = (req.headers.authorization || '').replace('Bearer ', '');
      const me = db.members.find(m => m.token === token);
      if (!me) return send(401, { error: '인증 실패' });

      if (p === '/api/state') {
        return send(200, {
          me: { name: me.name, owner: !!me.owner },
          running: running && running.to, queued: queue.map(j => j.to),
          changes: db.messages.filter(m => m.kind === 'change').length,
          members: db.members.map(m => ({ name: m.name, owner: !!m.owner, local: !!m.local, claude: !!m.claude, online: online(m.name) })),
          messages: db.messages.filter(m => m.id > +u.searchParams.get('since')).slice(-300),
        });
      }
      if (p === '/api/messages' && req.method === 'POST') {
        const text = String(body.text || '').trim().slice(0, 20000);
        if (!text) return send(400, { error: '빈 메시지' });
        post(me.name, text); mentions(me.name, text, 0);
        return send(200, {});
      }
      if (p === '/api/invites' && req.method === 'POST') {
        if (!me.owner) return send(403, { error: '방장만 할 수 있어요' });
        const invite = rand(); db.invites[invite] = Date.now(); save();
        const proto = req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
        return send(200, { url: `${proto}://${req.headers.host}/#invite=${invite}` });
      }
      if (p === '/api/accounts' && req.method === 'POST') {
        if (!me.owner) return send(403, { error: '방장만 할 수 있어요' });
        if (!NAME.test(body.name || '') || ['all', '모두', 'system'].includes(body.name) || db.members.some(m => m.name === body.name)) return send(400, { error: '쓸 수 없는 이름이에요' });
        loginAccount(body.name, typeof body.email === 'string' && body.email.includes('@') && !body.email.startsWith('-') ? body.email : '');
        return send(200, {});
      }
      if (p === '/api/members' && req.method === 'DELETE') {
        if (!me.owner) return send(403, { error: '방장만 할 수 있어요' });
        const m = db.members.find(x => x.name === body.name);
        if (!m) return send(404, { error: '없는 멤버예요' });
        if (m.owner) return send(400, { error: '방장은 제거할 수 없어요' });
        removeMember(m);
        return send(200, {});
      }
      if (p === '/api/files') return send(200, Object.keys(walk(WS)).sort());
      if (p === '/api/file') {
        const rel = safeRel(req.method === 'GET' ? u.searchParams.get('path') : body.path);
        if (!rel) return send(400, { error: '잘못된 경로' });
        const abs = path.join(WS, rel), exists = fs.existsSync(abs);
        if (req.method === 'GET') {
          if (!exists) return send(404, { error: '없는 파일' });
          const b = fs.readFileSync(abs), text = !b.includes(0);
          return send(200, { text: text ? b.toString('utf8') : null, base: sha(b) });
        }
        if (exists && body.base !== sha(fs.readFileSync(abs))) return send(409, { error: '그 사이 다른 멤버가 고쳤어요. 다시 열어 주세요.' });
        if (req.method === 'PUT') {
          const buf = Buffer.from(String(body.text ?? ''));
          if (buf.length > MAX_FILE) return send(413, { error: '파일이 너무 커요' });
          write(rel, buf, me.name);
        } else if (req.method === 'DELETE') write(rel, null, me.name);
        return send(200, {});
      }
      if (p === '/api/revert' && req.method === 'POST') {
        if (!Object.hasOwn(db.history, String(body.hist))) return send(404, { error: '기록 없음' });
        const h = db.history[body.hist];
        write(h.path, h.existed ? fs.readFileSync(path.join(HIST, String(body.hist))) : null, me.name);
        return send(200, {});
      }
      if (p === '/api/job' && req.method === 'GET') {
        seen[me.name] = Date.now();
        if (!me.claude || !running_ok()) return send(200, {});
        const i = queue.findIndex(j => j.to === me.name);
        if (i < 0) return send(200, {});
        return send(200, buildJob(me, queue.splice(i, 1)[0]));
      }
      if (p === '/api/job' && req.method === 'POST') {
        if (!running || running.id !== body.id || running.to !== me.name) return send(409, { error: '만료된 작업' });
        finishJob(me, body);
        return send(200, {});
      }
      send(404, { error: '없음' });
    } catch (e) { console.error(e); if (!res.headersSent) send(500, { error: '서버 오류' }); else res.end(); }
  });

  const HOST = process.env.HOST || '127.0.0.1';
  server.listen(PORT, HOST, () => {
    console.log(`Clauduo 실행 중 (방장 전용 링크, 공유 금지):\nhttp://127.0.0.1:${PORT}/#t=${db.members[0].token}`);
    for (const m of db.members) if (m.local) worker(`http://127.0.0.1:${PORT}`, m.token, path.join(ACC, m.name));
  });
}
const PORT = +process.env.PORT || 4310;

// ---- 워커: 작업공간을 임시 폴더로 받아 Claude를 돌리고 바뀐 파일만 돌려준다 ----
function accountEnv(config) {
  const env = { ...process.env, CLAUDE_CONFIG_DIR: config };
  // 부모 셸의 자격증명이 남아 있으면 모든 계정이 같은 계정으로 실행된다
  delete env.CLAUDE_CODE_OAUTH_TOKEN; delete env.ANTHROPIC_API_KEY; delete env.ANTHROPIC_AUTH_TOKEN;
  return env;
}

function runClaude(cwd, prompt, env) {
  // 프롬프트에는 남이 쓴 내용이 들어가므로 쉘·웹 없이 파일 도구만 허용하고 작업공간의 설정은 읽지 않는다
  const args = ['-p', '--tools', 'Read,Edit,Write,Glob,Grep', '--permission-mode', 'acceptEdits',
    '--strict-mcp-config', '--setting-sources', '', '--no-session-persistence'];
  return new Promise(resolve => {
    const c = execFile(CLAUDE, args, { cwd, env, timeout: JOB_TIMEOUT - 30e3, maxBuffer: 2e7 }, (err, out, stderr) =>
      resolve(err ? { error: true, reply: `실행 실패: ${(stderr || out || err.message).slice(0, 500)}` } : { reply: out.trim() }));
    c.stdin.end(prompt);
  });
}

async function worker(url, token, config) {
  const api = async (method, p, body) => (await fetch(url + p, {
    method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: body && JSON.stringify(body),
  })).json();
  const env = config ? accountEnv(config) : process.env;
  for (;;) {
    await sleep(1500);
    let job;
    try { job = await api('GET', '/api/job'); } catch { continue; }
    if (job.error === '인증 실패') return console.log('방에서 제거되어 연결을 종료했어요.');
    if (!job.id) continue;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clauduo-'));
    let result;
    try {
      const before = Object.create(null);
      for (const [rel, b64] of Object.entries(job.files)) {
        if (!safeRel(rel)) continue;
        const buf = Buffer.from(b64, 'base64'), abs = path.join(dir, rel);
        fs.mkdirSync(path.dirname(abs), { recursive: true }); fs.writeFileSync(abs, buf);
        before[rel] = sha(buf);
      }
      result = await runClaude(dir, job.prompt, env);
      const after = walk(dir), changes = [];
      for (const [rel, buf] of Object.entries(after))
        if (before[rel] !== sha(buf)) changes.push({ path: rel, data: buf.toString('base64') });
      for (const rel of Object.keys(before)) if (!after[rel]) changes.push({ path: rel, data: null });
      result.changes = changes;
    } catch (e) { result = { error: true, reply: `실행 실패: ${e.message}`, changes: [] }; }
    fs.rmSync(dir, { recursive: true, force: true });
    try { await api('POST', '/api/job', { id: job.id, ...result }); } catch (e) { console.error('결과 전송 실패', e.message); }
  }
}

const [cmd, a, b] = process.argv.slice(2);
if (cmd === 'serve') serve();
else if (cmd === 'worker' && a && b) { console.log('참여 중. 이 창을 열어 두세요.'); worker(a.replace(/\/$/, ''), b); }
else console.log('사용법: node clauduo.js serve | node clauduo.js worker <url> <token>');
