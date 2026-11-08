#!/usr/bin/env node
// Clauduo 연결 프로그램: 작업공간을 임시 폴더로 받아 내 컴퓨터의 Claude로 작업하고 바뀐 파일만 돌려보낸다.
// 로그인 정보는 이 컴퓨터를 떠나지 않는다. 사용법: node worker.js <url> <token>
const fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto');
const { execFile } = require('child_process');

const JOB_TIMEOUT = 9.5 * 60e3;
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const sleep = ms => new Promise(r => setTimeout(r, ms));

// 신뢰 경계. .claude/.git/.mcp.json 차단: 공유 파일이 남의 Claude 설정(훅)이 되면 그 컴퓨터에서 코드가 실행된다.
function safeRel(p) {
  if (typeof p !== 'string' || !p || p.length > 500 || /[\\\0]/.test(p) || p.startsWith('/')) return null;
  const blocked = new Set(['.', '..', '.claude', '.git', '.mcp.json']);
  return p.split('/').every(s => s && !blocked.has(s)) ? p : null;
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

function runClaude(cwd, prompt, env) {
  // 프롬프트에는 남이 쓴 내용이 들어가므로 셸·웹 없이 파일 도구만 허용하고 작업공간의 설정은 읽지 않는다
  const args = ['-p', '--tools', 'Read,Edit,Write,Glob,Grep', '--permission-mode', 'acceptEdits',
    '--strict-mcp-config', '--setting-sources', '', '--no-session-persistence'];
  return new Promise(resolve => {
    const c = execFile(process.env.CLAUDE_BIN || 'claude', args, { cwd, env, timeout: JOB_TIMEOUT, maxBuffer: 2e7 }, (err, out, stderr) =>
      resolve(err ? { error: true, reply: `실행 실패: ${(stderr || out || err.message).slice(0, 500)}` } : { reply: out.trim() }));
    c.stdin.on('error', () => {});
    c.stdin.end(prompt);
  });
}

async function worker(url, token) {
  const api = async (method, body) => {
    const r = await fetch(url + '/api/worker/job', { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: body && JSON.stringify(body) });
    return { status: r.status, json: await r.json() };
  };
  console.log('Clauduo에 연결했어요. 이 창을 열어 두세요.');
  for (;;) {
    await sleep(1500);
    let res;
    try { res = await api('GET'); } catch { continue; }
    if (res.status === 401) return console.log('연결이 해제됐어요. 이 Claude가 워크스페이스에서 제거됐거나 토큰이 잘못됐어요.');
    const job = res.json;
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
      result = await runClaude(dir, job.prompt, process.env);
      const after = walk(dir), changes = [];
      for (const [rel, buf] of Object.entries(after))
        if (before[rel] !== sha(buf)) changes.push({ path: rel, data: buf.toString('base64') });
      for (const rel of Object.keys(before)) if (!after[rel]) changes.push({ path: rel, data: null });
      result.changes = changes;
    } catch (e) { result = { error: true, reply: `실행 실패: ${e.message}`, changes: [] }; }
    fs.rmSync(dir, { recursive: true, force: true });
    try { await api('POST', { id: job.id, ...result }); } catch (e) { console.error('결과 전송 실패', e.message); }
  }
}

module.exports = { safeRel, sha };
if (require.main === module) {
  const [url, token] = process.argv.slice(2);
  if (url && token) worker(url.replace(/\/$/, ''), token);
  else console.log('사용법: node worker.js <url> <token>');
}
