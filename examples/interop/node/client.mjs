// Independent Node clients and TCP lifecycle probes. No Donna libraries used.
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import fs from 'node:fs';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { Resolver } from 'node:dns/promises';

const host = process.env.DONNA_HOST ?? '172.29.53.10';
const ca = fs.readFileSync('/certs/cert.pem');
const timeout = 3000;
const name = 'WwW.ExAmPlE.TeSt';

function query(bits, id = 42000, payload = 1232) {
  const labels = name.split('.').flatMap(label => [Buffer.from([label.length]), Buffer.from(label)]);
  const question = Buffer.concat([...labels, Buffer.from([0, 0, 1, 0, 1])]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(bits & 0x0130, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 10);
  const opt = Buffer.from([0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0]);
  opt.writeUInt16BE(payload, 3);
  opt.writeUInt16BE(bits & 0x8000, 7);
  return Buffer.concat([header, question, opt]);
}

function nameEnd(wire, offset) {
  let cursor = offset;
  for (let labels = 0; labels < 128; labels++) {
    const length = wire[cursor++];
    assert.notEqual(length, undefined);
    if (length === 0) return cursor;
    if ((length & 0xc0) === 0xc0) { assert.ok(cursor < wire.length); return cursor + 1; }
    assert.ok(length < 64);
    cursor += length;
    assert.ok(cursor <= wire.length, 'truncated DNS label');
  }
  throw Error('too many DNS labels');
}

function validate(wire, request) {
  assert.ok(wire.length >= 12);
  assert.equal(wire.readUInt16BE(0), request.readUInt16BE(0));
  const flags = wire.readUInt16BE(2);
  assert.equal(flags & 0x868f, 0x8400, 'QR/AA set; TC/RA/RCODE clear');
  assert.equal(flags & 0x0030, 0, 'authoritative AD/CD clear');
  assert.equal(flags & 0x0100, request.readUInt16BE(2) & 0x0100, 'RD copied');
  assert.equal(wire.readUInt16BE(4), 1);
  const end = nameEnd(wire, 12) + 4;
  assert.deepEqual(wire.subarray(12, end), request.subarray(12, end), 'question case preserved');
  let cursor = end;
  let found = false;
  let optCount = 0;
  for (const countOffset of [6, 8, 10]) {
    for (let remaining = wire.readUInt16BE(countOffset); remaining; remaining--) {
      cursor = nameEnd(wire, cursor);
      assert.ok(cursor + 10 <= wire.length, 'truncated record');
      const type = wire.readUInt16BE(cursor);
      const length = wire.readUInt16BE(cursor + 8);
      assert.ok(cursor + 10 + length <= wire.length, 'truncated record data');
      const data = wire.subarray(cursor + 10, cursor + 10 + length);
      if (countOffset === 6 && type === 1 && data.equals(Buffer.from([192, 0, 2, 80]))) found = true;
      if (type === 41) {
        assert.equal(countOffset, 10, 'OPT belongs in the additional section');
        assert.equal(wire.readUInt16BE(cursor + 6) & 0x8000,
          request.readUInt16BE(request.length - 4) & 0x8000, 'DO copied');
        optCount++;
      }
      cursor += 10 + length;
    }
  }
  assert.equal(cursor, wire.length, 'trailing DNS response data');
  assert.equal(optCount, 1, 'exactly one response OPT');
  assert.ok(found, 'answer includes expected address');
}

function validateAnswers(answers, requests) {
  assert.equal(answers.length, requests.length);
  const pending = new Map(requests.map(request => [request.readUInt16BE(0), request]));
  assert.equal(pending.size, requests.length, 'unique in-flight IDs');
  for (const answer of answers) {
    const id = answer.readUInt16BE(0);
    assert.ok(pending.has(id), 'unknown or duplicate response ID');
    validate(answer, pending.get(id));
    pending.delete(id);
  }
  assert.equal(pending.size, 0, 'all queries answered');
}

function udp(request) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let finished = false;
    const timer = setTimeout(() => finish(Error('UDP timeout')), timeout);
    function finish(error, data) {
      if (finished) return;
      finished = true; clearTimeout(timer); socket.close(); error ? reject(error) : resolve(data);
    }
    socket.on('error', finish);
    socket.once('message', data => finish(null, data));
    socket.connect(5300, host, () => socket.send(request));
  });
}

function framedRequests(requests, { encrypted = false, fragments = false, halfClose = false } = {}) {
  return new Promise((resolve, reject) => {
    const socket = encrypted
      ? tls.connect({ host, port: 8530, servername: 'localhost', ca, minVersion: 'TLSv1.3', ALPNProtocols: ['dot'] })
      : net.connect({ host, port: 5300 });
    let buffered = Buffer.alloc(0);
    const answers = [];
    let finished = false;
    function finish(error) { if (finished) return; finished = true; socket.destroy(); error ? reject(error) : resolve(answers); }
    socket.setTimeout(timeout, () => finish(Error('stream timeout')));
    socket.on('error', finish);
    socket.on('end', () => { if (answers.length !== requests.length) finish(Error('premature EOF')); });
    socket.on('data', chunk => {
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length >= 2 && buffered.length >= buffered.readUInt16BE(0) + 2) {
        const length = buffered.readUInt16BE(0);
        answers.push(buffered.subarray(2, length + 2));
        buffered = buffered.subarray(length + 2);
      }
      if (answers.length === requests.length) finish();
    });
    socket.once(encrypted ? 'secureConnect' : 'connect', async () => {
      const frames = requests.map(request => {
        const prefix = Buffer.alloc(2); prefix.writeUInt16BE(request.length);
        return Buffer.concat([prefix, request]);
      });
      const bytes = Buffer.concat(frames);
      if (fragments) {
        for (let offset = 0; offset < bytes.length && !finished; offset++) {
          socket.write(bytes.subarray(offset, offset + 1));
          await new Promise(resolve => setTimeout(resolve, 1));
        }
      } else socket.write(bytes);
      if (halfClose && !finished) socket.end();
    });
  });
}

function doh(request, method) {
  return new Promise((resolve, reject) => {
    const session = http2.connect(`https://${host}:8443`, { ca, servername: 'localhost', minVersion: 'TLSv1.3' });
    let finished = false;
    function finish(error, bytes) { if (finished) return; finished = true; clearTimeout(timer); session.destroy(); error ? reject(error) : resolve(bytes); }
    const timer = setTimeout(() => finish(Error('HTTP/2 timeout')), timeout);
    session.on('error', finish);
    const path = method === 'GET' ? `/dns-query?dns=${request.toString('base64url')}` : '/dns-query';
    const stream = session.request({ ':method': method, ':path': path, 'content-type': 'application/dns-message' });
    const chunks = [];
    stream.on('response', headers => {
      try { assert.equal(headers[':status'], 200); } catch (error) { finish(error); }
    });
    stream.on('error', finish);
    stream.on('data', chunk => chunks.push(chunk));
    stream.on('end', () => finish(null, Buffer.concat(chunks)));
    stream.end(method === 'POST' ? request : undefined);
  });
}

async function aborts() {
  for (const bytes of [Buffer.alloc(0), Buffer.from([0]), Buffer.from([255, 255, 0]), Buffer.from([0, 0])]) {
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host, port: 5300 });
      socket.setTimeout(timeout, () => { socket.destroy(); reject(Error('abort connect timeout')); });
      socket.on('error', reject);
      socket.once('connect', () => socket.write(bytes, () => { socket.destroy(); resolve(); }));
    });
    const request = query(0x100);
    validate(await udp(request), request);
  }
}

let checks = 0;
for (let mask = 0; mask < 16; mask++) {
  const bits = (mask & 1 ? 0x100 : 0) | (mask & 2 ? 0x10 : 0)
    | (mask & 4 ? 0x20 : 0) | (mask & 8 ? 0x8000 : 0);
  const request = query(bits);
  for (const transport of [udp, async wire => (await framedRequests([wire]))[0],
    async wire => (await framedRequests([wire], { encrypted: true }))[0],
    wire => doh(wire, 'GET'), wire => doh(wire, 'POST')]) {
    validate(await transport(request), request); checks++;
  }
}
const pipeline = Array.from({ length: 12 }, (_, index) => query(0x100, 43000 + index));
for (const options of [{}, { fragments: true }, { halfClose: true }, { encrypted: true, fragments: true }]) {
  const answers = await framedRequests(pipeline, options);
  // RFC 7766 section 7 allows replies to arrive in a different order.
  validateAnswers(answers, pipeline);
  checks += answers.length;
}
await aborts();
const resolver = new Resolver({ timeout, tries: 1 });
resolver.setServers([`${host}:5300`]);
assert.deepEqual(await resolver.resolve4('www.example.test'), ['192.0.2.80']);
assert.equal((await resolver.resolveTxt('large.example.test')).length, 10, 'Node DNS automatically retries TCP');
console.log(`PASS Node ${checks} raw flag/stream checks, early aborts, standard DNS and TCP fallback`);
