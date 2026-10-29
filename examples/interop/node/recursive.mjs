// Independent standard-library resolver against Donna's iterative resolver.
import assert from 'node:assert/strict';
import { Resolver } from 'node:dns/promises';

const resolver = new Resolver({ timeout: 5000, tries: 1 });
resolver.setServers([process.env.RECURSIVE_ADDRESS ?? '172.29.53.11:5301']);
for (let repeat = 0; repeat < 2; repeat++) {
  for (const name of ['www.example.test.', 'alias.example.test.']) {
    assert.deepEqual(await resolver.resolve4(name), ['192.0.2.80']);
  }
  await assert.rejects(resolver.resolve4('missing.example.test.'), { code: 'ENOTFOUND' });
  await assert.rejects(resolver.resolve4('text.example.test.'), { code: 'ENODATA' });
  const addresses = await resolver.resolve4('many.example.test.');
  assert.equal(addresses.length, 96);
  assert.deepEqual(new Set(addresses), new Set(Array.from({ length: 96 }, (_, i) => `192.0.2.${i + 1}`)));
}
console.log('PASS Node recursive positive, alias, distinct NXDOMAIN/NODATA errors and complete large RRset; repeated queries');
