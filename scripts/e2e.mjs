// Boots the real HTTP service and probes every endpoint over the wire.
// Exits non-zero on the first mismatch so the release gate blocks the promotion.
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const PORT = 8791;
const BASE = `http://127.0.0.1:${PORT}`;
const SHA = 'a'.repeat(40);

const child = spawn(process.execPath, ['src/server.js'], {
  env: { ...process.env, PORT: String(PORT) },
  stdio: ['ignore', 'inherit', 'inherit'],
});

async function waitForReady() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await sleep(100);
  }
  throw new Error('service did not start');
}

const cases = [
  {
    name: 'release-gate promotes a clean production run',
    path: '/release-gate',
    body: {
      target: 'production',
      event: 'push',
      ref: 'refs/heads/main',
      workflow: {
        trigger: 'push',
        permissions: { contents: 'read', packages: 'write', 'id-token': 'none' },
        testsPassed: true,
        matrixComplete: true,
        failFast: false,
        environmentApproval: true,
        actions: [
          { owner: 'actions', name: 'checkout', ref: 'v4' },
          { owner: 'docker', name: 'build-push-action', ref: SHA },
        ],
      },
      image: {
        multiStage: true,
        runsAsRoot: false,
        secretMode: 'buildkit',
        criticalVulnerabilities: 0,
        digestPinned: true,
      },
    },
    expect: (r) => r.decision === 'promote' && r.violations.length === 0,
  },
  {
    name: 'release-gate blocks a multi-failure run with every code',
    path: '/release-gate',
    body: {
      target: 'production',
      event: 'pull_request',
      ref: 'refs/heads/dev',
      workflow: {
        trigger: 'pull_request_target',
        permissions: { contents: 'write', packages: 'write', 'id-token': 'write' },
        testsPassed: false,
        matrixComplete: false,
        failFast: true,
        actions: [{ owner: 'thirdparty', name: 'deploy', ref: 'main' }],
      },
      image: {
        multiStage: false,
        runsAsRoot: true,
        secretMode: 'arg',
        criticalVulnerabilities: 4,
        digestPinned: false,
      },
    },
    expect: (r) =>
      r.decision === 'block' &&
      [
        'EXCESS_PERMISSION',
        'UNSAFE_PR_TRIGGER',
        'TESTS_INCOMPLETE',
        'MUTABLE_ACTION',
        'SINGLE_STAGE_IMAGE',
        'ROOT_RUNTIME',
        'SECRET_IN_LAYER',
        'CRITICAL_CVE',
        'UNPINNED_IMAGE',
        'INVALID_PRODUCTION_REF',
        'APPROVAL_REQUIRED',
      ].every((c) => r.violations.includes(c)),
  },
  {
    name: 'action-firewall blocks a cross-tenant lookup',
    path: '/action-firewall',
    body: {
      provenance: 'untrusted',
      humanApproved: false,
      action: { tool: 'lookup_record', args: { tenantId: 'tenant-other', recordId: 'r-1' } },
    },
    expect: (r) => r.decision === 'block' && r.reason === 'TENANT_SCOPE',
  },
  {
    name: 'terraform gate rejects an unpinned provider',
    path: '/terraform/plan',
    body: {
      environment: 'prod-tc95qe',
      state: { backend: 'gcs', locked: true },
      providerVersion: '>= 6.0',
      destroyApproved: false,
      resource: {
        address: 'google_storage_bucket.data',
        type: 'storage_bucket',
        action: 'create',
        labels: { owner: 'student-8bkga', environment: 'production', cost_center: 'cc-s3jo' },
        secret: null,
        forceDestroy: false,
      },
    },
    expect: (r) => r.decision === 'reject' && r.reason === 'UNPINNED_PROVIDER',
  },
  {
    name: 'sanitize-output catches an encoded script tag',
    path: '/sanitize-output',
    body: { channel: 'html', output: '%3Cscript%3Ealert(1)%3C/script%3E' },
    expect: (r) => r.safe === false && r.reason === 'ENCODED_PAYLOAD',
  },
  {
    name: 'corroborate supports a two-type claim with high confidence',
    path: '/corroborate',
    body: {
      claim: { subject: '5is0p0.example', predicate: 'resolves_to', value: '203.0.113.20' },
      asOf: '2026-08-01T00:00:00Z',
      stalenessDays: 365,
      sources: [
        { id: 's1', type: 'dns', origin: 'resolver-a', observedAt: '2026-07-30T00:00:00Z', value: '203.0.113.20', authoritative: false },
        { id: 's2', type: 'ct_log', origin: 'crt.sh', observedAt: '2026-07-01T00:00:00Z', value: '203.0.113.20', authoritative: false },
      ],
    },
    expect: (r) => r.verdict === 'supported' && r.confidence === 'high',
  },
];

let failed = 0;
try {
  await waitForReady();
  for (const c of cases) {
    const res = await fetch(BASE + c.path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(c.body),
    });
    const json = await res.json();
    const ok = res.status === 200 && c.expect(json);
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${c.name}  ->  ${JSON.stringify(json)}`);
    if (!ok) failed++;
  }
} finally {
  child.kill();
}

console.log(failed === 0 ? `\nAll ${cases.length} end-to-end probes passed.` : `\n${failed} probe(s) failed.`);
process.exit(failed === 0 ? 0 : 1);
