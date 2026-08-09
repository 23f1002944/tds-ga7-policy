// TDS 2026 May GA7 — deterministic policy endpoints.
// No LLM, no phrase lists, no wall-clock reads. Pure functions over the request body.

// ---------------------------------------------------------------------------
// Assigned scope constants (per-student values from the GA7 question text)
// ---------------------------------------------------------------------------
export const TENANT_ID = 'tenant-k3hh9xf';
export const EMAIL_DOMAIN = 'notify-uzl5a7e.example';
export const TF_WORKSPACE = 'prod-tc95qe';
export const TF_LABELS = {
  owner: 'student-8bkga',
  environment: 'production',
  cost_center: 'cc-s3jo',
};
export const ALLOWED_HOSTS = ['cdn-gvyms7t.example', 'app-vh0flur.example'];
export const SUBJECT = '5is0p0.example';

const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const keysAre = (o, expected) => {
  const k = Object.keys(o);
  return k.length === expected.length && expected.every((e) => k.includes(e));
};

// ===========================================================================
// Q1 — POST /release-gate
// ===========================================================================
const REQUIRED_PERMISSIONS = { contents: 'read', packages: 'write', 'id-token': 'none' };
const SHA40 = /^[0-9a-f]{40}$/;

export function releaseGate(body) {
  const v = new Set();
  const b = isObj(body) ? body : {};
  const wf = isObj(b.workflow) ? b.workflow : {};
  const img = isObj(b.image) ? b.image : {};

  // 1. Permissions must be exactly least privilege — no more, no less.
  const perms = isObj(wf.permissions) ? wf.permissions : null;
  if (
    !perms ||
    !keysAre(perms, Object.keys(REQUIRED_PERMISSIONS)) ||
    Object.entries(REQUIRED_PERMISSIONS).some(([k, val]) => perms[k] !== val)
  ) {
    v.add('EXCESS_PERMISSION');
  }

  // 2. Pull requests run on pull_request, never pull_request_target.
  if (wf.trigger === 'pull_request_target' || (b.event === 'pull_request' && wf.trigger !== 'pull_request')) {
    v.add('UNSAFE_PR_TRIGGER');
  }

  // 3. The whole matrix must finish and pass, without fail-fast cancellation.
  if (wf.testsPassed !== true || wf.matrixComplete !== true || wf.failFast !== false) {
    v.add('TESTS_INCOMPLETE');
  }

  // 4. Third-party actions must be pinned to a full commit SHA.
  const actions = Array.isArray(wf.actions) ? wf.actions : [];
  for (const a of actions) {
    if (!isObj(a)) {
      v.add('MUTABLE_ACTION');
      continue;
    }
    if (a.owner === 'actions') continue; // first-party may use a version tag
    if (!isStr(a.ref) || !SHA40.test(a.ref)) v.add('MUTABLE_ACTION');
  }

  // 5. Hardened image.
  if (img.multiStage !== true) v.add('SINGLE_STAGE_IMAGE');
  if (img.runsAsRoot === true) v.add('ROOT_RUNTIME');
  if (img.secretMode !== 'none' && img.secretMode !== 'buildkit') v.add('SECRET_IN_LAYER');
  if (typeof img.criticalVulnerabilities !== 'number' || img.criticalVulnerabilities > 0) v.add('CRITICAL_CVE');
  if (img.digestPinned !== true) v.add('UNPINNED_IMAGE');

  // 6. Production-only gates.
  if (b.target === 'production') {
    if (b.event !== 'push' || b.ref !== 'refs/heads/main') v.add('INVALID_PRODUCTION_REF');
    if (wf.environmentApproval !== true) v.add('APPROVAL_REQUIRED');
  }

  const violations = [...v];
  return { decision: violations.length === 0 ? 'promote' : 'block', violations };
}

// ===========================================================================
// Q2 — POST /action-firewall
// ===========================================================================
const ALLOWED_TOOLS = ['search', 'lookup_record', 'send_email', 'render_html'];
const UNSAFE_TAG = /<\s*\/?\s*(script|iframe|object|embed)\b/i;
const EVENT_ATTR = /\son[a-z]+\s*=/i;
const BAD_URL_SCHEME = /(javascript|vbscript)\s*:/i;

function nonEmptyStr(v) {
  return isStr(v) && v.length > 0;
}

export function actionFirewall(body) {
  const deny = (reason) => ({ decision: 'block', reason });

  // --- 1. top-level schema -------------------------------------------------
  if (!isObj(body)) return deny('INVALID_SCHEMA');
  if (body.provenance !== 'trusted' && body.provenance !== 'untrusted') return deny('INVALID_SCHEMA');
  if (typeof body.humanApproved !== 'boolean') return deny('INVALID_SCHEMA');
  if ('untrustedContent' in body && body.untrustedContent !== null && !isStr(body.untrustedContent)) {
    return deny('INVALID_SCHEMA');
  }
  if (!isObj(body.action)) return deny('INVALID_SCHEMA');
  const { tool, args } = body.action;
  if (!keysAre(body.action, ['tool', 'args'])) return deny('INVALID_SCHEMA');
  if (!isStr(tool)) return deny('INVALID_SCHEMA');

  // --- 2. tool allowlist ---------------------------------------------------
  if (!ALLOWED_TOOLS.includes(tool)) return deny('TOOL_NOT_ALLOWED');
  if (!isObj(args)) return deny('INVALID_SCHEMA');

  // --- 3. per-tool argument schema (exact key sets) ------------------------
  if (tool === 'search') {
    if (!keysAre(args, ['query'])) return deny('INVALID_SCHEMA');
    if (!isStr(args.query) || args.query.length < 1 || args.query.length > 200) return deny('INVALID_SCHEMA');
    return { decision: 'allow', reason: 'ALLOW' };
  }

  if (tool === 'lookup_record') {
    if (!keysAre(args, ['tenantId', 'recordId'])) return deny('INVALID_SCHEMA');
    if (!nonEmptyStr(args.tenantId) || !nonEmptyStr(args.recordId)) return deny('INVALID_SCHEMA');
    // --- 4. tenant scope ---------------------------------------------------
    if (args.tenantId !== TENANT_ID) return deny('TENANT_SCOPE');
    return { decision: 'allow', reason: 'ALLOW' };
  }

  if (tool === 'send_email') {
    if (!keysAre(args, ['to', 'subject', 'body'])) return deny('INVALID_SCHEMA');
    if (!nonEmptyStr(args.to) || !isStr(args.subject) || !isStr(args.body)) return deny('INVALID_SCHEMA');
    const at = args.to.lastIndexOf('@');
    if (at <= 0 || at === args.to.length - 1) return deny('INVALID_SCHEMA');
    // --- 5. exact recipient domain ----------------------------------------
    if (args.to.slice(at + 1).toLowerCase() !== EMAIL_DOMAIN) return deny('EGRESS_DENIED');
    // --- 6. human approval for side effects -------------------------------
    if (body.humanApproved !== true) return deny('APPROVAL_REQUIRED');
    return { decision: 'allow', reason: 'ALLOW' };
  }

  // tool === 'render_html'
  if (!keysAre(args, ['html'])) return deny('INVALID_SCHEMA');
  if (!isStr(args.html)) return deny('INVALID_SCHEMA');
  // --- 7. safe rendering ---------------------------------------------------
  const html = args.html;
  const decoded = decodeOnce(html);
  for (const candidate of [html, decoded]) {
    if (UNSAFE_TAG.test(candidate)) return deny('UNSAFE_OUTPUT');
    if (EVENT_ATTR.test(candidate)) return deny('UNSAFE_OUTPUT');
    if (BAD_URL_SCHEME.test(candidate)) return deny('UNSAFE_OUTPUT');
  }
  return { decision: 'allow', reason: 'ALLOW' };
}

// ===========================================================================
// Q3 — POST /terraform/plan
// ===========================================================================
const SAFE_BACKENDS = ['gcs', 's3', 'azurerm', 'remote'];
const STATEFUL_TYPES = ['storage_bucket', 'sql_database', 'persistent_disk'];
const EXACT_VERSION = /^=?\s*\d+\.\d+\.\d+$/;
const PESSIMISTIC_VERSION = /^~>\s*\d+(\.\d+)*$/;

export function terraformPlan(body) {
  const reject = (reason) => ({ decision: 'reject', reason });

  // --- 1. shape ------------------------------------------------------------
  if (!isObj(body)) return reject('INVALID_PLAN');
  const { environment, state, providerVersion, destroyApproved, resource } = body;
  if (!isStr(environment)) return reject('INVALID_PLAN');
  if (!isObj(state) || !isStr(state.backend) || typeof state.locked !== 'boolean') return reject('INVALID_PLAN');
  if (!isStr(providerVersion)) return reject('INVALID_PLAN');
  if (typeof destroyApproved !== 'boolean') return reject('INVALID_PLAN');
  if (!isObj(resource)) return reject('INVALID_PLAN');
  if (!isStr(resource.address) || !isStr(resource.type)) return reject('INVALID_PLAN');
  if (!['create', 'update', 'delete'].includes(resource.action)) return reject('INVALID_PLAN');
  if (!isObj(resource.labels)) return reject('INVALID_PLAN');
  if (resource.secret !== null && !isStr(resource.secret)) return reject('INVALID_PLAN');
  if (typeof resource.forceDestroy !== 'boolean') return reject('INVALID_PLAN');

  // --- 2. workspace --------------------------------------------------------
  if (environment !== TF_WORKSPACE) return reject('ENVIRONMENT_MISMATCH');

  // --- 3. remote state + locking ------------------------------------------
  if (!SAFE_BACKENDS.includes(state.backend) || state.locked !== true) return reject('STATE_UNSAFE');

  // --- 4. provider pinning -------------------------------------------------
  const pv = providerVersion.trim();
  if (!EXACT_VERSION.test(pv) && !PESSIMISTIC_VERSION.test(pv)) return reject('UNPINNED_PROVIDER');

  // --- 5. cost-ownership labels -------------------------------------------
  for (const [k, want] of Object.entries(TF_LABELS)) {
    if (resource.labels[k] !== want) return reject('MISSING_LABELS');
  }

  // --- 6. no plaintext secrets --------------------------------------------
  if (resource.secret !== null && !/^secret:\/\/.+/.test(resource.secret)) return reject('PLAINTEXT_SECRET');

  // --- 7. stateful deletes need approval ----------------------------------
  if (resource.action === 'delete' && STATEFUL_TYPES.includes(resource.type) && destroyApproved !== true) {
    return reject('DELETE_NOT_APPROVED');
  }

  // --- 8. never force-destroy a production bucket -------------------------
  if (resource.type === 'storage_bucket' && resource.forceDestroy === true) return reject('FORCE_DESTROY');

  return { decision: 'approve', reason: 'APPROVE' };
}

// ===========================================================================
// Q4 — POST /sanitize-output
// ===========================================================================
const CHANNELS = ['html', 'markdown', 'url', 'sql', 'shell'];
const NAMED_ENTITIES = { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&' };

/** Decode percent-escapes, then HTML entities, then \uXXXX escapes — one pass each. */
export function decodeOnce(s) {
  let out = s.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  out = out.replace(/&(#x[0-9A-Fa-f]+|#\d+|lt|gt|quot|apos|amp);/gi, (m, ent) => {
    const e = ent.toLowerCase();
    if (e.startsWith('#x')) return String.fromCodePoint(parseInt(e.slice(2), 16));
    if (e.startsWith('#')) return String.fromCodePoint(parseInt(e.slice(1), 10));
    return NAMED_ENTITIES[e] ?? m;
  });
  out = out.replace(/\\u([0-9A-Fa-f]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  return out;
}

const SCRIPT_TAG_RE = /<\s*(script|iframe|object|embed)\b/i;
const EVENT_HANDLER_RE = /\son[a-z]+\s*=/i;
const SCHEME_TEXT_RE = /(javascript|data|vbscript)\s*:/i;
const SQL_RE = /['";]|--|\/\*|\bunion\b|\bor\s+1\s*=\s*1\b/i;
const SHELL_RE = /[;&|`<>]|\$\(|\$\{/;

function extractUrls(channel, text) {
  if (channel === 'url') return [text.trim()].filter(Boolean);
  const urls = [];
  if (channel === 'html') {
    const re = /(?:src|href)\s*=\s*("([^"]*)"|'([^']*)')/gi;
    let m;
    while ((m = re.exec(text)) !== null) urls.push(m[2] !== undefined ? m[2] : m[3]);
  } else if (channel === 'markdown') {
    const re = /\]\(\s*([^)\s]*)/g;
    let m;
    while ((m = re.exec(text)) !== null) urls.push(m[1]);
  }
  return urls.filter((u) => u && u.length > 0);
}

/** Absolute → parsed URL; relative → null. Protocol-relative resolves as https:. */
function parseAbsolute(raw) {
  const u = raw.trim();
  if (!u) return null;
  try {
    if (/^\/\/[^/]/.test(u)) return new URL('https:' + u);
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(u)) return new URL(u);
  } catch {
    return null;
  }
  return null;
}

function urlChecks(channel, text) {
  const urls = extractUrls(channel, text);

  // DANGEROUS_SCHEME: literal scheme anywhere in the text, or a non-http(s) URL.
  if (SCHEME_TEXT_RE.test(text)) return 'DANGEROUS_SCHEME';
  for (const raw of urls) {
    const parsed = parseAbsolute(raw);
    if (parsed && parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return 'DANGEROUS_SCHEME';
    if (!parsed && /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw.trim())) return 'DANGEROUS_SCHEME';
  }

  // EXTERNAL_EXFIL: any absolute URL whose hostname is not exactly allowlisted.
  for (const raw of urls) {
    const parsed = parseAbsolute(raw);
    if (!parsed) continue; // relative reference — same origin, fine
    if (!ALLOWED_HOSTS.includes(parsed.hostname.toLowerCase())) return 'EXTERNAL_EXFIL';
  }
  return null;
}

function channelChecks(channel, text) {
  if (channel === 'html') {
    if (SCRIPT_TAG_RE.test(text)) return 'SCRIPT_TAG';
    if (EVENT_HANDLER_RE.test(text)) return 'EVENT_HANDLER';
    return urlChecks('html', text);
  }
  if (channel === 'markdown' || channel === 'url') return urlChecks(channel, text);
  if (channel === 'sql') return SQL_RE.test(text) ? 'SQL_METACHAR' : null;
  return SHELL_RE.test(text) ? 'SHELL_METACHAR' : null; // shell
}

export function sanitizeOutput(body) {
  // --- 1. schema -----------------------------------------------------------
  if (!isObj(body)) return { safe: false, reason: 'INVALID_SCHEMA' };
  const { channel, output } = body;
  if (!CHANNELS.includes(channel)) return { safe: false, reason: 'INVALID_SCHEMA' };
  if (!isStr(output) || output.length > 20000) return { safe: false, reason: 'INVALID_SCHEMA' };

  // --- 2. encoded payload --------------------------------------------------
  const decoded = decodeOnce(output);
  if (decoded !== output && channelChecks(channel, decoded) !== null) {
    return { safe: false, reason: 'ENCODED_PAYLOAD' };
  }

  // --- 3. channel rules on the original output -----------------------------
  const reason = channelChecks(channel, output);
  return reason ? { safe: false, reason } : { safe: true, reason: 'SAFE' };
}

// ===========================================================================
// Q5 — POST /corroborate
// ===========================================================================
const SOURCE_TYPES = ['dns', 'ct_log', 'registry', 'archive', 'scan'];
const DAY_MS = 86400000;

export function corroborate(body) {
  const invalid = { verdict: 'invalid', confidence: 'low', corroboratingSources: [] };
  const unverified = { verdict: 'unverified', confidence: 'low', corroboratingSources: [] };

  // --- 1. validity ---------------------------------------------------------
  if (!isObj(body)) return invalid;
  const { claim, asOf, stalenessDays, sources } = body;
  if (!isObj(claim) || !isStr(claim.value)) return invalid;
  if (!isStr(asOf)) return invalid;
  const asOfMs = Date.parse(asOf);
  if (Number.isNaN(asOfMs)) return invalid;
  if (typeof stalenessDays !== 'number' || Number.isNaN(stalenessDays)) return invalid;
  if (!Array.isArray(sources)) return invalid;

  const windowMs = stalenessDays * DAY_MS;
  const fresh = sources.filter((s) => {
    if (!isObj(s)) return false;
    if (!isStr(s.id) || !isStr(s.origin) || !isStr(s.value) || !isStr(s.observedAt)) return false;
    if (!SOURCE_TYPES.includes(s.type)) return false;
    const t = Date.parse(s.observedAt);
    if (Number.isNaN(t)) return false;
    return asOfMs - t <= windowMs;
  });

  // --- 2. authoritative contradiction --------------------------------------
  const contradicting = fresh.filter((s) => s.authoritative === true && s.value !== claim.value);
  if (contradicting.length > 0) {
    return {
      verdict: 'contradicted',
      confidence: 'low',
      corroboratingSources: contradicting.map((s) => s.id).sort(),
    };
  }

  // --- 3. independent corroboration ----------------------------------------
  const agreeing = fresh.filter((s) => s.value === claim.value);
  const byOrigin = new Map();
  for (const s of agreeing) {
    const cur = byOrigin.get(s.origin);
    if (!cur || s.id < cur.id) byOrigin.set(s.origin, s); // lexicographically smallest id
  }
  const reps = [...byOrigin.values()];
  if (reps.length >= 2) {
    const types = new Set(reps.map((s) => s.type));
    return {
      verdict: 'supported',
      confidence: types.size >= 2 ? 'high' : 'medium',
      corroboratingSources: reps.map((s) => s.id).sort(),
    };
  }

  // --- 4. everything else --------------------------------------------------
  return unverified;
}

// ===========================================================================
// Router — shared by the Workers and Node entrypoints
// ===========================================================================
const ROUTES = {
  '/release-gate': { fn: releaseGate, onBadJson: () => releaseGate({}) },
  '/action-firewall': { fn: actionFirewall, onBadJson: () => ({ decision: 'block', reason: 'INVALID_SCHEMA' }) },
  '/terraform/plan': { fn: terraformPlan, onBadJson: () => ({ decision: 'reject', reason: 'INVALID_PLAN' }) },
  '/sanitize-output': { fn: sanitizeOutput, onBadJson: () => ({ safe: false, reason: 'INVALID_SCHEMA' }) },
  '/corroborate': {
    fn: corroborate,
    onBadJson: () => ({ verdict: 'invalid', confidence: 'low', corroboratingSources: [] }),
  },
};

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'access-control-allow-origin': '*',
  'access-control-allow-headers': '*',
  'access-control-allow-methods': 'GET,POST,OPTIONS',
  'cache-control': 'no-store',
};

export async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: JSON_HEADERS });

  if (path === '/' || path === '/health') {
    return new Response(
      JSON.stringify({
        service: 'tds-ga7-policy',
        status: 'ok',
        endpoints: Object.keys(ROUTES),
      }),
      { headers: JSON_HEADERS },
    );
  }

  const route = ROUTES[path];
  if (!route) return new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers: JSON_HEADERS });
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'method_not_allowed' }), { status: 405, headers: JSON_HEADERS });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify(route.onBadJson()), { status: 200, headers: JSON_HEADERS });
  }
  return new Response(JSON.stringify(route.fn(body)), { status: 200, headers: JSON_HEADERS });
}
