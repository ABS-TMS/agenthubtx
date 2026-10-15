// netlify/functions/rets-roster.js
//
// PRIVATE agent-roster export from the NTREIS Matrix RETS Member resource.
// Standalone on purpose: it does not touch rets-lookup.js or any page that uses it.
// Uses the same env vars (RETS_LOGIN_URL, RETS_USERNAME, RETS_PASSWORD) plus ROSTER_KEY.
// Fails closed (403) unless ROSTER_KEY is set AND the request has a matching &key=.
//
//   /.netlify/functions/rets-roster?office=KWMC01SL&key=<ROSTER_KEY>&format=columns   (see real field names)
//   /.netlify/functions/rets-roster?office=KWMC01SL&key=<ROSTER_KEY>&format=csv       (download roster)
//   optional: &officeField=<field>  &query=<raw DMQL2>  &resource=Member  &class=Member  &pageSize=250  &max=1000
// Field names are NOT verified against the live server — use format=columns first.

const crypto = require('crypto');

const RETS_VERSION = 'RETS/1.8';
const USER_AGENT = 'AgentHubTX-RETS/1.0';

function b64(str) {
  return Buffer.from(str, 'utf8').toString('base64');
}

function md5(str) {
  return crypto.createHash('md5').update(str, 'utf8').digest('hex');
}

// Parses a WWW-Authenticate header into its scheme + key/value directives.
// e.g. 'Digest realm="NTREIS", qop="auth", nonce="abc123", opaque="xyz"'
function parseAuthHeader(headerValue) {
  const scheme = headerValue.split(' ')[0];
  const params = {};
  const re = /(\w+)=(?:"([^"]*)"|([^\s,]+))/g;
  let m;
  while ((m = re.exec(headerValue)) !== null) {
    params[m[1]] = m[2] !== undefined ? m[2] : m[3];
  }
  return { scheme, params };
}

// Builds an RFC 2617 Digest Authorization header value. Supports both the
// qop="auth" variant (modern) and the legacy no-qop variant some older RETS
// 1.x servers still use — NTREIS specifically isn't documented either way,
// so both paths are implemented rather than assumed.
function buildDigestHeader({ username, password, method, uri, authParams }) {
  const { realm, nonce, opaque, qop } = authParams;
  const ha1 = md5(`${username}:${realm}:${password}`);
  const ha2 = md5(`${method}:${uri}`);
  let response, extra;
  if (qop) {
    const nc = '00000001';
    const cnonce = crypto.randomBytes(8).toString('hex');
    response = md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
    extra = `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
  } else {
    response = md5(`${ha1}:${nonce}:${ha2}`);
    extra = '';
  }
  const opaquePart = opaque ? `, opaque="${opaque}"` : '';
  return `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}"${extra}${opaquePart}`;
}

// Very small cookie-jar: RETS servers may set more than one cookie (session cookie +
// possibly a load-balancer/ASP.NET cookie). We keep every Set-Cookie name=value pair
// and resend the whole set on every subsequent request in this invocation.
function parseSetCookies(headers) {
  const raw = headers.getSetCookie ? headers.getSetCookie() : (headers.get('set-cookie') ? [headers.get('set-cookie')] : []);
  const jar = {};
  for (const line of raw) {
    const pair = line.split(';')[0]; // "Name=Value"
    const idx = pair.indexOf('=');
    if (idx > -1) {
      jar[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
    }
  }
  return jar;
}

function cookieHeader(jar) {
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
}

// Parses the RETS-RESPONSE key=value block returned by Login into a plain object,
// and resolves the capability URLs (Search, GetObject, GetMetadata, Logout, ...) against
// the login URL's origin, since NTREIS may return them as relative paths.
function parseLoginResponse(xmlText, loginUrl) {
  const origin = new URL(loginUrl).origin;
  const block = xmlText.split(/<RETS-RESPONSE>/i)[1]?.split(/<\/RETS-RESPONSE>/i)[0] || '';
  const lines = block.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const kv = {};
  for (const line of lines) {
    const idx = line.indexOf('=');
    if (idx > -1) {
      kv[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
  }
  const resolve = (v) => {
    if (!v) return v;
    try {
      return new URL(v, origin).toString();
    } catch {
      return v;
    }
  };
  return {
    raw: kv,
    urls: {
      search: resolve(kv.Search),
      getObject: resolve(kv.GetObject),
      getMetadata: resolve(kv.GetMetadata),
      logout: resolve(kv.Logout),
      action: resolve(kv.Action),
    },
    timeoutSeconds: kv.TimeoutSeconds ? Number(kv.TimeoutSeconds) : null,
  };
}

async function retsLogin() {
  const loginUrl = process.env.RETS_LOGIN_URL;
  const username = process.env.RETS_USERNAME;
  const password = process.env.RETS_PASSWORD;
  if (!loginUrl || !username || !password) {
    throw new Error('Missing RETS_LOGIN_URL / RETS_USERNAME / RETS_PASSWORD env vars');
  }

  const baseHeaders = {
    'RETS-Version': RETS_VERSION,
    'User-Agent': USER_AGENT,
    Accept: '*/*',
  };

  // Step 1: probe with no credentials. Do NOT assume Basic — many RETS 1.x
  // servers (including, per NTREIS support, this one) actually require HTTP
  // Digest auth. Sending Basic blindly on the first request is what caused
  // real 401s here even with fully correct credentials; the fix is to let
  // the server's WWW-Authenticate challenge tell us which scheme to use.
  let res = await fetch(loginUrl, { headers: baseHeaders });

  if (res.status === 401) {
    const challenge = res.headers.get('www-authenticate');
    if (!challenge) {
      throw new Error('RETS login HTTP 401 with no WWW-Authenticate header — cannot determine auth scheme');
    }
    const { scheme, params } = parseAuthHeader(challenge);
    const uri = new URL(loginUrl).pathname;

    let authHeader;
    if (scheme === 'Digest') {
      authHeader = buildDigestHeader({ username, password, method: 'GET', uri, authParams: params });
    } else if (scheme === 'Basic') {
      authHeader = `Basic ${b64(`${username}:${password}`)}`;
    } else {
      throw new Error(`Unsupported RETS auth scheme: ${scheme}`);
    }

    res = await fetch(loginUrl, {
      headers: { ...baseHeaders, Authorization: authHeader },
    });
  }

  const bodyText = await res.text();
  if (!res.ok) {
    throw new Error(`RETS login HTTP ${res.status}: ${bodyText.slice(0, 500)}`);
  }
  const replyCodeMatch = bodyText.match(/ReplyCode="(\d+)"/);
  const replyTextMatch = bodyText.match(/ReplyText="([^"]*)"/);
  if (replyCodeMatch && replyCodeMatch[1] !== '0') {
    throw new Error(`RETS login failed — ReplyCode ${replyCodeMatch[1]}: ${replyTextMatch?.[1] || 'unknown error'}`);
  }

  const jar = parseSetCookies(res.headers);
  const parsed = parseLoginResponse(bodyText, loginUrl);
  return { cookieJar: jar, ...parsed };
}

// Splits a COMPACT / COMPACT-DECODED response into { columns: [...], rows: [[...], ...] }.
// RETS wraps each COLUMNS/DATA line with the delimiter on both ends, so a plain split()
// yields one empty string at the start and end — those get filtered out.
function parseCompact(xmlText) {
  const delimMatch = xmlText.match(/<DELIMITER\s+value="([0-9A-Fa-f]+)"\s*\/?>/);
  const delimChar = delimMatch ? String.fromCharCode(parseInt(delimMatch[1], 16)) : '\t';

  const columnsMatch = xmlText.match(/<COLUMNS>([\s\S]*?)<\/COLUMNS>/);
  const columns = columnsMatch
    ? columnsMatch[1].split(delimChar).map((s) => s.trim()).filter((s) => s.length > 0)
    : [];

  const dataMatches = [...xmlText.matchAll(/<DATA>([\s\S]*?)<\/DATA>/g)];
  const rows = dataMatches.map((m) => {
    const cells = m[1].split(delimChar);
    // Drop the empty leading/trailing cells created by the wrapping delimiter.
    if (cells.length && cells[0] === '') cells.shift();
    if (cells.length && cells[cells.length - 1] === '') cells.pop();
    return cells;
  });

  const countMatch = xmlText.match(/<COUNT\s+Records="(\d+)"\s*\/?>/);
  const replyCodeMatch = xmlText.match(/ReplyCode="(\d+)"/);
  const replyTextMatch = xmlText.match(/ReplyText="([^"]*)"/);

  return {
    replyCode: replyCodeMatch ? replyCodeMatch[1] : null,
    replyText: replyTextMatch ? replyTextMatch[1] : null,
    count: countMatch ? Number(countMatch[1]) : rows.length,
    columns,
    rows,
    records: rows.map((r) => Object.fromEntries(columns.map((c, i) => [c, r[i] ?? '']))),
  };
}

function buildQuery() { throw new Error('Provide a query'); }

async function retsSearch(session, { resource = 'Property', class: cls = 'Property', mlsNumber, address, rawQuery, limit = 1, offset = 1 }) {
  const query = rawQuery || buildQuery({ mlsNumber, address });
  const params = new URLSearchParams({
    SearchType: resource,
    Class: cls,
    Query: query,
    QueryType: 'DMQL2',
    Format: 'COMPACT-DECODED',
    Count: '1',
    Limit: String(limit),
    StandardNames: '0',
  });
  if (offset > 1) params.set('Offset', String(offset));
  const url = `${session.urls.search}?${params.toString()}`;
  const res = await fetch(url, {
    headers: {
      'RETS-Version': RETS_VERSION,
      'User-Agent': USER_AGENT,
      Accept: '*/*',
      Cookie: cookieHeader(session.cookieJar),
    },
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`RETS search HTTP ${res.status}: ${text.slice(0, 500)}`);
  }
  return parseCompact(text);
}


exports.handler = async (event) => {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };
  try {
    const qs = event.queryStringParameters || {};
    const rosterKey = process.env.ROSTER_KEY;
    if (!rosterKey || qs.key !== rosterKey) {
      return { statusCode: 403, headers: cors, body: JSON.stringify({ error: 'Forbidden' }) };
    }
    const session = await retsLogin();
    let result;
    if (true) {
      const resource = qs.resource || 'Member';
      const cls = qs.class || 'Member';
      const officeField = qs.officeField || 'MemberOfficeMlsId';
      const rawQuery = qs.query || (qs.office ? `(${officeField}=${qs.office})` : null);
      if (!rawQuery) throw new Error('Provide office (e.g. KWMC01SL) or a raw DMQL2 query');
      const pageSize = Math.min(parseInt(qs.pageSize, 10) || 250, 500);
      const maxRows = Math.min(parseInt(qs.max, 10) || 1000, 2000);

      const all = [];
      let columns = [];
      let offset = 1;
      let lastReply = { code: null, text: null };
      while (all.length < maxRows) {
        const page = await retsSearch(session, { resource, class: cls, rawQuery, limit: pageSize, offset });
        lastReply = { code: page.replyCode, text: page.replyText };
        if (!columns.length) columns = page.columns;
        if (!page.records.length) break;
        all.push(...page.records);
        if (page.records.length < pageSize) break;
        offset += page.records.length;
      }

      if (qs.format === 'columns') {
        result = { count: all.length, columns, sample: all[0] || null, reply: lastReply, queryUsed: rawQuery };
      } else {
        const pick = (exact, fallback, reject) =>
          columns.find((c) => exact.test(c)) ||
          columns.find((c) => fallback.test(c) && !(reject && reject.test(c)));
        const cFirst = pick(/^MemberFirstName$/i, /first.?name/i);
        const cLast = pick(/^MemberLastName$/i, /last.?name/i);
        const cLic = pick(/^MemberStateLicense$/i, /license/i, /exp|date|type|state$/i);
        const cEmail = pick(/^MemberEmail$/i, /e-?mail/i);
        const cMls = pick(/^MemberMlsId$/i, /mls.?id/i, /office/i);
        const cStatus = pick(/^MemberStatus$/i, /status/i);
        const cType = pick(/^MLSMemberType$/i, /member.?type/i);
        const picked = { cFirst, cLast, cLic, cEmail, cMls, cStatus, cType };
        const rows = all.map((r) => ({
          'First Name': cFirst ? r[cFirst] : '',
          'Last Name': cLast ? r[cLast] : '',
          'License Number': cLic ? r[cLic] : '',
          'MLS ID': cMls ? r[cMls] : '',
          'Email': cEmail ? r[cEmail] : '',
          'Status': cStatus ? r[cStatus] : '',
          'Member Type': cType ? r[cType] : '',
        }));
        if (qs.format === 'csv') {
          const esc = (v) => {
            const s = String(v ?? '');
            return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
          };
          const header = Object.keys(rows[0] || { 'First Name': 1, 'Last Name': 1, 'License Number': 1, 'MLS ID': 1, 'Email': 1, 'Status': 1, 'Member Type': 1 });
          const csv = [header.join(',')].concat(rows.map((r) => header.map((h) => esc(r[h])).join(','))).join('\r\n');
          return { statusCode: 200, headers: { ...cors, 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="roster.csv"' }, body: csv };
        }
        result = { count: rows.length, picked, reply: lastReply, queryUsed: rawQuery, rows };
      }
    }
    return { statusCode: 200, headers: cors, body: JSON.stringify(result, null, 2) };
  } catch (err) {
    return { statusCode: 500, headers: cors, body: JSON.stringify({ error: err.message }) };
  }
};
