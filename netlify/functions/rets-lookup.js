// netlify/functions/rets-lookup.js
//
// Hand-rolled NTREIS Matrix RETS 1.8 client. No npm dependency (native fetch only).
// Talks directly to the RETS 1.8 server: login -> session cookie -> search / getobject / getmetadata.
// Netlify functions are stateless per-invocation, so every call does a full login -> action -> (implicit) done
// cycle. We don't bother calling Logout — RETS sessions time out on their own (TimeoutSeconds from login,
// per the manual) and there's no persistent connection to clean up between invocations anyway.
//
// Env vars required (set in Netlify site settings):
//   RETS_LOGIN_URL   e.g. https://ntrdd.mlsmatrix.com/rets/login.ashx
//   RETS_USERNAME
//   RETS_PASSWORD
//
// Modes (query param `mode`):
//   mode=metadata&resource=Property&class=RESI
//     -> raw GetMetadata XML for that resource/class. Use this FIRST to find the real field
//        SystemNames NTREIS uses (MLS#, price, address, showing instructions, private remarks, etc.)
//        before wiring up the real field-select list below. Do not guess field names against a live
//        MLS feed — pull them from here.
//
//   mode=search&mlsNumber=21327448  (or &address=... — address matching is looser, see buildQuery)
//     -> raw parsed COMPACT-DECODED rows for that listing, ALL fields (no Select= restriction yet).
//        Use this against the known test listing (2416 Fall Leaf Court, MLS# 21327448) to see real
//        field names/values side by side with the Agent Full / Customer Full reports already reviewed,
//        then build the real client-safe field map as a second pass.
//
//   mode=photos&listingKey=<ListingKeyNumeric>
//     -> best-effort list of photo URLs via GetObject (Location=1). NOTE: exact response shaping for
//        Location=1 (multipart vs. flat key/value) is implementation-specific and UNVERIFIED against the
//        live NTREIS server — the parser here is permissive (regex over Location: lines) but flag this as
//        the first thing to sanity-check once real credentials are wired up.
//
// This file intentionally does NOT hardcode a NTREIS field-select list yet — see mode=metadata / mode=search
// above. Wiring the real client-safe field map (matching the Customer Full filtering logic already confirmed)
// is the next step after this file is confirmed working end-to-end against the live feed.

const RETS_VERSION = 'RETS/1.8';
const USER_AGENT = 'AgentHubTX-RETS/1.0';

function b64(str) {
  return Buffer.from(str, 'utf8').toString('base64');
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

  const res = await fetch(loginUrl, {
    headers: {
      'RETS-Version': RETS_VERSION,
      'User-Agent': USER_AGENT,
      Accept: '*/*',
      Authorization: `Basic ${b64(`${username}:${password}`)}`,
    },
  });

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

// Builds a DMQL2 query. mlsNumber match is exact; address match is a loose CONTAINS-style
// match on StreetName since we don't yet know NTREIS's exact address field breakdown
// (StreetNumber/StreetName/StreetSuffix are usually separate fields, not one "Address" field —
// confirm via mode=metadata before relying on address search for real).
function buildQuery({ mlsNumber, address }) {
  if (mlsNumber) {
    // Field name assumed as "MLSNumber" per the manual's field references seen so far —
    // VERIFY exact SystemName via mode=metadata before treating this as final.
    return `(MLSNumber=${mlsNumber})`;
  }
  if (address) {
    return `(StreetName=~*${address}*)`;
  }
  throw new Error('Provide mlsNumber or address');
}

async function retsSearch(session, { resource = 'Property', class: cls = 'RESI', mlsNumber, address }) {
  const query = buildQuery({ mlsNumber, address });
  const params = new URLSearchParams({
    SearchType: resource,
    Class: cls,
    Query: query,
    QueryType: 'DMQL2',
    Format: 'COMPACT-DECODED',
    Count: '1',
    Limit: '1',
    StandardNames: '0',
  });
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

async function retsGetMetadata(session, { resource = 'Property', class: cls }) {
  const params = new URLSearchParams({
    Type: cls ? 'METADATA-TABLE' : 'METADATA-RESOURCE',
    ID: cls ? `${resource}:${cls}` : resource,
    Format: 'COMPACT',
  });
  const url = `${session.urls.getMetadata}?${params.toString()}`;
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
    throw new Error(`RETS GetMetadata HTTP ${res.status}: ${text.slice(0, 500)}`);
  }
  return text; // returned raw — inspect directly to find real field SystemNames
}

// BEST-EFFORT / UNVERIFIED — see file header note. Location=1 asks the server to return
// URLs instead of binary image data, but the exact response shape (multipart vs. flat
// key/value blocks) varies by RETS server. This regexes out every "Location:" value it can
// find rather than assuming one exact structure. Confirm against a real listing before relying
// on this for production use.
async function retsGetPhotos(session, { resource = 'Property', listingKey }) {
  const params = new URLSearchParams({
    Resource: resource,
    Type: 'Photo',
    ID: `${listingKey}:*`,
    Location: '1',
  });
  const url = `${session.urls.getObject}?${params.toString()}`;
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
    throw new Error(`RETS GetObject HTTP ${res.status}: ${text.slice(0, 500)}`);
  }
  const urls = [...text.matchAll(/Location\s*[:=]\s*(\S+)/gi)].map((m) => m[1].trim());
  return { photoCount: urls.length, urls, raw: text.slice(0, 2000) };
}

exports.handler = async (event) => {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };
  try {
    const qs = event.queryStringParameters || {};
    const mode = qs.mode || 'search';

    if (mode === 'debug') {
      const u = process.env.RETS_USERNAME || '';
      const p = process.env.RETS_PASSWORD || '';
      const l = process.env.RETS_LOGIN_URL || '';
      // Never return the actual password. Return enough to catch trailing/leading
      // whitespace, wrong length, or accidental quote characters without exposing the secret.
      const edge = (s) => (s.length ? `"${s[0]}"..."${s[s.length - 1]}"` : '(empty)');
      const debugInfo = {
        usernameLength: u.length,
        usernameFirstLastChar: edge(u),
        usernameHasLeadingOrTrailingSpace: u !== u.trim(),
        passwordLength: p.length,
        passwordFirstLastChar: edge(p),
        passwordHasLeadingOrTrailingSpace: p !== p.trim(),
        loginUrl: l,
        loginUrlHasLeadingOrTrailingSpace: l !== l.trim(),
        authHeaderPreview: `Basic ${b64(`${u}:${p}`)}`.slice(0, 20) + '...',
        retsVersionHeaderSent: RETS_VERSION,
        userAgentHeaderSent: USER_AGENT,
      };
      return { statusCode: 200, headers: cors, body: JSON.stringify(debugInfo, null, 2) };
    }

    const session = await retsLogin();

    let result;
    if (mode === 'metadata') {
      result = await retsGetMetadata(session, { resource: qs.resource, class: qs.class });
      return { statusCode: 200, headers: { ...cors, 'Content-Type': 'text/xml' }, body: result };
    } else if (mode === 'search') {
      result = await retsSearch(session, {
        resource: qs.resource,
        class: qs.class,
        mlsNumber: qs.mlsNumber,
        address: qs.address,
      });
    } else if (mode === 'photos') {
      if (!qs.listingKey) throw new Error('Provide listingKey');
      result = await retsGetPhotos(session, { resource: qs.resource, listingKey: qs.listingKey });
    } else {
      throw new Error(`Unknown mode "${mode}" — use metadata, search, or photos`);
    }

    return { statusCode: 200, headers: cors, body: JSON.stringify(result, null, 2) };
  } catch (err) {
    return { statusCode: 500, headers: cors, body: JSON.stringify({ error: err.message }) };
  }
};
