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
//     -> raw parsed COMPACT-DECODED rows for that listing, ALL fields, unfiltered.
//
//   mode=report&mlsNumber=21327448  (or &address=...)
//     -> the real production mode. Returns { found, agentFacing, clientSafe } for a single listing —
//        agentFacing is the full record (for the agent's own internal tool view, includes showing
//        instructions/access info/etc.), clientSafe is the filtered subset safe to send a buyer
//        (built by buildClientSafeRecord() below). This is what showing-request.html should call.
//
//   mode=citysearch&city=Rhome&limit=12  (or &subdivision=Robson+Ranch instead of &city=)
//     -> for public card grids (e.g. a town's "Homes for Sale" section). Returns
//        { count, listings: [{ clientSafe, photoUrl }, ...] } for every Active listing in that city
//        (or subdivision, for a master-planned community that isn't its own municipality — e.g.
//        Robson Ranch, which sits inside Denton/Krugerville and has no City lookup entry of its own).
//        NEVER returns agentFacing data — this is a public-facing endpoint. photoUrl is best-effort
//        (primary photo only, via GetObject ":0") and may be null if the fetch fails for a listing.
//
//   mode=openhouses&listingId=20902063  (or &startDate=2026-08-22&endDate=2026-08-24 for a date range)
//     -> queries the separate Openhouse RETS resource (confirmed to exist on this server —
//        distinct from Property, joined by ListingId). Returns { count, openHouses: [...] } with
//        date/startTime/endTime/remarks/type/refreshments. Date-range mode has no city filter built
//        in (Openhouse has no City field) — for OpenDFWHomes' per-listing curated workflow, listingId
//        mode is the more directly useful one; date-range mode is there for a future "browse all
//        upcoming open houses" feature, which would need to cross-reference results against
//        mode=citysearch or mode=report to get address/photo/price for display.
//
//   mode=cardbuilder&mlsNumber=20902063
//     -> the real production endpoint for OpenDFWHomes.com. Replaces the manual
//        Matrix-PDF-parsing + pdfimages workflow: given one MLS#, pulls the property
//        record, finds its soonest upcoming open house via mode=openhouses internally,
//        fetches the primary photo and embeds it as base64 (matching the site's
//        existing fully self-contained card pattern — no external image hosting),
//        and returns a ready-to-paste { html: "<article class=\"card\">...</article>" }
//        block matching the site's exact existing markup. Also returns { raw: {...} }
//        with the individual field values, for updating hero stats/listing_expiration_tracker.csv.
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

// Builds a DMQL2 query. mlsNumber match is exact; address match is a loose CONTAINS-style
// match on StreetName since we don't yet know NTREIS's exact address field breakdown
// (StreetNumber/StreetName/StreetSuffix are usually separate fields, not one "Address" field —
// confirm via mode=metadata before relying on address search for real).
function buildQuery({ mlsNumber, address }) {
  if (mlsNumber) {
    // Confirmed via live metadata: SystemName is "ListingId" (Character, max 30) —
    // this is NOT the same as ListingKey/ListingKeyNumeric (internal DB IDs).
    return `(ListingId=${mlsNumber})`;
  }
  if (address) {
    return `(StreetName=~*${address}*)`;
  }
  throw new Error('Provide mlsNumber or address');
}

// DMQL2 conjunction: (Field1=Value1),(Field2=Value2) — comma at this bracket
// level is AND, per RETS 1.8 DMQL2 syntax used elsewhere in this file's
// confirmed-working single-MLS# query.
// City (and StandardStatus) are Interpretation=Lookup fields — RETS stores a
// short internal code and only decodes it to display text on OUTPUT. Confirmed
// live: (City=Rhome) and (StandardStatus=Active) both returned ReplyCode 20206
// "Invalid Query Syntax". The real codes come from METADATA-LOOKUP_TYPE:
// StandardStatus's "Active" code is the constant "ACT". City's code is a
// numeric ID that's DIFFERENT PER CITY (Rhome=1252) and can't be hardcoded —
// must be resolved from the live lookup table for whatever city is requested.
const ACTIVE_STATUS_CODE = 'ACT';

// OpenHouseStatus (on the separate Openhouse resource, not Property) has its
// own lookup table — confirmed via mode=lookups&resource=Openhouse: Active's
// code is also "ACT", same convention as StandardStatus. This resource is
// otherwise well-behaved: ListingId and OpenHouseDate are plain fields (not
// Lookup), and a simple hyphenated date range (2026-08-22-2026-08-24) works
// as-is — confirmed live, no special syntax needed unlike City/StandardStatus.
const OPENHOUSE_ACTIVE_CODE = 'ACT';

function buildOpenHouseByListingQuery(listingId) {
  return `(ListingId=${listingId}) AND (OpenHouseStatus=${OPENHOUSE_ACTIVE_CODE})`;
}

// Formats an open house date/start/end into OpenDFWHomes' exact badge text
// style: "Sat Aug 15 · 1:00–3:00PM" when both times share a meridiem, or
// "Sat Aug 15 · 11:00AM–1:00PM" when they don't.
const DAY_ABBR = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTH_ABBR = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
// Matches OpenDFWHomes' own data-day values — only fri/sat/sun are wired to
// filter tabs today, but every day gets a real 3-letter code so the existing
// hideExpiredListings()/sortListingsByDate() date-parsing logic (which reads
// this exact badge text) keeps working regardless of which day it lands on.
const DAY_CODE = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

function formatOpenHouseBadge(dateStr, startIso, endIso) {
  // dateStr is "YYYY-MM-DD"; startIso/endIso are full ISO datetimes in the
  // listing's local time already (RETS doesn't apply timezone conversion here).
  const [y, m, d] = dateStr.split('-').map(Number);
  const dateObj = new Date(y, m - 1, d);
  const dayName = DAY_ABBR[dateObj.getDay()];
  const monthName = MONTH_ABBR[m - 1];

  function parseTime(iso) {
    const match = iso.match(/T(\d{2}):(\d{2})/);
    if (!match) return null;
    let hour = parseInt(match[1], 10);
    const minute = match[2];
    const meridiem = hour >= 12 ? 'PM' : 'AM';
    hour = hour % 12;
    if (hour === 0) hour = 12;
    return { hour, minute, meridiem };
  }

  const start = parseTime(startIso);
  const end = parseTime(endIso);
  if (!start || !end) return `${dayName} ${monthName} ${d}`;

  const startStr = start.meridiem === end.meridiem
    ? `${start.hour}:${start.minute}`
    : `${start.hour}:${start.minute}${start.meridiem}`;
  const endStr = `${end.hour}:${end.minute}${end.meridiem}`;

  return `${dayName} ${monthName} ${d} \u00b7 ${startStr}\u2013${endStr}`;
}

function dayCodeFromDate(dateStr) {
  const [y, m, d] = dateStr.split('-').map(Number);
  return DAY_CODE[new Date(y, m - 1, d).getDay()];
}

// Escapes a string for safe use inside a single-quoted JS string literal
// (the onclick="openModal('...', '...')" attributes on OpenDFWHomes' cards).
function escapeJsString(str) {
  return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function escapeHtmlText(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildOpenHouseByDateRangeQuery(startDate, endDate) {
  return `(OpenHouseDate=${startDate}-${endDate}) AND (OpenHouseStatus=${OPENHOUSE_ACTIVE_CODE})`;
}

async function resolveCityCode(session, cityName) {
  const xml = await retsGetLookupValues(session, { lookupName: 'City' });
  const parsed = parseCompact(xml); // METADATA responses use the same COLUMNS/DATA/DELIMITER shape as search results
  const match = parsed.records.find(
    (r) => (r.LongValue || '').trim().toLowerCase() === cityName.trim().toLowerCase()
  );
  if (!match) {
    throw new Error(`City "${cityName}" not found in the City lookup table — check spelling/capitalization`);
  }
  return match.Value;
}

async function buildCityActiveQuery(session, city) {
  // CONFIRMED WORKING against this NTREIS server: explicit uppercase "AND"
  // (with spaces) between two SEPARATELY parenthesized clauses. Verified live —
  // returned exactly the 77 real Active Rhome listings, all correct.
  // Both other forms tried first were rejected with ReplyCode 20206 "Invalid
  // Query Syntax": (City=X),(Status=Y) and (City=X,Status=Y). Neither the
  // RETS-spec "textbook" form nor the simpler single-parens form worked here —
  // this server's dialect specifically wants the literal " AND " keyword.
  //
  // IMPORTANT: filters on MlsStatus, not StandardStatus. StandardStatus is
  // RESO-standardized and collapses Active Contingent (AC), Active Kick Out
  // (AKO), and Active Option Contract (AOC) all into the same "Active"/ACT
  // bucket — filtering on it alone would silently include listings that are
  // already under some form of contract. MlsStatus is Matrix's own native
  // field and DOES distinguish these (confirmed via mode=lookups: ACT/AC/
  // AKO/AOC are separate codes there) — this is what actually limits public
  // "Homes for Sale" display to genuinely, fully available listings.
  const cityCode = await resolveCityCode(session, city);
  return `(City=${cityCode}) AND (MlsStatus=${ACTIVE_STATUS_CODE})`;
}

// For a master-planned community that ISN'T its own municipality (e.g. Robson
// Ranch, which sits inside Denton/Krugerville) — City search won't find it,
// since there's no matching City lookup entry for the community name. Use
// SubdivisionName instead. Confirmed via metadata: SubdivisionName is a plain
// Character field (not Lookup), so the literal text can be queried directly —
// no code-resolution step needed, unlike City.
function buildSubdivisionActiveQuery(subdivision) {
  // Same MlsStatus reasoning as buildCityActiveQuery above.
  return `(SubdivisionName=${subdivision}) AND (MlsStatus=${ACTIVE_STATUS_CODE})`;
}

// ---------------------------------------------------------------------------
// CLIENT-SAFE FILTERING
//
// Confirmed against a real NTREIS "Customer Full" report (2026-08-20, MLS#
// 21355847) side by side with our raw search response for MLS# 21327448.
// Customer Full is broad-inclusion, not a short curated list — nearly every
// property-characteristic field shows (heating, cooling, roof, construction,
// flooring, fence, foundation, appliances, interior/exterior features, HOA
// dues/includes, taxes, legal description, lot/block, community amenities).
// So this uses a BLACKLIST (exclude sensitive/internal fields, pass through
// everything else) rather than a whitelist — matches Customer Full's actual
// behavior and means new NTREIS fields default to visible instead of
// silently hidden until someone remembers to whitelist them.
//
// Room-by-room dimensions are NOT included — that data lives in a separate
// PropertyRooms RETS resource (a second query per listing) and was
// deliberately left out of scope for this phase.
// ---------------------------------------------------------------------------

// Named fields to strip, grouped by why. Update this list, not the whitelist
// approach, if NTREIS adds new sensitive fields in the future.
const CLIENT_EXCLUDE_FIELDS = new Set([
  // Showing coordination / access — never buyer-facing
  'PrivateRemarks', 'PrivateOfficeRemarks',
  'OwnerName', 'OwnerPhone', 'OwnerPhoneAlternative', 'OwnerPays', 'OwnerPermissionToVideoYN',
  'OccupantName', 'OccupantPhone', 'OccupantPhoneAlternative', 'OccupantType',
  'ShowingContactPhone', 'ShowingContactPhoneExt', 'ShowingContactType',
  'ShowingInstructions', 'ShowingInstructionsSecured', 'ShowingRequirements', 'ShowingAttendedYN',
  'KeyboxNumber', 'LockBoxType', 'LockBoxLocation', 'AccessCode',
  'ConsentforVisitorstoRecord', 'NoticeSurveillanceDevicesPresent',

  // Agent/office contact details — Customer Full shows agent + office NAME
  // only (matches the "trims to office+agent name" behavior already
  // confirmed), never phone/email/internal IDs.
  'ListAgentDirectPhone', 'ListAgentEmail', 'ListAgentMlsId', 'ListAgentKeyNumeric',
  'ListAgentMLSProvider', 'ListAgentTextingAllowedYN',
  'ListOfficePhone', 'ListOfficeMlsId', 'ListOfficeKeyNumeric',
  'ListOfficeManager', 'ListOfficeManagerKeyNumeric', 'ListOfficeManagerLicense',
  'ListOfficeManagerMLSID', 'ListOfficeManagerPhone',
  'CoListAgentDirectPhone', 'CoListAgentEmail', 'CoListAgentFullName', 'CoListAgentKeyNumeric', 'CoListAgentMlsId',
  'CoListOfficeKeyNumeric', 'CoListOfficeMlsId', 'CoListOfficeName', 'CoListOfficePhone',
  'CoListOfficeManager', 'CoListOfficeManagerKeyNumeric', 'CoListOfficeManagerLicense',
  'CoListOfficeManagerMLSID', 'CoListOfficeManagerPhone',
  'AttributionContact', 'PropertyManagedBy',

  // Any existing/prior buyer's agent info — not relevant to a new prospective
  // buyer and could leak details about another party's transaction.
  'BuyerAgentDirectPhone', 'BuyerAgentEmail', 'BuyerAgentFullName', 'BuyerAgentKeyNumeric', 'BuyerAgentMlsId',
  'BuyerOfficeKeyNumeric', 'BuyerOfficeMlsId', 'BuyerOfficeName', 'BuyerOfficePhone',
  'BuyerOfficeManager', 'BuyerOfficeManagerKeyNumeric', 'BuyerOfficeManagerLicense',
  'BuyerOfficeManagerMLSID', 'BuyerOfficeManagerPhone',
  'BuyerTeamKey', 'BuyerTeamKeyNumeric', 'BuyerTeamName', 'BuyerFinancing',
  'BuyerAgentTextingAllowedYN',
  'CoBuyerAgentDirectPhone', 'CoBuyerAgentEmail', 'CoBuyerAgentFullName', 'CoBuyerAgentKeyNumeric', 'CoBuyerAgentMlsId',
  'CoBuyerOfficeKeyNumeric', 'CoBuyerOfficeMlsId', 'CoBuyerOfficeName', 'CoBuyerOfficePhone',
  'CoBuyerOfficeManager', 'CoBuyerOfficeManagerKeyNumeric', 'CoBuyerOfficeManagerLicense',
  'CoBuyerOfficeManagerMLSID', 'CoBuyerOfficeManagerPhone', 'CoBuyerAgentTextingAllowedYN',

  // Financial / lending — not shown on Customer Full
  'Loan1Amount', 'Loan1InterestRate', 'Loan1Years', 'LoanBalance', 'LoanInterestRate',
  'LoanPayment', 'LoanPaymentType', 'LoanType', 'MortgageCompany', 'OriginalMortgageDate',
  'SecondMortgageYN', 'LenderName', 'DepositAmount', 'DepositPet',
  'GrossAnnualIncome', 'GrossAnnualExpenses', 'NetOperationIncome', 'InsuranceExpense',
  'CapitalizationRate', 'GrossIncomeMultiplier', 'OperatingExpenseIncludes', 'MoniesRequired',
  'ClosePrice', 'CloseDate', 'PurchaseContractDate', 'ContingencyInfo',
  'SellerContributions', 'ThirdPartyAssistanceProgramYN',

  // Internal system fields / keys / timestamps — not on Customer Full
  'ListingKeyNumeric', 'ListTeamKey', 'ListTeamKeyNumeric', 'ListTeamName',
  'OriginatingSystemKey', 'OriginatingSystemTimestamp', 'OriginatingSystemName',
  'DOCBOX_GUID', 'DocBox_ModificationTimestamp', 'DocBox_NumMlsDocuments',
  'DocBox_NumPrivateDocuments', 'DocBox_NumPublicDocuments',
  'DocumentManagerMLSCount', 'DocumentManagerPrivateCount', 'DocumentManagerPublicCount', 'DocumentManagerTotalCount',
  'PropertyKey', 'PropertyMatch', 'GeocodeConfidence', 'USProperty_MUI', 'RETSUpdateTransactionYN',
  'ModificationTimestamp', 'StatusChangeTimestamp', 'PhotosChangeTimestamp', 'PriceChangeTimestamp',
  'ListingService', 'ListSource', 'ListSourceOriginal', 'ListSourceVendor', 'ListMLSProvider',
  'SyndicateTo', 'InternetAddressDisplayYN', 'InternetAutomatedValuationDisplayYN',
  'InternetConsumerCommentYN', 'InternetEntireListingDisplayYN',
  'ListingAgreement', 'ListingContractDate', 'ExpirationDateOption', 'HoldDate',
  'WithdrawnDate', 'CancellationDate', 'OffMarketDate', 'PreviousListPrice', 'PreviousStatus',
  'MLSNumberSaleOrLease', 'ParcelNumber2', 'BuildingAreaSource', 'LotSizeSource',
  'TitleCompanyClosing', 'TitleCompanyLocation', 'TitleCompanyPhone', 'TitleCompanyPreferred',

  // Coordinates: manual explicitly restricts displaying actual lat/long
  // values per NTREIS's mapping-vendor licensing agreement.
  'Latitude', 'Longitude',
]);

// Ratio/analytics fields (RATIO_*) and internal *KeyNumeric IDs beyond the
// ones already named above — pattern-based catch-all so newly added NTREIS
// fields of these shapes are excluded by default too, not just today's list.
function isClientExcluded(fieldName) {
  if (CLIENT_EXCLUDE_FIELDS.has(fieldName)) return true;
  if (fieldName.startsWith('RATIO_')) return true;
  if (/KeyNumeric$/.test(fieldName)) return true;
  return false;
}

// Builds the buyer-facing subset of a full RETS record. Field order in the
// output follows the field order of the input record.
function buildClientSafeRecord(fullRecord) {
  const safe = {};
  for (const [key, value] of Object.entries(fullRecord)) {
    if (!isClientExcluded(key)) safe[key] = value;
  }
  // Convenience: a single formatted address string, built from the parts
  // Customer Full displays as one line (e.g. "2416 Fall Leaf Court, Denton, TX 76209").
  const parts = [
    fullRecord.StreetNumber, fullRecord.StreetDirPrefix, fullRecord.StreetName,
    fullRecord.StreetSuffix, fullRecord.StreetDirSuffix,
  ].filter(Boolean).join(' ');
  const unit = fullRecord.UnitNumber ? ` #${fullRecord.UnitNumber}` : '';
  const cityStateZip = [fullRecord.City, fullRecord.StateOrProvince].filter(Boolean).join(', ')
    + (fullRecord.PostalCode ? ` ${fullRecord.PostalCode}` : '');
  safe.FormattedAddress = [parts + unit, cityStateZip].filter(Boolean).join(', ');
  return safe;
}

async function retsSearch(session, { resource = 'Property', class: cls = 'Property', mlsNumber, address, rawQuery, limit = 1 }) {
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

// Lists every top-level RESOURCE this RETS server exposes (Property, OpenHouse,
// Media, etc.) — the resource-scoped metadata above only tells you about ONE
// resource you already know the name of; this is how we check whether a
// resource like "OpenHouse" exists at all before trying to query it.
async function retsGetSystemMetadata(session) {
  const params = new URLSearchParams({
    Type: 'METADATA-SYSTEM',
    ID: '*',
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
    throw new Error(`RETS GetMetadata (system) HTTP ${res.status}: ${text.slice(0, 500)}`);
  }
  return text;
}

// For Interpretation=Lookup fields (e.g. City, StandardStatus), RETS stores a
// short internal code and only DECODES it to the friendly display text on
// OUTPUT (with Format=COMPACT-DECODED). Queries must use the raw short code,
// not the decoded text — confirmed the hard way: (City=Rhome) and
// (StandardStatus=Active) both returned ReplyCode 20206 "Invalid Query Syntax"
// even though those are exactly the values shown in COMPACT-DECODED results.
// This pulls the actual Value<->LongValue code table for a given LookupName
// (visible in the field's own metadata row) so we can find the right code.
async function retsGetLookupValues(session, { resource = 'Property', lookupName }) {
  const params = new URLSearchParams({
    Type: 'METADATA-LOOKUP_TYPE',
    ID: `${resource}:${lookupName}`,
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
    throw new Error(`RETS GetMetadata (lookup) HTTP ${res.status}: ${text.slice(0, 500)}`);
  }
  return text;
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

// Best-effort single-photo variant of retsGetPhotos, for card grids where
// fetching all photos per listing (retsGetPhotos above) would mean too many
// round trips. Per the manual, ":0" is the primary photo. Never throws —
// a missing/failed photo just means the card renders without one.
async function retsGetPrimaryPhoto(session, { resource = 'Property', listingKey }) {
  try {
    const params = new URLSearchParams({
      Resource: resource,
      Type: 'Photo',
      ID: `${listingKey}:0`,
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
    if (!res.ok) return null;
    const text = await res.text();
    const match = text.match(/Location\s*[:=]\s*(\S+)/i);
    return match ? match[1].trim() : null;
  } catch {
    return null;
  }
}

// OpenDFWHomes.com embeds every listing photo as a base64 data: URI directly
// in the HTML (a fully self-contained static site, no external image
// hosting) — this fetches the actual photo bytes from the Location URL
// above and re-encodes them, matching that existing pattern.
async function fetchImageAsBase64(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    const buf = await res.arrayBuffer();
    const base64 = Buffer.from(buf).toString('base64');
    const contentType = res.headers.get('content-type') || 'image/jpeg';
    return `data:${contentType};base64,${base64}`;
  } catch {
    return null;
  }
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

      let authSchemeChallenged = '(could not probe — see authProbeError)';
      let authProbeError = null;
      try {
        const probe = await fetch(l, {
          headers: { 'RETS-Version': RETS_VERSION, 'User-Agent': USER_AGENT, Accept: '*/*' },
        });
        authSchemeChallenged = probe.status === 401
          ? (probe.headers.get('www-authenticate') || '(401 but no WWW-Authenticate header)')
          : `(no 401 — got HTTP ${probe.status} unauthenticated, unexpected)`;
      } catch (e) {
        authProbeError = e.message;
      }

      const debugInfo = {
        usernameLength: u.length,
        usernameFirstLastChar: edge(u),
        usernameHasLeadingOrTrailingSpace: u !== u.trim(),
        passwordLength: p.length,
        passwordFirstLastChar: edge(p),
        passwordHasLeadingOrTrailingSpace: p !== p.trim(),
        loginUrl: l,
        loginUrlHasLeadingOrTrailingSpace: l !== l.trim(),
        authSchemeChallenged,
        authProbeError,
        retsVersionHeaderSent: RETS_VERSION,
        userAgentHeaderSent: USER_AGENT,
      };
      return { statusCode: 200, headers: cors, body: JSON.stringify(debugInfo, null, 2) };
    }

    const session = await retsLogin();

    let result;
    if (mode === 'resources') {
      // Lists every top-level resource this server exposes — use this to
      // check whether something like "OpenHouse" exists before querying it.
      result = await retsGetSystemMetadata(session);
      return { statusCode: 200, headers: { ...cors, 'Content-Type': 'text/xml' }, body: result };
    } else if (mode === 'metadata') {
      result = await retsGetMetadata(session, { resource: qs.resource, class: qs.class });
      return { statusCode: 200, headers: { ...cors, 'Content-Type': 'text/xml' }, body: result };
    } else if (mode === 'search') {
      result = await retsSearch(session, {
        resource: qs.resource,
        class: qs.class,
        mlsNumber: qs.mlsNumber,
        address: qs.address,
      });
    } else if (mode === 'report') {
      // Returns BOTH the full agent-facing record (everything, for the
      // agent's own internal tool view) and a filtered clientSafe record
      // (for anything actually sent to a buyer) side by side, for a single
      // listing. Requires mlsNumber (or address) to resolve to exactly one match.
      const searchResult = await retsSearch(session, {
        resource: qs.resource,
        class: qs.class,
        mlsNumber: qs.mlsNumber,
        address: qs.address,
      });
      if (!searchResult.records.length) {
        result = { found: false, replyCode: searchResult.replyCode, replyText: searchResult.replyText };
      } else {
        const fullRecord = searchResult.records[0];
        result = {
          found: true,
          agentFacing: fullRecord,
          clientSafe: buildClientSafeRecord(fullRecord),
        };
      }
    } else if (mode === 'lookups') {
      if (!qs.lookupName) throw new Error('Provide lookupName (e.g. City, StandardStatus — the LookupName from the field\'s own metadata row)');
      result = await retsGetLookupValues(session, { resource: qs.resource, lookupName: qs.lookupName });
      return { statusCode: 200, headers: { ...cors, 'Content-Type': 'text/xml' }, body: result };
    } else if (mode === 'rawsearch') {
      // DEBUG ONLY — lets us test different DMQL2 query strings directly via
      // URL param, without a redeploy per attempt. Not used by any real page.
      if (!qs.query) throw new Error('Provide query (a raw DMQL2 string, e.g. (City=Rhome))');
      result = await retsSearch(session, {
        resource: qs.resource,
        class: qs.class,
        rawQuery: qs.query,
        limit: qs.limit ? parseInt(qs.limit, 10) : 5,
      });
    } else if (mode === 'cardbuilder') {
      // Builds a complete, ready-to-paste OpenDFWHomes.com <article class="card">
      // block for one listing: pulls the property record, finds its soonest
      // upcoming open house date/time, fetches the primary photo and embeds
      // it as base64 (matching the site's existing fully self-contained
      // pattern), and formats everything into the exact markup already used
      // on the site. Replaces the manual Matrix-PDF-parsing + pdfimages steps.
      if (!qs.mlsNumber) throw new Error('Provide mlsNumber');

      const propertyResult = await retsSearch(session, {
        resource: qs.resource,
        class: qs.class,
        mlsNumber: qs.mlsNumber,
      });
      const record = propertyResult.records[0];
      if (!record) {
        result = { found: false, mlsNumber: qs.mlsNumber };
      } else {
        const ohQuery = buildOpenHouseByListingQuery(qs.mlsNumber);
        const ohResult = await retsSearch(session, {
          resource: 'Openhouse',
          class: 'OpenHouse',
          rawQuery: ohQuery,
          limit: 25,
        });
        // Take the soonest upcoming open house (results aren't guaranteed
        // sorted server-side, so sort by date+time here).
        const upcoming = ohResult.records
          .filter((r) => r.OpenHouseDate && r.OpenHouseStartTime)
          .sort((a, b) => new Date(a.OpenHouseStartTime) - new Date(b.OpenHouseStartTime))[0];

        const photoUrl = await retsGetPrimaryPhoto(session, {
          resource: qs.resource,
          listingKey: record.ListingKeyNumeric,
        });
        const photoBase64 = photoUrl ? await fetchImageAsBase64(photoUrl) : null;

        const addressParts = [record.StreetNumber, record.StreetDirPrefix, record.StreetName, record.StreetSuffix, record.StreetDirSuffix]
          .filter(Boolean).join(' ') + (record.UnitNumber ? (' #' + record.UnitNumber) : '');
        const price = parseFloat(record.ListPrice) || 0;
        const beds = record.BedroomsTotal || '';
        const full = parseInt(record.BathroomsFull, 10) || 0;
        const half = parseInt(record.BathroomsHalf, 10) || 0;
        const baths = half ? (full + half * 0.5) : full;
        const sqft = record.LivingArea ? parseFloat(record.LivingArea).toLocaleString('en-US') : '';
        const cityStateZip = `${record.City || ''}, ${record.StateOrProvince === 'Texas' ? 'TX' : (record.StateOrProvince || '')} ${record.PostalCode || ''}`.trim();
        const subdivision = record.SubdivisionName || '';

        const badge = upcoming
          ? formatOpenHouseBadge(upcoming.OpenHouseDate, upcoming.OpenHouseStartTime, upcoming.OpenHouseEndTime)
          : null;
        const dayCode = upcoming ? dayCodeFromDate(upcoming.OpenHouseDate) : 'soon';

        const addrEsc = escapeHtmlText(addressParts);
        const addrJs = escapeJsString(addressParts);
        const badgeJs = badge ? escapeJsString(badge) : '';

        const photoTag = photoBase64
          ? `<img src="${photoBase64}" alt="${addrEsc}" loading="lazy">`
          : '<!-- photo fetch failed — add manually -->';

        const html = `    <article class="card" data-day="${dayCode}">
      <div class="card-photo">
        ${photoTag}
        <span class="tag">NEW</span>
        ${badge ? `<span class="oh-badge">${escapeHtmlText(badge)}</span>` : ''}
      </div>
      <div class="card-body">
        <div class="card-top">
          <p class="price">$${price.toLocaleString('en-US')}</p>
          <p class="specs">${beds} bd &middot; ${baths} ba &middot; ${sqft} sf</p>
        </div>
        <p class="addr">${addrEsc}</p>
        <p class="citystate">${escapeHtmlText(cityStateZip)}${subdivision ? ` &middot; ${escapeHtmlText(subdivision)}` : ''}</p>
        <div class="card-foot">
          <span class="broker">Listed by ${escapeHtmlText(record.ListOfficeName || '')}<span class="agent">Agent: ${escapeHtmlText(record.ListAgentFullName || '')}</span></span>
          <button class="btn-request" onclick="openModal('${addrJs}', '${badgeJs}')">Request showing</button>
        </div>
      </div>
    </article>`;

        result = {
          found: true,
          html,
          photoFetchFailed: !photoBase64,
          openHouseFound: !!upcoming,
          raw: {
            mlsNumber: qs.mlsNumber,
            address: addressParts,
            price,
            beds,
            baths,
            sqft,
            city: record.City,
            subdivision,
            listAgent: record.ListAgentFullName,
            listOffice: record.ListOfficeName,
            openHouseBadge: badge,
            dayCode,
          },
        };
      }
    } else if (mode === 'openhouses') {
      // Two ways to call this:
      //   &listingId=20902063           -> all upcoming open houses for one listing
      //   &startDate=2026-08-22&endDate=2026-08-24 -> all open houses in a date range,
      //     across the entire NTREIS coverage area (no city filter — the Openhouse
      //     resource has no City field of its own; callers wanting a specific city
      //     should cross-reference the returned ListingId values against a
      //     mode=citysearch result, or look up each one via mode=report).
      // Returns clientSafe-shaped rows — OpenHouseRemarks is the only field that
      // could theoretically contain agent-written text, and it's public-facing
      // open house info by nature, so no filtering needed here.
      let ohQuery;
      if (qs.listingId) {
        ohQuery = buildOpenHouseByListingQuery(qs.listingId);
      } else if (qs.startDate && qs.endDate) {
        ohQuery = buildOpenHouseByDateRangeQuery(qs.startDate, qs.endDate);
      } else {
        throw new Error('Provide listingId, or both startDate and endDate (YYYY-MM-DD)');
      }
      const limit = qs.limit ? Math.min(parseInt(qs.limit, 10) || 25, 100) : 25;
      const searchResult = await retsSearch(session, {
        resource: 'Openhouse',
        class: 'OpenHouse',
        rawQuery: ohQuery,
        limit,
      });
      result = {
        count: searchResult.records.length,
        openHouses: searchResult.records.map((r) => ({
          openHouseKey: r.OpenHouseKeyNumeric,
          listingId: r.ListingId,
          date: r.OpenHouseDate,
          startTime: r.OpenHouseStartTime,
          endTime: r.OpenHouseEndTime,
          remarks: r.OpenHouseRemarks || '',
          type: r.OpenHouseType || '',
          refreshments: r.Refreshments || '',
        })),
      };
    } else if (mode === 'citysearch') {
      // For public card grids (e.g. a town's "Homes for Sale" section).
      // Returns clientSafe property data PLUS listing agent/office name+phone+email —
      // unlike mode=report's clientSafe (which strips agent contact info because that's
      // for an internal buyer-relationship tool where the point is the AGENT controls
      // contact, not the buyer). Here, on a public marketing page, showing listing
      // agent/office identity and contact is standard MLS/IDX display practice (same
      // as Zillow/Realtor.com) — this is a different, legitimate display context.
      if (!qs.city && !qs.subdivision) throw new Error('Provide city or subdivision');
      const limit = qs.limit ? Math.min(parseInt(qs.limit, 10) || 12, 24) : 12;
      const cityQuery = qs.subdivision
        ? buildSubdivisionActiveQuery(qs.subdivision)
        : await buildCityActiveQuery(session, qs.city);
      const searchResult = await retsSearch(session, {
        resource: qs.resource,
        class: qs.class,
        rawQuery: cityQuery,
        limit,
      });
      const listings = await Promise.all(
        searchResult.records.map(async (record) => {
          const photoUrl = await retsGetPrimaryPhoto(session, {
            resource: qs.resource,
            listingKey: record.ListingKeyNumeric,
          });
          return {
            ...buildClientSafeRecord(record),
            ListAgentFullName: record.ListAgentFullName || '',
            ListAgentDirectPhone: record.ListAgentDirectPhone || '',
            ListAgentEmail: record.ListAgentEmail || '',
            ListOfficeName: record.ListOfficeName || '',
            photoUrl,
          };
        })
      );
      result = {
        count: listings.length,
        listings,
        // Diagnostics — helps distinguish "genuinely zero active listings"
        // from "the query itself failed silently." Not needed by the page,
        // just useful when troubleshooting an empty result.
        _debug: {
          queryUsed: cityQuery,
          replyCode: searchResult.replyCode,
          replyText: searchResult.replyText,
          rawRowCount: searchResult.count,
        },
      };
    } else if (mode === 'photos') {
      if (!qs.listingKey) throw new Error('Provide listingKey');
      result = await retsGetPhotos(session, { resource: qs.resource, listingKey: qs.listingKey });
    } else {
      throw new Error(`Unknown mode "${mode}" — use metadata, search, report, citysearch, or photos`);
    }

    return { statusCode: 200, headers: cors, body: JSON.stringify(result, null, 2) };
  } catch (err) {
    return { statusCode: 500, headers: cors, body: JSON.stringify({ error: err.message }) };
  }
};
