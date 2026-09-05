// ================================================================
// WORKER.JS — DigiStore DZ
// Cloudflare Worker (no Node.js, no Express, no dependencies)
// Deploy via: npx wrangler deploy
//
// File storage: Cloudflare R2 via the native `env.BUCKET` binding.
// Upload flow: browser → Worker → R2 (no presigned URLs).
// Delete flow: Worker → R2.
//
// Payments: SlickPay (CIB / EDAHABIA via SATIM). Secret key lives ONLY in
// the Worker secret `SLICKPAY_KEY` (set with `wrangler secret put`), never
// in wrangler.jsonc `vars` and never shipped to the browser.
//
// Data + auth: Supabase (Postgres via its REST API — PostgREST — plus
// Supabase Auth/GoTrue). All privileged reads/writes here use the
// `SUPABASE_SERVICE_ROLE_KEY` Worker secret, which bypasses Postgres Row
// Level Security entirely — that's what lets this Worker do things an
// ordinary signed-in visitor's key can't (list all users, write another
// user's purchase record, delete an account, etc). Never expose that key
// to the browser; only the public `SUPABASE_ANON_KEY` / `SUPABASE_URL`
// (in wrangler.jsonc `vars`) and firebase.js's client-side equivalent are
// meant to be public.
//
// Collections here still use Firestore-style names (e.g. 'purchases',
// 'products/<id>/private') — they map onto rows in one generic
// `public.documents` table (see supabase/schema.sql), not separate SQL
// tables per collection. See the `Docs` helper below.
// ================================================================

// ---------------------------------------------------------------
// Admin-only route protection
// ---------------------------------------------------------------
// Routes that let the caller write/delete storage (upload-file,
// delete-file) must never be reachable by an anonymous visitor —
// only the admin should be able to call them.
//
// This used to be (and still is) proven server-side, never trusted from
// a client-visible static secret: the admin panel signs the admin into
// real Supabase Auth (see the `Auth` object in supabase.js) and sends the
// resulting access token as `Authorization: Bearer <token>`. This
// function hands that token to Supabase's own GoTrue `/auth/v1/user`
// endpoint, which verifies its signature/expiry and tells us which
// Supabase account it actually belongs to — a token can't be forged or
// reused for a different account. We then check that account's email
// against the configured admin email.
//
// Set up once:
//   1. Supabase dashboard → Authentication → Users → Add user (the
//      admin's real login email + a strong password).
//   2. Put that same email in ADMIN_EMAIL in supabase.js.
//   3. npx wrangler secret put ADMIN_EMAIL   (same email, on the Worker)
async function supabaseGetUser(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const m = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!m) return { ok: false, status: 401, error: 'Missing bearer token.' };
  const accessToken = m[1];

  if (!env.SUPABASE_URL) {
    return { ok: false, status: 500, error: 'SUPABASE_URL is not configured on this Worker.' };
  }

  let user;
  try {
    const res = await fetch(`${env.SUPABASE_URL.replace(/\/+$/, '')}/auth/v1/user`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        // Either the anon or the service-role key works as `apikey` here;
        // the anon key is enough since we're just asking "whose token is
        // this", not doing a privileged operation.
        apikey: env.SUPABASE_ANON_KEY || env.SUPABASE_SERVICE_ROLE_KEY || '',
      },
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      return { ok: false, status: 401, error: body.msg || body.error_description || 'Invalid or expired session — please log in again.' };
    }
    user = await res.json();
  } catch (e) {
    return { ok: false, status: 401, error: 'Could not verify session: ' + e.message };
  }

  if (!user || !user.id) return { ok: false, status: 401, error: 'Unauthorized.' };
  return { ok: true, uid: user.id, email: (user.email || '').toLowerCase() ? user.email : '' };
}

// Verifies the bearer token is a real, currently-valid Supabase session
// and returns who it belongs to — no ADMIN_EMAIL check. Used by routes
// that need to know *which* customer is calling (e.g. /api/claim-free)
// without requiring that caller to be the admin.
async function requireUserAuth(request, env) {
  return supabaseGetUser(request, env);
}

async function requireAdminAuth(request, env) {
  if (!env.ADMIN_EMAIL) {
    // Fail closed: if the secret was never configured, refuse rather
    // than silently allowing unauthenticated access.
    return { ok: false, status: 500, error: 'ADMIN_EMAIL is not configured on this Worker.' };
  }

  const result = await supabaseGetUser(request, env);
  if (!result.ok) return result;

  if (!result.email || result.email.toLowerCase() !== env.ADMIN_EMAIL.toLowerCase()) {
    return { ok: false, status: 403, error: 'This account is not the admin account.' };
  }
  return result;
}

// ---------------------------------------------------------------
// SlickPay config
// ---------------------------------------------------------------
const SLICKPAY_BASE_URL = {
  sandbox:    'https://devapi.slick-pay.com/api/v2',
  production: 'https://prodapi.slick-pay.com/api/v2',
};

function slickpayBaseUrl(env) {
  const mode = (env.SLICKPAY_ENV || 'sandbox').toLowerCase();
  return SLICKPAY_BASE_URL[mode] || SLICKPAY_BASE_URL.sandbox;
}

function slickpayHeaders(env) {
  return {
    'Authorization': `Bearer ${env.SLICKPAY_KEY}`,
    'Content-Type':  'application/json',
    'Accept':        'application/json',
    'User-Agent':    'DigiStoreDZ/1.0 (+https://digital-website.digitch.workers.dev)',
  };
}

class SlickPayError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'SlickPayError';
    this.status = status;
    this.body = body;
  }
}

async function slickpayRequest(env, path, { method = 'GET', body } = {}) {
  const res = await fetch(`${slickpayBaseUrl(env)}${path}`, {
    method,
    headers: slickpayHeaders(env),
    body: body ? JSON.stringify(body) : undefined,
  });

  const resClone = res.clone();
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON response */ }

  if (!res.ok) {
    let rawText = '';
    if (!data) { try { rawText = await resClone.text(); } catch {} }
    // SlickPay returns a generic "Server Error" when the merchant has no
    // linked bank account (RIB) — surface that distinctly so the caller
    // can map it to a clear 503 instead of a confusing 500.
    const msg = (data && (data.message || JSON.stringify(data.errors)))
      || (rawText ? `SlickPay ${res.status}: ${rawText.slice(0, 200)}` : `SlickPay HTTP ${res.status}`);
    throw new SlickPayError(msg, res.status, data);
  }
  return data;
}

// SlickPay's commission is configured per merchant account and is NOT
// guaranteed to be a flat amount — it can be a percentage (the guide's own
// example shows 190 DA commission on a 10,000 DA sale, ~1.9%, not a flat
// fee). Hardcoding a guessed number here would silently undercharge the
// customer and eat into the merchant's payout whenever the real rate is
// higher. So the real fee is looked up from SlickPay's own commission
// endpoint at checkout time (see getGatewayFee below) and used everywhere
// instead. This constant is kept ONLY as a fallback for the rare case
// where that lookup call itself fails, so checkout never hard-breaks.
const SLICKPAY_GATEWAY_FEE_DA_FALLBACK = 40;

const SlickPay = {
  async createInvoice(env, { amount, items, firstname, lastname, email, phone, address, returnUrl, webhookUrl, webhookSignature, webhookMetaData, fees = 100 }) {
    const payload = {
      amount,
      items,
      fees,
      url: returnUrl,
      firstname,
      lastname,
      email,
      phone,
      address,
    };
    if (env.SLICKPAY_ACCOUNT) payload.account = env.SLICKPAY_ACCOUNT;
    if (webhookUrl)       payload.webhook_url       = webhookUrl;
    if (webhookSignature) payload.webhook_signature = webhookSignature;
    if (webhookMetaData)  payload.webhook_meta_data  = webhookMetaData;

    return slickpayRequest(env, '/users/invoices', { method: 'POST', body: payload });
  },

  async getInvoice(env, id) {
    return slickpayRequest(env, `/users/invoices/${encodeURIComponent(id)}`, { method: 'GET' });
  },

  async commission(env, amount) {
    return slickpayRequest(env, '/users/invoices/commission', { method: 'POST', body: { amount } });
  },

  async listAccounts(env) {
    return slickpayRequest(env, '/users/accounts', { method: 'GET' });
  },
};

// Ask SlickPay what this merchant's account will actually be charged in
// commission for a given base amount, so the surcharge shown to and
// collected from the customer matches what SlickPay will really deduct
// (we pass fees: 0 on invoice creation — see the checkout route — meaning
// SlickPay deducts its real commission from the payout rather than adding
// it again at the payment page; this fee lookup is what makes sure we've
// already collected exactly that much from the customer up front, so the
// merchant nets the full listed product price).
// Falls back to SLICKPAY_GATEWAY_FEE_DA_FALLBACK if the lookup itself
// fails, so a transient SlickPay API hiccup never blocks checkout.
async function getGatewayFee(env, baseAmount) {
  try {
    const res = await SlickPay.commission(env, baseAmount);
    const fee = Number(res && res.commission);
    if (Number.isFinite(fee) && fee > 0) return fee;
    throw new Error('Unexpected response shape: ' + JSON.stringify(res));
  } catch (err) {
    console.error('[checkout] commission lookup failed, using fallback fee:', err.message);
    return SLICKPAY_GATEWAY_FEE_DA_FALLBACK;
  }
}

// ---------------------------------------------------------------
// Supabase REST helper (PostgREST), authenticated with the service-role
// key. Every collection here is a row in the generic `public.documents`
// table (see supabase/schema.sql) — `collection` and `id` together are
// the primary key, `data` is the document's fields as JSON. The service
// role key bypasses Row Level Security entirely, so this Worker can read
///write anything, the same way the old Firestore service-account JWT
// could.
// ---------------------------------------------------------------

// Every helper below builds a REST URL by interpolating a document ID
// directly into the query string (`id=eq.<id>`). Several of those IDs
// originate from client input (cart productIds, the order_id in the
// public /api/checkout/status/:order_id URL, etc.) and must never be
// allowed to smuggle extra PostgREST filter syntax (e.g. an embedded
// `&` or `,`) into the query. Real document IDs here are either UUIDs
// we generate or short alphanumeric order codes we generate — reject
// anything that doesn't look like that instead of trying to escape it.
function assertSafeDocId(id) {
  const raw = String(id ?? '');
  if (!raw || !/^[A-Za-z0-9_\-\.]+$/.test(raw)) {
    throw new Error(`Invalid document ID: ${JSON.stringify(raw)}`);
  }
  return raw;
}

function supabaseRestBase(env) {
  if (!env.SUPABASE_URL) throw new Error('SUPABASE_URL is not configured on this Worker.');
  return `${env.SUPABASE_URL.replace(/\/+$/, '')}/rest/v1`;
}

function supabaseServiceHeaders(env, extra = {}) {
  if (!env.SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error(
      'SUPABASE_SERVICE_ROLE_KEY secret is not set on this Worker. ' +
      'Run: npx wrangler secret put SUPABASE_SERVICE_ROLE_KEY'
    );
  }
  return {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    'Content-Type': 'application/json',
    ...extra,
  };
}

// Turns one PostgREST row `{ collection, id, data, created_at, updated_at }`
// into the flat `{ id, ...data }` shape the rest of this file (and the
// frontend) expects — same shape docToObject() used to return.
function rowToObject(row) {
  if (!row) return null;
  return { id: row.id, ...(row.data || {}) };
}

const Docs = {
  async getDoc(env, collection, id) {
    const safeId = assertSafeDocId(id);
    const res = await fetch(
      `${supabaseRestBase(env)}/documents?collection=eq.${encodeURIComponent(collection)}&id=eq.${encodeURIComponent(safeId)}&select=*`,
      { headers: supabaseServiceHeaders(env) }
    );
    if (!res.ok) throw new Error(`Docs.getDoc failed: ${res.status} ${await res.text()}`);
    const rows = await res.json();
    return rows[0] ? rowToObject(rows[0]) : null;
  },

  // Creates a doc with a generated id (Postgres default gen_random_uuid()).
  async addDoc(env, collection, data) {
    const res = await fetch(`${supabaseRestBase(env)}/documents`, {
      method: 'POST',
      headers: supabaseServiceHeaders(env, { Prefer: 'return=representation' }),
      body: JSON.stringify([{ collection, data }]),
    });
    if (!res.ok) throw new Error(`Docs.addDoc failed: ${res.status} ${await res.text()}`);
    const rows = await res.json();
    return rowToObject(rows[0]);
  },

  // Partial update — merges `data` into the existing JSON (matches
  // Firestore's updateDoc/updateMask behavior of only touching the given
  // fields, not overwriting the whole document). Defined below the object
  // literal as Docs.updateDoc, since it needs a read-modify-write
  // (Postgres has no per-field JSON "updateMask" over plain REST the way
  // Firestore's PATCH does) and reads more clearly as its own function.

  async deleteDoc(env, collection, id) {
    const safeId = assertSafeDocId(id);
    const res = await fetch(
      `${supabaseRestBase(env)}/documents?collection=eq.${encodeURIComponent(collection)}&id=eq.${encodeURIComponent(safeId)}`,
      { method: 'DELETE', headers: supabaseServiceHeaders(env) }
    );
    // Deleting a doc that's already gone is fine — PostgREST returns 200
    // with an empty array either way, so there's nothing to special-case.
    if (!res.ok) throw new Error(`Docs.deleteDoc failed: ${res.status} ${await res.text()}`);
  },

  // Upsert — creates the doc at this exact id if it doesn't exist, or
  // replaces its `data` entirely if it does (matches Firestore's set()
  // without {merge:true}).
  async setDoc(env, collection, id, data) {
    const safeId = assertSafeDocId(id);
    const res = await fetch(`${supabaseRestBase(env)}/documents?on_conflict=collection,id`, {
      method: 'POST',
      headers: supabaseServiceHeaders(env, {
        Prefer: 'resolution=merge-duplicates,return=representation',
      }),
      body: JSON.stringify([{ collection, id: safeId, data, updated_at: new Date().toISOString() }]),
    });
    if (!res.ok) throw new Error(`Docs.setDoc failed: ${res.status} ${await res.text()}`);
    const rows = await res.json();
    return rowToObject(rows[0]);
  },

  // Atomically "claims" collection/id — creates a tiny doc there ONLY if
  // one doesn't already exist there, and returns whether THIS call was
  // the one that created it. A single INSERT with ON CONFLICT DO NOTHING
  // is atomic in Postgres, same guarantee Firestore's
  // currentDocument.exists=false precondition gave us.
  //
  // Used as a one-shot lock around order delivery. Both the payment-status
  // poll (payment-return.html hits this every ~3s) and the SlickPay
  // webhook independently check "is this order still pending?" and, if so,
  // call deliverOrder() then mark the order delivered — but that read-then-
  // write has no atomicity of its own, so if the poll and the webhook land
  // within the same few hundred ms of each other, both can see 'pending'
  // and both call deliverOrder(), creating two purchase records (two
  // license keys / access links) for one payment. This conditional insert
  // does the same job: only one of the two racing requests can win the
  // claim, so deliverOrder() only ever runs once per order.
  async claimOnce(env, collection, id) {
    const safeId = assertSafeDocId(id);
    const res = await fetch(`${supabaseRestBase(env)}/documents?on_conflict=collection,id`, {
      method: 'POST',
      headers: supabaseServiceHeaders(env, {
        Prefer: 'resolution=ignore-duplicates,return=representation',
      }),
      body: JSON.stringify([{ collection, id: safeId, data: { claimedAt: new Date().toISOString() } }]),
    });
    if (!res.ok) throw new Error(`Docs.claimOnce failed: ${res.status} ${await res.text()}`);
    const rows = await res.json();
    // ignore-duplicates means a conflicting row returns an EMPTY array
    // (nothing was inserted) rather than an error — so "we won the claim"
    // is exactly "a row came back".
    return rows.length > 0;
  },

  // List a collection ordered/limited — e.g. the most recent admin login
  // records. `orderByField` is a field INSIDE `data` (e.g. 'at',
  // 'createdAt'), sorted as text — every timestamp this app writes is an
  // ISO-8601 string, which sorts correctly as plain text.
  async listCollection(env, collection, { orderByField, direction = 'DESCENDING', limit = 50 } = {}) {
    const params = new URLSearchParams();
    params.set('collection', `eq.${collection}`);
    params.set('select', '*');
    params.set('limit', String(limit));
    if (orderByField) {
      params.set('order', `data->>${orderByField}.${direction === 'DESCENDING' ? 'desc' : 'asc'}`);
    }
    const res = await fetch(`${supabaseRestBase(env)}/documents?${params.toString()}`, {
      headers: supabaseServiceHeaders(env),
    });
    if (!res.ok) throw new Error(`Docs.listCollection failed: ${res.status} ${await res.text()}`);
    const rows = await res.json();
    return rows.map(rowToObject);
  },

  // Run a structured query, e.g. find a purchase by a field value (or
  // several — all ANDed together, matching Firestore's compositeFilter).
  async queryCollection(env, collection, fieldFilters, limit = 10) {
    const params = new URLSearchParams();
    params.set('collection', `eq.${collection}`);
    params.set('select', '*');
    params.set('limit', String(limit));
    for (const [field, value] of fieldFilters) {
      // ->> compares the JSON value as text. Every field this app filters
      // by (userId, productId, status, phone, name, variantLabel,
      // invoiceId) is stored and compared as a string, so this matches
      // Firestore's EQUAL semantics for these fields exactly. `null`
      // needs `is.null` instead of `eq.` (Postgres, unlike `=`, treats
      // NULL specially).
      if (value === null || value === undefined) {
        params.append(`data->>${field}`, 'is.null');
      } else {
        params.append(`data->>${field}`, `eq.${value}`);
      }
    }
    const res = await fetch(`${supabaseRestBase(env)}/documents?${params.toString()}`, {
      headers: supabaseServiceHeaders(env),
    });
    if (!res.ok) throw new Error(`Docs.queryCollection failed: ${res.status} ${await res.text()}`);
    const rows = await res.json();
    return rows.map(rowToObject);
  },
};

Docs.updateDoc = async function updateDoc(env, collection, id, patch) {
  const safeId = assertSafeDocId(id);
  const existing = await Docs.getDoc(env, collection, safeId);
  const merged = { ...(existing || {}), ...patch };
  delete merged.id; // `id` lives in its own column, not inside `data`
  const res = await fetch(
    `${supabaseRestBase(env)}/documents?collection=eq.${encodeURIComponent(collection)}&id=eq.${encodeURIComponent(safeId)}`,
    {
      method: 'PATCH',
      headers: supabaseServiceHeaders(env, { Prefer: 'return=representation' }),
      body: JSON.stringify({ data: merged, updated_at: new Date().toISOString() }),
    }
  );
  if (!res.ok) throw new Error(`Docs.updateDoc failed: ${res.status} ${await res.text()}`);
  const rows = await res.json();
  return rows[0] ? rowToObject(rows[0]) : null;
};

// ---------------------------------------------------------------
// Supabase Auth admin calls — deleting an account can only be done
// server-side with the service-role key (the browser SDK can only ever
// act on the currently signed-in user).
// ---------------------------------------------------------------
async function deleteSupabaseAuthUser(env, uid) {
  const res = await fetch(`${env.SUPABASE_URL.replace(/\/+$/, '')}/auth/v1/admin/users/${encodeURIComponent(uid)}`, {
    method: 'DELETE',
    headers: supabaseServiceHeaders(env),
  });
  if (!res.ok && res.status !== 404) {
    let detail = '';
    try { detail = JSON.stringify(await res.json()); } catch {}
    throw new Error(`Failed to delete Supabase Auth account: ${res.status} ${detail}`);
  }
}

// ---------------------------------------------------------------
// Pricing — re-derived server-side from the product doc, never trusted
// from the client. Mirrors the variant-price logic in firebase.js /
// index.html (prod.variables[].items[].price, legacy prod.variants[].price,
// falling back to prod.price).
// ---------------------------------------------------------------
// Returns { price, label }. `label` is only ever a variant label that
// actually exists on the product doc (i.e. text an admin typed into the
// dashboard) — never the raw client-supplied string. That matters because
// this label later gets persisted into `slickpay_orders` / `purchases`
// (as `productName` / `variantLabel`) and rendered with innerHTML in both
// admin.html and index.html. If we accepted the client's variantLabel
// verbatim, anyone could send `variant_label: "<img src=x onerror=...>"`
// at checkout — it'd still price at the base product.price (no match), but
// the payload would be stored and later executed in the admin's or a
// buyer's browser. Requiring an exact match against the product's own
// variant list closes that off at the source, before it's ever written.
function resolveVariant(product, variantLabel) {
  if (!variantLabel) return { price: product.price, label: null };
  if (Array.isArray(product.variables)) {
    for (const grp of product.variables) {
      const item = (grp.items || []).find(it => it.label === variantLabel || variantLabel.split(' / ').includes(it.label));
      if (item && item.price != null) return { price: item.price, label: variantLabel };
    }
  }
  if (Array.isArray(product.variants)) {
    const item = product.variants.find(v => v.label === variantLabel);
    if (item && item.price != null) return { price: item.price, label: variantLabel };
  }
  // No match — this isn't a real variant of the product, so don't trust or
  // persist the label. Fall back to the base price with no variant text.
  return { price: product.price, label: null };
}

// Kept as a thin wrapper for callers that only need the price.
function resolveVariantPrice(product, variantLabel) {
  return resolveVariant(product, variantLabel).price;
}

// ---------------------------------------------------------------
// Delivery info — deliveryLink / deliveryType / deliveryFiles / autoDeliver
// now live in products/{id}/private/delivery, an admin-only subdocument,
// instead of on the public product doc. That's what keeps them out of
// every storefront visitor's Firestore read (and the localStorage cache
// DB._load() writes from it in firebase.js) before they've bought anything.
// See admin.html's saveProduct(), which now writes here instead of onto
// the product doc.
//
// Falls back to the legacy fields directly on the product doc for any
// product that hasn't been re-saved from the admin panel since this
// migration — safe to delete that fallback once every product has been
// re-saved (or you've run a one-time migration) so nothing still has
// delivery fields sitting on the public doc.
// ---------------------------------------------------------------
async function getProductDelivery(env, productId, productDoc) {
  let priv = null;
  try {
    const safeId = assertSafeDocId(productId);
    priv = await Docs.getDoc(env, `products/${safeId}/private`, 'delivery');
  } catch (e) {
    console.error('[getProductDelivery] private doc fetch failed:', e.message);
  }
  const src = priv || productDoc || {};
  return {
    autoDeliver:   !!src.autoDeliver,
    deliveryLink:  src.deliveryLink  || '',
    deliveryType:  src.deliveryType  || 'link',
    deliveryFiles: Array.isArray(src.deliveryFiles) ? src.deliveryFiles : [],
  };
}

async function priceCartItems(env, cartItems) {
  // Fetch every product in the cart concurrently instead of one at a time —
  // a 5-item cart used to mean 5 sequential Firestore round-trips before
  // checkout could even create the invoice. Promise.all fires them together.
  const priced = await Promise.all(cartItems.map(async (item) => {
    const productId = item.productId || item.id;
    const product = await Docs.getDoc(env, 'products', productId);
    if (!product) throw new Error(`Product not found: ${productId}`);
    const { price: unitPrice, label: variantLabel } = resolveVariant(product, item.variantLabel);
    const qty = Math.max(1, parseInt(item.qty, 10) || 1);
    const delivery = await getProductDelivery(env, productId, product);
    return {
      productId,
      name: variantLabel ? `${product.name} — ${variantLabel}` : product.name,
      images: product.images || [],
      category: product.category || '',
      // 'course' | 'pack' | 'product' (legacy). Set by the admin panel's
      // Content Type field. Courses never use the link/file delivery
      // fields below — their content lives in products/{id}/private/
      // curriculum and is only ever served through the verified
      // GET /api/content/:id route, so a course purchase is always
      // auto-completed on payment confirmation (see deliverOrder below).
      contentType: product.contentType || 'product',
      unitPrice,
      qty,
      variantLabel,
      // Carried along so deliverOrder() doesn't need a second product fetch.
      autoDeliver:   delivery.autoDeliver,
      deliveryLink:  delivery.deliveryLink,
      deliveryType:  delivery.deliveryType,
      deliveryFiles: delivery.deliveryFiles,
    };
  }));
  return priced;
}

// ---------------------------------------------------------------
// Order fulfillment — creates `purchases` docs for a paid order so
// the buyer sees them on My Products without any admin action.
// If a product has autoDeliver + deliveryLink configured, the purchase
// is created already `completed` with the access link attached.
// Otherwise it's created `pending`, same as the manual proof-of-payment
// flow, so the admin can deliver it by hand from the admin panel.
// ---------------------------------------------------------------
async function deliverOrder(env, order) {
  if (!order || !order.userId) {
    // No user to attach the purchase to (e.g. a very old/legacy order) —
    // nothing we can do automatically. The admin can still see the raw
    // slickpay_orders record.
    return;
  }
  const now = new Date().toISOString();

  let items = Array.isArray(order.items) && order.items.length ? order.items : null;
  if (!items) {
    // Legacy single-item order (created before cart items were persisted).
    items = [{
      productId:    order.product_id || order.productId || '',
      name:         order.product_name || order.productName || '',
      images:       [],
      category:     '',
      unitPrice:    order.amount,
      qty:          1,
      variantLabel: null,
      autoDeliver:  false,
      deliveryLink: '',
      deliveryType: 'link',
    }];
  }

  // Legacy items may not carry delivery info — resolve all of those product
  // lookups concurrently up front rather than one-by-one inside the loop
  // below (this only ever affects old orders created before cart items
  // carried their own delivery info, but no reason to make it sequential).
  const resolvedItems = await Promise.all(items.map(async (item) => {
    let { autoDeliver, deliveryLink, deliveryType, images, category, name, deliveryFiles, contentType } = item;
    if ((autoDeliver === undefined || !Array.isArray(deliveryFiles) || contentType === undefined) && item.productId) {
      try {
        const product = await Docs.getDoc(env, 'products', item.productId);
        if (product) {
          const delivery = await getProductDelivery(env, item.productId, product);
          autoDeliver   = delivery.autoDeliver;
          deliveryLink  = delivery.deliveryLink;
          deliveryType  = delivery.deliveryType;
          deliveryFiles = delivery.deliveryFiles;
          images        = product.images || [];
          category      = product.category || '';
          name          = name || product.name;
          contentType   = product.contentType || 'product';
        }
      } catch { /* best-effort */ }
    }
    return { ...item, autoDeliver, deliveryLink, deliveryType, images, category, name, deliveryFiles, contentType };
  }));

  for (const item of resolvedItems) {
    const { autoDeliver, deliveryLink, deliveryType, images, category, name, deliveryFiles, contentType } = item;
    // Courses never gate on deliveryLink — their content isn't a link/file
    // at all, it's the curriculum served by GET /api/content/:id, which
    // checks this very purchase doc's status. So a paid course is always
    // completed immediately; there's nothing for an admin to "deliver".
    const isAuto = !!(autoDeliver && deliveryLink) || contentType === 'course';

    // Build accessData: Download Link and the uploaded file list are now
    // independent — a product can have either, or both merged together
    // (e.g. a video link plus a bonus PDF). Attach whichever is actually
    // populated rather than gating _Files behind deliveryType === 'pdf'.
    // Courses skip this entirely — there's no link/file to attach, their
    // content is served live from the curriculum doc via /api/content/:id.
    let accessData = {};
    if (isAuto && contentType !== 'course') {
      accessData = { '_DeliveryType': deliveryType || 'link', 'Download Link': deliveryLink };
      if (Array.isArray(deliveryFiles) && deliveryFiles.length) {
        accessData['_Files'] = deliveryFiles.map(f => ({ url: f.url, name: f.name }));
      }
    }

    const purchaseDoc = {
      userId:        order.userId,
      userEmail:     order.userEmail || order.email || '',
      productId:     item.productId || '',
      productName:   item.variantLabel ? `${name || ''} — ${item.variantLabel}` : (name || ''),
      productImage:  (images || [])[0] || '',
      productType:   category || 'Digital',
      contentType:   contentType || 'product',
      accessLink:    isAuto && contentType !== 'course' ? deliveryLink : '',
      accessData,
      proofImages:   [],
      customerName:  `${order.firstname || ''} ${order.lastname || ''}`.trim(),
      customerPhone: order.phone || '',
      customerEmail: order.userEmail || order.email || '',
      paymentMethod: 'slickpay',
      orderNotes:    '',
      status:        isAuto ? 'completed' : 'pending',
      purchaseDate:  now,
      createdAt:     now,
      orderId:       order.orderId || '',
      variantLabel:  item.variantLabel || null,
      deliveryType:  isAuto ? (deliveryType || 'link') : '',
    };
    if (isAuto) purchaseDoc.deliveredAt = now;

    try {
      await Docs.addDoc(env, 'purchases', purchaseDoc);
    } catch (e) {
      console.error('[deliverOrder] Firestore addDoc failed:', e.message);
    }
  }
}

async function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const enc = new TextEncoder();
  const aBuf = enc.encode(a), bBuf = enc.encode(b);
  if (aBuf.length !== bBuf.length) return false;
  let diff = 0;
  for (let i = 0; i < aBuf.length; i++) diff |= aBuf[i] ^ bBuf[i];
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const method = request.method;
    const path   = url.pathname;

    // ── CORS headers (added to every response) ───────────────────
    const corsHeaders = {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age':       '86400',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });

    // ============================================================
    // ROUTE: GET /api/health
    // ============================================================
    if (path === '/api/health' && method === 'GET') {
      return json({ status: 'ok' });
    }

    // ============================================================
    // ROUTE: POST /api/upload-file
    // Stores the uploaded file in R2 via the native `env.BUCKET`
    // binding and returns its public URL.
    // ============================================================
    if (path === '/api/upload-file' && method === 'POST') {
      const auth = await requireAdminAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        let form;
        try {
          form = await request.formData();
        } catch {
          return json({ error: 'Expected multipart/form-data with a "file" field.' }, 400);
        }

        const file   = form.get('file');
        const folder = (form.get('folder') || 'deliveries/misc').toString();

        if (!file || typeof file.arrayBuffer !== 'function') {
          return json({ error: 'No file provided.' }, 400);
        }

        const MAX_BYTES = 50 * 1024 * 1024; // 50MB
        if (file.size > MAX_BYTES) {
          return json({ error: 'File is too large — must be under 50MB.' }, 400);
        }

        if (!env.BUCKET) {
          return json({ error: 'R2 bucket binding (env.BUCKET) is not configured.' }, 500);
        }
        if (!env.R2_PUBLIC_URL) {
          return json({ error: 'R2_PUBLIC_URL is not configured.' }, 500);
        }

        const safeName    = (file.name || 'file').replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const safeFolder  = folder.replace(/[^a-zA-Z0-9/_\-]/g, '_').replace(/^\/+/, '');
        const objectPath  = `${safeFolder}/${Date.now()}_${safeName}`;
        const contentType = file.type || 'application/octet-stream';
        const fileBytes   = await file.arrayBuffer();

        // Upload to R2 via the native binding — no S3 API, no signing.
        await env.BUCKET.put(objectPath, fileBytes, {
          httpMetadata: {
            contentType,
            contentDisposition: `attachment; filename="${file.name || safeName}"`,
          },
        });

        // Build the public URL. R2_PUBLIC_URL is the base URL of your
        // public R2 bucket — either its r2.dev URL or your connected
        // custom domain, e.g. "https://pub-xxxxxxxx.r2.dev" or
        // "https://files.yourdomain.com" (no trailing slash).
        const pathParts   = objectPath.split('/').map(encodeURIComponent).join('/');
        const downloadUrl = `${env.R2_PUBLIC_URL.replace(/\/+$/, '')}/${pathParts}`;

        return json({
          url:  downloadUrl,
          path: objectPath,
          name: file.name || safeName,
          size: file.size || 0,
        });

      } catch (err) {
        console.error('[upload-file] error:', err.message);
        return json({ error: 'Internal server error.', message: err.message }, 500);
      }
    }

    // ============================================================
    // ROUTE: POST /api/delete-file
    // Deletes the object from R2 via the native `env.BUCKET` binding.
    // ============================================================
    if (path === '/api/delete-file' && method === 'POST') {
      const auth = await requireAdminAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        let body;
        try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body.' }, 400); }

        const objectPath = (body.path || '').toString();
        if (!objectPath) return json({ error: 'path is required.' }, 400);

        if (!env.BUCKET) {
          return json({ error: 'R2 bucket binding (env.BUCKET) is not configured.' }, 500);
        }

        // R2 delete is idempotent — no error if the key doesn't exist.
        await env.BUCKET.delete(objectPath);

        return json({ ok: true });

      } catch (err) {
        console.error('[delete-file] error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ============================================================
    // ROUTE: POST /api/admin/log-access
    // Called once by admin.html right after a successful admin sign-in
    // (fresh login or a restored session). Records who/when/where/how for
    // a security audit trail — e.g. to notice a sign-in that wasn't you.
    // IP + geolocation come from Cloudflare's own request metadata
    // (request.cf) — nothing external is called, nothing is guessed.
    // ============================================================
    if (path === '/api/admin/log-access' && method === 'POST') {
      const auth = await requireAdminAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        const cf = request.cf || {};
        await Docs.addDoc(env, 'admin_login_log', {
          email:     auth.email,
          uid:       auth.uid,
          ip:        request.headers.get('CF-Connecting-IP') || 'unknown',
          country:   cf.country  || '',
          region:    cf.region   || '',
          city:      cf.city     || '',
          timezone:  cf.timezone || '',
          userAgent: request.headers.get('User-Agent') || 'unknown',
          at:        new Date().toISOString(),
        });
        return json({ ok: true });
      } catch (err) {
        console.error('[log-access] error:', err.message);
        // Non-critical — don't block the admin from using the panel just
        // because the audit log write failed.
        return json({ ok: false }, 200);
      }
    }

    // ============================================================
    // ROUTE: GET /api/admin/login-history
    // Returns recent admin sign-in records, most recent first.
    // ============================================================
    if (path === '/api/admin/login-history' && method === 'GET') {
      const auth = await requireAdminAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 500);
        const entries = await Docs.listCollection(env, 'admin_login_log', {
          orderByField: 'at', direction: 'DESCENDING', limit,
        });
        return json({ entries });
      } catch (err) {
        console.error('[login-history] error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ============================================================
    // ROUTE: GET /api/admin/users
    // Returns all registered users for the admin panel's Users page.
    // The panel previously read `_db.collection('users').get()` directly
    // from the client SDK — a "list" query across the whole collection,
    // which needs a separate Firestore rules permission from "get" (read
    // one doc by ID). Most rule setups only grant the latter, so this
    // always came back empty/permission-denied regardless of how many
    // users actually existed — same root cause as the earlier signup
    // bug. Routing through the service account here bypasses that
    // entirely, same as /api/admin/login-history above.
    // ============================================================
    if (path === '/api/admin/users' && method === 'GET') {
      const auth = await requireAdminAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '1000', 10) || 1000, 5000);
        // Deliberately no orderByField here: Firestore's orderBy excludes
        // any document that's missing the ordered field entirely (not
        // just sorts it last), which would silently drop older user docs
        // that predate a `createdAt` field being added. Fetch everything,
        // then sort here where a missing field just falls back to 0
        // instead of vanishing the user from the list.
        const users = await Docs.listCollection(env, 'users', { limit });
        users.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
        return json({ users });
      } catch (err) {
        console.error('[admin/users] error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ============================================================
    // ROUTE: POST /api/delete-user
    // Deletes a customer: their `users/{uid}` document AND their real
    // Supabase Auth account (the latter can only be done server-side, with
    // the service-role key — the browser SDK can't delete other users).
    // Their `purchases` docs are left in place — deleting a user shouldn't
    // silently wipe order history/analytics.
    // ============================================================
    if (path === '/api/delete-user' && method === 'POST') {
      const auth = await requireAdminAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        let body;
        try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body.' }, 400); }

        const uid = (body.uid || '').toString().trim();
        if (!uid) return json({ error: 'uid is required.' }, 400);

        // Guard rail: the admin can't delete the account they're signed in
        // as — that would be an easy way to accidentally lock yourself out.
        if (uid === auth.uid) {
          return json({ error: "You can't delete the account you're currently signed in as." }, 400);
        }

        await Docs.deleteDoc(env, 'users', uid);
        await deleteSupabaseAuthUser(env, uid);

        return json({ ok: true });
      } catch (err) {
        console.error('[delete-user] error:', err.message);
        return json({ error: 'Internal server error.', message: err.message }, 500);
      }
    }

    // ============================================================
    // ROUTE: POST /api/webhook
    // Receives SlickPay's async payment notification. This is a backstop
    // to the status-poll endpoint below — it lets an order get delivered
    // even if the buyer closes the tab right after paying.
    // ============================================================
    if (path === '/api/webhook' && method === 'POST') {
      try {
        let body;
        try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body.' }, 400); }

        // Signature verification is REQUIRED, not optional. Without it, anyone
        // who finds this URL can POST a fake "payment completed" event for any
        // order and get a product delivered for free. If this 500s, set the
        // secret with: npx wrangler secret put SLICKPAY_WEBHOOK_SIG
        // (use the same value passed as webhookSignature when creating invoices).
        if (!env.SLICKPAY_WEBHOOK_SIG) {
          console.error('[webhook] rejected: SLICKPAY_WEBHOOK_SIG is not configured on this Worker.');
          return json({ error: 'Webhook secret not configured on server.' }, 500);
        }
        const sig = body.webhook_signature || body.signature || request.headers.get('x-webhook-signature') || '';
        const sigOk = await constantTimeEqual(String(sig), String(env.SLICKPAY_WEBHOOK_SIG));
        if (!sigOk) return json({ error: 'Invalid webhook signature.' }, 403);

        const invoice   = body.data || body.invoice || body;
        const completed = (invoice.completed === 1 || body.completed === 1) ? 1 : 0;
        const meta       = body.meta_data || body.webhook_meta_data || invoice.meta_data || {};
        let orderId      = meta.order_id || meta.orderId || '';
        const invoiceId  = String(invoice.id || body.id || '');

        let order = null;
        if (orderId) {
          order = await Docs.getDoc(env, 'slickpay_orders', orderId);
        }
        if (!order && invoiceId) {
          const matches = await Docs.queryCollection(env, 'slickpay_orders', [['invoiceId', invoiceId]], 1);
          order = matches[0] || null;
          if (order) orderId = order.id;
        }
        if (!order) return json({ error: 'Order not found for webhook.' }, 404);

        if (completed === 1 && order.status !== 'delivered') {
          try {
            // Claim delivery for this order before doing it — see
            // Docs.claimOnce() for why: the checkout/status poll can
            // land at nearly the same moment as this webhook, and without
            // this lock both could deliver the same order twice.
            const won = await Docs.claimOnce(env, 'order_delivery_locks', orderId);
            if (won) {
              await deliverOrder(env, order);
              await Docs.updateDoc(env, 'slickpay_orders', orderId, {
                status: 'delivered',
                paidAt: new Date().toISOString(),
              });
            }
          } catch (fsErr) {
            console.error('[webhook] delivery failed:', fsErr.message);
          }
        }

        return json({ ok: true });
      } catch (err) {
        console.error('[webhook] unexpected error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ============================================================
    // ROUTE: GET /api/checkout/fee?amount=NNN
    // Lets the cart/checkout UI show the REAL SlickPay commission for the
    // current total before the customer submits, instead of a guessed flat
    // number — so what's shown in the cart matches what's actually charged
    // when POST /api/checkout runs the same lookup.
    // ============================================================
    if (path === '/api/checkout/fee' && method === 'GET') {
      const amount = Number(url.searchParams.get('amount'));
      if (!Number.isFinite(amount) || amount <= 0) {
        return json({ error: 'Missing or invalid amount.' }, 400);
      }
      const fee = await getGatewayFee(env, amount);
      return json({ fee });
    }

    // ============================================================
    // ROUTE: POST /api/checkout
    // Creates a SlickPay invoice and returns { order_id, payment_url, amount }
    // Body: { product_id, product_name, amount, firstname, lastname, email, phone }
    // ============================================================
    if (path === '/api/checkout' && method === 'POST') {
      try {
        if (!env.SLICKPAY_KEY) {
          return json({ error: 'Payment gateway not configured.' }, 503);
        }

        let body;
        try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body.' }, 400); }

        const {
          product_id, product_name, firstname, lastname, email, phone, address,
          items: rawItems, user_id, user_email,
        } = body || {};
        // NOTE: a client-supplied `amount` field, if present in the request body,
        // is intentionally ignored below. Price is ALWAYS re-derived server-side
        // from product IDs looked up in Firestore — never trust a client-computed
        // total, or anyone can pay whatever they want for a product.
        const safeAddress = (address && address.trim().length >= 5) ? address.trim() : 'Algérie - Livraison numérique';

        if (!firstname || !lastname || (!email && !phone)) {
          return json({ error: 'Missing required fields: firstname, lastname, and email or phone.' }, 400);
        }

        // Build a normalized items list whether the client sent a full cart
        // or a single product_id (legacy/buy-now flow) — either way, pricing
        // is looked up server-side from the product DB, never from the client.
        const normalizedItems = (Array.isArray(rawItems) && rawItems.length)
          ? rawItems.map(it => ({
              productId:    it.product_id || it.productId || it.id,
              variantLabel: it.variant_label || it.variantLabel || null,
              qty:          it.qty || 1,
            }))
          : (product_id ? [{ productId: product_id, variantLabel: null, qty: 1 }] : []);

        if (!normalizedItems.length) {
          return json({ error: 'Missing required fields: items or product_id.' }, 400);
        }

        let pricedItems;
        try {
          pricedItems = await priceCartItems(env, normalizedItems);
        } catch (err) {
          // Full detail goes to the Worker's own logs (visible to you via
          // `npx wrangler tail` or the Cloudflare dashboard) — never to the
          // customer. A raw config/secret error was previously shown
          // directly in the checkout modal, which leaked internal backend
          // state (e.g. "SUPABASE_SERVICE_ROLE_KEY secret is not set") to
          // shoppers.
          console.error('[checkout] priceCartItems failed:', err.message);
          return json({ error: 'We could not process your cart right now. Please try again in a moment, or contact support if this persists.' }, 400);
        }
        const computedAmount = pricedItems.reduce((sum, it) => sum + it.unitPrice * it.qty, 0);

        const finalProductName = product_name || (pricedItems.length === 1 ? pricedItems[0].name : `Order (${pricedItems.length} items)`);

        if (!finalProductName || !computedAmount) {
          return json({ error: 'Missing required fields: product_name/items and amount.' }, 400);
        }
        if (Number(computedAmount) <= 100) {
          return json({ error: 'Amount must be greater than 100 DZD.' }, 400);
        }

        // The customer is charged the products total PLUS SlickPay's real
        // commission for this order — looked up fresh via getGatewayFee()
        // rather than assumed, since the rate isn't necessarily flat (see
        // comment above SLICKPAY_GATEWAY_FEE_DA_FALLBACK). Itemized as its
        // own line so it's never hidden inside the product price.
        const gatewayFee   = await getGatewayFee(env, Number(computedAmount));
        const chargeAmount = Number(computedAmount) + gatewayFee;

        const appUrl = env.APP_URL || 'https://digital-website.digitch.workers.dev';
        const returnUrl = `${appUrl}/payment-return.html`;

        // Generate a short order ID stored in webhook meta
        const orderId = 'ORD-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7).toUpperCase();

        let invoiceData;
        try {
          invoiceData = await SlickPay.createInvoice(env, {
            amount: chargeAmount,
            items: [
              ...(pricedItems
                ? pricedItems.map(it => ({ name: it.name, price: it.unitPrice, quantity: it.qty }))
                : [{ name: finalProductName, price: Number(computedAmount), quantity: 1 }]),
              { name: 'Payment processing fee', price: gatewayFee, quantity: 1 },
            ],
            firstname,
            lastname,
            email: email || undefined,
            phone: phone || undefined,
            address: safeAddress,
            returnUrl,
            webhookUrl:       env.SLICKPAY_WEBHOOK_URL || undefined,
            webhookSignature: env.SLICKPAY_WEBHOOK_SIG || undefined,
            webhookMetaData:  { order_id: orderId, product_id: product_id || '' },
            // We already fold SlickPay's flat commission into `chargeAmount`
            // above (as its own "Payment processing fee" line item), so the
            // customer is already paying it there. Passing fees: 100 here
            // tells SlickPay's own API to ALSO add its commission on top at
            // the CIB payment page, which is what was stacking a second
            // 40 DA on the total (500 -> 540). fees: 0 = merchant absorbs
            // SlickPay's cut out of the chargeAmount we already collected,
            // instead of it being charged to the customer a second time.
            fees: 0,
          });
        } catch (err) {
          console.error('[checkout] SlickPay error:', err.message);
          if (err instanceof SlickPayError) {
            const isNoRib = err.message.toLowerCase().includes('server error') || err.status === 500;
            return json({ error: isNoRib ? 'Payment service temporarily unavailable. Please try another method.' : err.message }, isNoRib ? 503 : 502);
          }
          return json({ error: 'Payment gateway error.' }, 502);
        }

        // The root-level `url` is the SATIM card page; `invoice.url` is the merchant view
        const paymentUrl = invoiceData.url;
        const invoiceId  = invoiceData.id;

        if (!paymentUrl) {
          return json({ error: 'Payment gateway did not return a payment URL.' }, 502);
        }

        // Persist the pending order in Firestore (best-effort — don't block payment)
        try {
          await Docs.setDoc(env, 'slickpay_orders', orderId, {
            orderId,
            invoiceId: String(invoiceId),
            product_id:   product_id       || (pricedItems && pricedItems.length === 1 ? pricedItems[0].productId : ''),
            product_name: finalProductName || '',
            amount:       Number(chargeAmount),      // total actually charged to the customer (products + gateway fee)
            productsAmount: Number(computedAmount),  // products-only subtotal, for reference
            gatewayFee:   gatewayFee,
            items:        pricedItems || null,
            userId:       user_id    || '',
            userEmail:    user_email || email || '',
            firstname,
            lastname,
            email:        email        || '',
            phone:        phone        || '',
            address:      safeAddress,
            status:       'pending',
            paymentUrl,
            createdAt:    new Date().toISOString(),
          });
        } catch (fsErr) {
          // Non-fatal — log and continue
          console.error('[checkout] Firestore write failed:', fsErr.message);
        }

        return json({ order_id: orderId, payment_url: paymentUrl, amount: Number(chargeAmount), invoice_id: invoiceId });

      } catch (err) {
        console.error('[checkout] unexpected error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ============================================================
    // ROUTE: GET /api/checkout/status/:order_id
    // Polls SlickPay for payment status.
    // Returns { status, completed, invoice_id, rejection_reason }
    // ============================================================
    if (path.startsWith('/api/checkout/status/') && method === 'GET') {
      try {
        const orderId = path.replace('/api/checkout/status/', '').trim();
        if (!orderId) return json({ error: 'Missing order_id.' }, 400);

        // Fetch our persisted order from Firestore
        let order = null;
        try {
          order = await Docs.getDoc(env, 'slickpay_orders', orderId);
        } catch { /* not found */ }

        if (!order || !order.invoiceId) {
          return json({ error: 'Order not found.' }, 404);
        }

        // If already marked paid/delivered, return immediately. If payment was
        // confirmed on a previous poll but delivery hadn't finished yet
        // (status === 'paid'), retry delivery now before responding.
        if (order.status === 'paid' || order.status === 'delivered') {
          if (order.status === 'paid') {
            try {
              const won = await Docs.claimOnce(env, 'order_delivery_locks', orderId);
              if (won) {
                await deliverOrder(env, order);
                await Docs.updateDoc(env, 'slickpay_orders', orderId, { status: 'delivered' });
              }
            } catch (fsErr) {
              console.error('[checkout/status] delivery retry failed:', fsErr.message);
            }
          }
          return json({ status: 'paid', completed: 1, invoice_id: order.invoiceId, rejection_reason: null });
        }

        // Poll SlickPay for fresh status
        let invoiceStatus;
        try {
          invoiceStatus = await SlickPay.getInvoice(env, order.invoiceId);
        } catch (err) {
          return json({ status: order.status, completed: 0, invoice_id: order.invoiceId, rejection_reason: err.message });
        }

        const completed = invoiceStatus.completed === 1 ? 1 : 0;
        const rejectionReason = invoiceStatus.data?.rejection_reason || null;

        // Payment confirmed — create the buyer's `purchases` doc(s) right away
        // (auto-delivered if the product has an auto-delivery link configured,
        // otherwise queued as `pending` for the admin to fulfill manually),
        // then mark the order as delivered so we never re-run this twice.
        if (completed === 1 && order.status === 'pending') {
          try {
            // Same claim-before-deliver lock as the webhook handler above —
            // this poll and the webhook can both observe status:'pending'
            // within the same instant, so only whichever one wins the
            // claim is allowed to actually deliver.
            const won = await Docs.claimOnce(env, 'order_delivery_locks', orderId);
            if (won) {
              await deliverOrder(env, order);
              await Docs.updateDoc(env, 'slickpay_orders', orderId, {
                status:  'delivered',
                paidAt:  new Date().toISOString(),
              });
            }
          } catch (fsErr) {
            console.error('[checkout/status] Firestore update failed:', fsErr.message);
          }
        }

        return json({
          status:           completed === 1 ? 'paid' : order.status,
          completed,
          invoice_id:       order.invoiceId,
          rejection_reason: rejectionReason,
        });

      } catch (err) {
        console.error('[checkout/status] unexpected error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ============================================================
    // ROUTE: POST /api/claim-free
    // Lets a signed-in customer claim a $0 product into their My Products,
    // without trusting the client to say what's free or what it delivers.
    // Mirrors deliverOrder()'s logic but re-derives everything server-side
    // from the product doc — the same principle /api/checkout already
    // follows for paid orders ("price is ALWAYS re-derived server-side,
    // never trusted from the client"). This used to be done by the
    // customer's own browser writing straight to Firestore, which meant
    // anyone could, in principle, call the same Firestore write directly
    // and hand themselves a purchase record with a fabricated accessLink —
    // moving it here closes that off.
    // ============================================================
    if (path === '/api/claim-free' && method === 'POST') {
      const auth = await requireUserAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        let body;
        try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body.' }, 400); }

        const productId = (body.productId || body.product_id || '').toString().trim();
        if (!productId) return json({ error: 'productId is required.' }, 400);

        const product = await Docs.getDoc(env, 'products', productId);
        if (!product) return json({ error: 'Product not found.' }, 404);

        const { price, label: variantLabel } = resolveVariant(product, body.variantLabel || body.variant_label || null);
        if (Number(price) > 0) {
          return json({ error: 'This product is not free.' }, 400);
        }

        // Don't hand out a second copy of the same free product/variant.
        const existing = await Docs.queryCollection(env, 'purchases', [
          ['userId', auth.uid], ['productId', productId], ['variantLabel', variantLabel],
        ], 1);
        if (existing[0]) {
          return json({ ok: true, purchase: existing[0], alreadyOwned: true });
        }

        const now = new Date().toISOString();
        const delivery = await getProductDelivery(env, productId, product);
        const contentType = product.contentType || 'product';
        const isAuto = !!(delivery.autoDeliver && delivery.deliveryLink) || contentType === 'course';

        let accessData = {};
        if (isAuto && contentType !== 'course') {
          accessData = { '_DeliveryType': delivery.deliveryType || 'link', 'Download Link': delivery.deliveryLink };
          if (Array.isArray(delivery.deliveryFiles) && delivery.deliveryFiles.length) {
            accessData['_Files'] = delivery.deliveryFiles.map(f => ({ url: f.url, name: f.name }));
          }
        }

        // Best-effort profile fields for the admin's Purchases view — not
        // security-relevant (nobody else can read another user's purchase
        // doc), just display context, so a missing users/{uid} doc doesn't
        // block the claim.
        let profile = {};
        try { profile = (await Docs.getDoc(env, 'users', auth.uid)) || {}; } catch { /* best-effort */ }

        const purchaseDoc = {
          userId:        auth.uid,
          userEmail:     auth.email || profile.email || '',
          productId,
          productName:   variantLabel ? `${product.name || ''} — ${variantLabel}` : (product.name || ''),
          productImage:  (product.images || [])[0] || '',
          productType:   product.category || 'Digital',
          contentType,
          accessLink:    isAuto && contentType !== 'course' ? delivery.deliveryLink : '',
          accessData,
          proofImages:   [],
          customerName:  profile.name || '',
          customerPhone: profile.phone || '',
          customerEmail: auth.email || profile.email || '',
          paymentMethod: 'free',
          orderNotes:    '',
          status:        isAuto ? 'completed' : 'pending',
          purchaseDate:  now,
          createdAt:     now,
          orderId:       'FREE-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7).toUpperCase(),
          variantLabel,
          deliveryType:  isAuto ? (delivery.deliveryType || 'link') : '',
        };
        if (isAuto) purchaseDoc.deliveredAt = now;

        const created = await Docs.addDoc(env, 'purchases', purchaseDoc);
        return json({ ok: true, purchase: created });

      } catch (err) {
        console.error('[claim-free] error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ============================================================
    // ROUTE: GET /api/content/:productId
    // Serves the protected curriculum (course modules/lessons) or pack
    // resource list for a signed-in user who actually owns it. This is the
    // ONLY way lesson content ever reaches the browser — it is never part
    // of the public product doc, never cached in localStorage, and never
    // trusted from anything the client claims. Entitlement is re-derived
    // here, every time, from the `purchases` collection (status ===
    // 'completed'), the same source of truth /api/checkout's webhook and
    // /api/claim-free write to. Reaching a URL, having a client-side flag,
    // or having reached payment-return.html grants nothing by itself.
    // ============================================================
    if (path.startsWith('/api/content/') && method === 'GET') {
      const auth = await requireUserAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        const productId = decodeURIComponent(path.slice('/api/content/'.length)).trim();
        if (!productId) return json({ error: 'productId is required.' }, 400);

        const owned = await Docs.queryCollection(env, 'purchases', [
          ['userId', auth.uid], ['productId', productId], ['status', 'completed'],
        ], 1);
        const isAdmin = !!env.ADMIN_EMAIL && (auth.email || '').toLowerCase() === env.ADMIN_EMAIL.toLowerCase();
        if (!owned[0] && !isAdmin) {
          return json({ error: 'You do not have access to this content yet.' }, 403);
        }

        const safeId = assertSafeDocId(productId);
        const curriculum = await Docs.getDoc(env, `products/${safeId}/private`, 'curriculum');
        if (!curriculum) return json({ error: 'This content has no curriculum yet.' }, 404);

        return json({
          ok: true,
          modules: Array.isArray(curriculum.modules) ? curriculum.modules : [],
          resources: Array.isArray(curriculum.resources) ? curriculum.resources : [],
          progress: (owned[0] && owned[0].progress) || { completedLessonIds: [], lastLessonId: null },
          purchaseId: owned[0] ? owned[0].id : null,
        });
      } catch (err) {
        console.error('[content] error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ============================================================
    // ROUTE: POST /api/progress
    // Saves lesson progress (which lessons are completed, and the last
    // lesson viewed) onto the buyer's own purchase/enrollment record —
    // never onto the shared product/course doc. Ownership of that record
    // is re-checked server-side (userId must match the caller), so one
    // user can never write into another user's progress.
    // ============================================================
    if (path === '/api/progress' && method === 'POST') {
      const auth = await requireUserAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        let body;
        try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body.' }, 400); }

        const productId = (body.productId || '').toString().trim();
        const lessonId  = (body.lessonId || '').toString().trim();
        const completed = body.completed !== false; // default: marking complete
        if (!productId || !lessonId) return json({ error: 'productId and lessonId are required.' }, 400);

        const owned = await Docs.queryCollection(env, 'purchases', [
          ['userId', auth.uid], ['productId', productId], ['status', 'completed'],
        ], 1);
        const purchase = owned[0];
        if (!purchase) return json({ error: 'You do not have access to this content.' }, 403);

        const prior = (purchase.progress && Array.isArray(purchase.progress.completedLessonIds))
          ? purchase.progress.completedLessonIds : [];
        const nextIds = completed
          ? Array.from(new Set([...prior, lessonId]))
          : prior.filter(id => id !== lessonId);

        const progress = { completedLessonIds: nextIds, lastLessonId: lessonId, updatedAt: new Date().toISOString() };
        await Docs.updateDoc(env, 'purchases', purchase.id, { progress });

        return json({ ok: true, progress });
      } catch (err) {
        console.error('[progress] error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ROUTE: POST /api/complete-google-registration
    // Finishes a Google sign-up (username + phone) server-side, using the
    // service-role key, instead of the client SDK writing directly. The
    // duplicate username/phone checks need to scan the whole `users`
    // collection, which the anon key's RLS policies deliberately don't
    // allow (only your own user doc, or the admin) — routing this through
    // the Worker's service-role key bypasses that restriction safely,
    // since the checks themselves are what keep it safe (same pattern as
    // /api/claim-free, /api/delete-user, etc).
    // ============================================================
    if (path === '/api/complete-google-registration' && method === 'POST') {
      const auth = await requireUserAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        // The admin account must only ever be reached via admin.html's
        // dedicated email+password login — never through this public
        // signup route, no matter which Google session authenticated it.
        if (env.ADMIN_EMAIL && (auth.email || '').toLowerCase() === env.ADMIN_EMAIL.toLowerCase()) {
          return json({ error: 'This Google account is not available for sign-in. Please use a different account.' }, 403);
        }

        let body;
        try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body.' }, 400); }

        const username = (body.username || '').toString().trim().slice(0, 60);
        const phone    = (body.phone || '').toString().trim().slice(0, 20);
        const photoURL = (body.photoURL || '').toString().trim().slice(0, 500);
        const checkUsername = body.checkUsername !== false; // default true (Google flow); email/password signup passes false to preserve its original behavior of allowing duplicate display names
        if (!username) return json({ error: 'Please enter a username.' }, 400);
        if (!phone)    return json({ error: 'Please enter a phone number.' }, 400);

        // Duplicate checks — run server-side with the service account, so
        // they always work regardless of client Firestore rules.
        if (checkUsername) {
          const nameMatches = await Docs.queryCollection(env, 'users', [['name', username]], 2);
          if (nameMatches.some(u => u.id !== auth.uid)) {
            return json({ error: 'This username is already taken. Please choose another one.' }, 409);
          }
        }
        const phoneMatches = await Docs.queryCollection(env, 'users', [['phone', phone]], 2);
        if (phoneMatches.some(u => u.id !== auth.uid)) {
          return json({ error: 'This phone number is already linked to another account.' }, 409);
        }

        const now = new Date().toISOString();
        const existing = await Docs.getDoc(env, 'users', auth.uid);
        const userDoc = {
          id: auth.uid,
          email: auth.email || '',
          name: username,
          phone,
          photoURL: photoURL || (existing && existing.photoURL) || '',
          createdAt: (existing && existing.createdAt) || now,
          lastLogin: now,
        };
        await Docs.setDoc(env, 'users', auth.uid, userDoc);

        return json({ ok: true, user: { id: auth.uid, email: userDoc.email, name: userDoc.name, phone: userDoc.phone } });

      } catch (err) {
        console.error('[complete-google-registration] error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ============================================================
    // ROUTE: POST /api/rollback-registration
    // Self-service account deletion, used ONLY by supabase.js's
    // register() when the account it just created (via Supabase Auth's
    // signUp()) turns out to have a duplicate phone number and the
    // signup needs to be rolled back so the email address is free to
    // retry with. The Supabase browser SDK has no "delete my own
    // account" method (only the service-role key can delete accounts),
    // so this route exists purely to let a user delete THEMSELVES —
    // requireUserAuth() below proves the caller's token really does
    // belong to the account being deleted; there is no `uid` parameter
    // to trust from the request body.
    // ============================================================
    if (path === '/api/rollback-registration' && method === 'POST') {
      const auth = await requireUserAuth(request, env);
      if (!auth.ok) return json({ error: auth.error }, auth.status);
      try {
        await Docs.deleteDoc(env, 'users', auth.uid).catch(() => {});
        await deleteSupabaseAuthUser(env, auth.uid);
        return json({ ok: true });
      } catch (err) {
        console.error('[rollback-registration] error:', err.message);
        return json({ error: 'Internal server error.' }, 500);
      }
    }

    // ── 404 for unknown /api routes ───────────────────────────────
    if (path.startsWith('/api/')) {
      return json({ error: 'Not found.' }, 404);
    }

    // ── Non-API routes: serve static files via the ASSETS binding ──
    // Google sign-in now goes through Supabase Auth's redirect-based OAuth
    // flow (see supabase.js), not a popup, so this Worker no longer needs
    // to relax Cross-Origin-Opener-Policy the way the old Firebase
    // signInWithPopup() flow required. The ASSETS binding's default
    // same-origin COOP header is left as-is.
    return env.ASSETS.fetch(request);
  },
};