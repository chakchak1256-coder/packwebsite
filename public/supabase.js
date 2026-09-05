// ================================================================
// SUPABASE.JS — Supabase Auth + Postgres (fully synced)
// Replaces the old firebase.js. Loaded by both index.html (storefront)
// and admin.html (admin panel) — see the "app isolation" note below for
// why each gets its own Supabase client instance.
//
// Data model: every collection ('users', 'purchases', 'products', etc)
// is a set of rows in ONE generic Postgres table, `public.documents`
// (collection text, id text, data jsonb) — see supabase/schema.sql.
// The `_db` object below is a small compatibility shim that makes that
// table behave like a Firestore collection (`.collection(x).doc(y).get()`
// and friends), so almost everything below it ports over unchanged from
// the original Firestore-based logic.
// ================================================================

// Escapes HTML special characters in untrusted text (customer names,
// emails, phone numbers, review comments, order notes, etc.) before it's
// interpolated into innerHTML anywhere in index.html / admin.html. This
// exists to prevent stored XSS from user-submitted data (e.g. a malicious
// checkout name or product review) executing script in another visitor's
// — or the admin's — browser.
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// These are NOT secrets — Supabase's URL and "anon"/"publishable" key are
// meant to be public; Row Level Security (see supabase/schema.sql) is what
// actually protects your data, the same way Firebase's apiKey was public
// and Firestore security rules did the real protecting.
const supabaseConfig = {
  url: "https://redbcznzczspusdzbxbq.supabase.co",
  anonKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJlZGJjem56Y3pzcHVzZHpieGJxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg0NjQ5MDIsImV4cCI6MjEwNDA0MDkwMn0.DbyJI_hx9NufL0gRWZFCIbQ4jmlyyFFM402Bngr1Lj8",
};

// ── App isolation (storefront vs admin) ────────────────────────────
// index.html and admin.html both load this file, but they must NOT
// share one Supabase Auth session. A single client stores its session
// under one localStorage key regardless of which page wrote it, so
// logging into the admin panel in one tab overwrote the customer
// session in another tab (and vice versa) — the same problem the old
// Firebase setup had, fixed the same way: each page gets its own
// client, with its own storage key, so the two sessions live
// side-by-side in localStorage and never overwrite each other.
// admin.html sets window.__IS_ADMIN = true before this file loads
// (see admin.html), which is what lets this file tell the two pages
// apart.
//
// "Remember me" (see UserAuth.login/Auth below) switches a session
// between localStorage (survives closing the browser) and
// sessionStorage (cleared when the tab/browser closes) — Supabase's
// client doesn't have a built-in per-login toggle for this the way
// Firebase did, so this tiny custom storage adapter picks the backing
// store at write-time based on _persistMode.
let _persistMode = 'local'; // 'local' | 'session' — see setPersistence() below
function makeStorageAdapter() {
  return {
    getItem(key) {
      try { return localStorage.getItem(key) ?? sessionStorage.getItem(key); }
      catch (e) { return null; }
    },
    setItem(key, value) {
      try {
        if (_persistMode === 'session') { sessionStorage.setItem(key, value); localStorage.removeItem(key); }
        else { localStorage.setItem(key, value); sessionStorage.removeItem(key); }
      } catch (e) {}
    },
    removeItem(key) {
      try { localStorage.removeItem(key); sessionStorage.removeItem(key); } catch (e) {}
    },
  };
}

const _client = window.supabase.createClient(supabaseConfig.url, supabaseConfig.anonKey, {
  auth: {
    storageKey: window.__IS_ADMIN ? 'sb-adminApp-auth' : 'sb-storefrontApp-auth',
    storage: makeStorageAdapter(),
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: true, // required for the Google OAuth redirect flow below
  },
});

// ================================================================
// _db — Firestore-compatible shim over the `documents` table
// ================================================================
function _generateId() {
  if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
  return 'id_' + Date.now().toString(36) + Math.random().toString(36).slice(2);
}

function _docSnapshot(row) {
  return {
    id: row ? row.id : undefined,
    exists: !!row,
    data() { return row ? { ...row.data } : undefined; },
    ref: row ? _docRef(row.collection, row.id) : null,
  };
}

function _diffRows(prevRows, currRows) {
  const prevMap = new Map(prevRows.map(r => [r.id, r]));
  const currMap = new Map(currRows.map(r => [r.id, r]));
  const changes = [];
  currRows.forEach(r => {
    if (!prevMap.has(r.id)) changes.push({ type: 'added', doc: _docSnapshot(r) });
    else if (JSON.stringify(prevMap.get(r.id).data) !== JSON.stringify(r.data)) changes.push({ type: 'modified', doc: _docSnapshot(r) });
  });
  prevRows.forEach(r => { if (!currMap.has(r.id)) changes.push({ type: 'removed', doc: _docSnapshot(r) }); });
  return changes;
}

function _querySnapshot(rows, changesOverride) {
  const docs = rows.map(_docSnapshot);
  return {
    docs,
    size: docs.length,
    empty: docs.length === 0,
    docChanges: changesOverride || (() => docs.map(d => ({ type: 'added', doc: d }))),
  };
}

function _buildQuery(collectionPath, state = {}) {
  const s = {
    filters: state.filters || [],
    orderByField: state.orderByField || null,
    orderByDir: state.orderByDir || 'asc',
    limitN: state.limitN || null,
    startAfterVal: state.startAfterVal,
  };

  async function runQuery() {
    let q = _client.from('documents').select('*').eq('collection', collectionPath);
    s.filters.forEach(([field, value]) => { q = q.eq(`data->>${field}`, String(value)); });
    if (s.orderByField) q = q.order(`data->>${s.orderByField}`, { ascending: s.orderByDir !== 'desc' });
    if (s.startAfterVal !== undefined) {
      if (s.orderByDir === 'desc') q = q.lt(`data->>${s.orderByField}`, String(s.startAfterVal));
      else q = q.gt(`data->>${s.orderByField}`, String(s.startAfterVal));
    }
    if (s.limitN) q = q.limit(s.limitN);
    const { data, error } = await q;
    if (error) throw error;
    return data || [];
  }

  return {
    where(field, _op, value) { return _buildQuery(collectionPath, { ...s, filters: [...s.filters, [field, value]] }); },
    orderBy(field, dir = 'asc') { return _buildQuery(collectionPath, { ...s, orderByField: field, orderByDir: dir }); },
    limit(n) { return _buildQuery(collectionPath, { ...s, limitN: n }); },
    startAfter(val) { return _buildQuery(collectionPath, { ...s, startAfterVal: val }); },
    async get() { return _querySnapshot(await runQuery()); },
    // Realtime listener — re-runs the same filtered query on every INSERT/
    // UPDATE/DELETE Supabase Realtime reports for this collection, and
    // diffs against the previous result to build docChanges(). Requires
    // `alter publication supabase_realtime add table public.documents;`
    // (already in supabase/schema.sql) and, for anything filtered to "my
    // own" rows, an authenticated session (RLS applies to Realtime too).
    onSnapshot(cb, errCb) {
      let prevRows = [];
      let live = true;
      async function refresh() {
        try {
          const rows = await runQuery();
          const snap = _querySnapshot(rows, () => _diffRows(prevRows, rows));
          prevRows = rows;
          if (live) cb(snap);
        } catch (e) { if (live && errCb) errCb(e); }
      }
      refresh();
      const channel = _client
        .channel(`docs:${collectionPath}:${_generateId()}`)
        .on('postgres_changes', { event: '*', schema: 'public', table: 'documents', filter: `collection=eq.${collectionPath}` }, refresh)
        .subscribe();
      return () => { live = false; _client.removeChannel(channel); };
    },
  };
}

function _docRef(path, id) {
  return {
    id,
    // Emulates a Firestore subcollection path, e.g.
    // _db.collection('products').doc(id).collection('private') →
    // collection path "products/<id>/private" — same string format
    // worker.js already uses for these.
    collection(subPath) { return _collectionRef(`${path}/${id}/${subPath}`); },
    async get() {
      const { data, error } = await _client.from('documents').select('*').eq('collection', path).eq('id', id).maybeSingle();
      if (error) throw error;
      return _docSnapshot(data || null);
    },
    async set(data, options = {}) {
      let toWrite = data;
      if (options.merge) {
        const { data: existing } = await _client.from('documents').select('*').eq('collection', path).eq('id', id).maybeSingle();
        toWrite = { ...((existing && existing.data) || {}), ...data };
      }
      const { error } = await _client.from('documents').upsert([{ collection: path, id, data: toWrite }], { onConflict: 'collection,id' });
      if (error) throw error;
    },
    async update(data) {
      const { data: existing, error: readErr } = await _client.from('documents').select('*').eq('collection', path).eq('id', id).maybeSingle();
      if (readErr) throw readErr;
      const merged = { ...((existing && existing.data) || {}), ...data };
      const { error } = await _client.from('documents').update({ data: merged, updated_at: new Date().toISOString() }).eq('collection', path).eq('id', id);
      if (error) throw error;
    },
    async delete() {
      const { error } = await _client.from('documents').delete().eq('collection', path).eq('id', id);
      if (error) throw error;
    },
  };
}

function _collectionRef(path) {
  const query = _buildQuery(path);
  return {
    ...query,
    doc(id) { return _docRef(path, id || _generateId()); },
    async add(data) {
      const { data: rows, error } = await _client.from('documents').insert([{ collection: path, data }]).select();
      if (error) throw error;
      return _docRef(path, rows[0].id);
    },
  };
}

const _db = {
  collection(path) { return _collectionRef(path); },
  batch() {
    const ops = [];
    return {
      delete(ref) { ops.push(() => ref.delete()); },
      set(ref, data, options) { ops.push(() => ref.set(data, options)); },
      update(ref, data) { ops.push(() => ref.update(data)); },
      async commit() { await Promise.all(ops.map(fn => fn())); },
    };
  },
};

// ================================================================
// _auth — small Firebase-Auth-shaped wrapper over Supabase Auth
// ================================================================
function _wrapUser(u) {
  if (!u) return null;
  return {
    uid: u.id,
    email: u.email || '',
    displayName: (u.user_metadata && (u.user_metadata.full_name || u.user_metadata.name)) || '',
    photoURL: (u.user_metadata && u.user_metadata.avatar_url) || '',
    app_metadata: u.app_metadata || {},
    async getIdToken(forceRefresh) {
      if (forceRefresh) {
        const { data, error } = await _client.auth.refreshSession();
        if (error) return null;
        return data.session ? data.session.access_token : null;
      }
      const { data } = await _client.auth.getSession();
      return data.session ? data.session.access_token : null;
    },
    async updateProfile({ displayName } = {}) {
      const patch = {};
      if (displayName !== undefined) patch.full_name = displayName;
      const { error } = await _client.auth.updateUser({ data: patch });
      if (error) throw error;
    },
  };
}

let _cachedAuthUser = null;
_client.auth.onAuthStateChange((_event, session) => { _cachedAuthUser = session ? session.user : null; });

const _auth = {
  get currentUser() { return _wrapUser(_cachedAuthUser); },
  onAuthStateChanged(cb) {
    const { data: sub } = _client.auth.onAuthStateChange((_event, session) => cb(_wrapUser(session ? session.user : null)));
    return () => sub.subscription.unsubscribe();
  },
  async signOut() { await _client.auth.signOut(); },
  async createUserWithEmailAndPassword(email, password) {
    const { data, error } = await _client.auth.signUp({ email, password });
    if (error) throw error;
    return { user: _wrapUser(data.user), session: data.session };
  },
  async signInWithEmailAndPassword(email, password) {
    const { data, error } = await _client.auth.signInWithPassword({ email, password });
    if (error) throw error;
    return { user: _wrapUser(data.user) };
  },
  async setPersistence(mode) { _persistMode = mode; },
  Persistence: { LOCAL: 'local', SESSION: 'session' },
  async sendPasswordResetEmail(email) {
    const { error } = await _client.auth.resetPasswordForEmail(email);
    if (error) throw error;
  },
};

// ================================================================
// USER AUTH — Supabase Authentication
// ================================================================
const UserAuth = {
  _current: null,

  // Access token for the currently signed-in customer (any user, not just
  // the admin — unlike Auth.getIdToken() below, which is deliberately
  // gated to ADMIN_EMAIL). Used to authenticate ordinary customers to
  // Worker routes that need to know *which* signed-in user is calling,
  // e.g. /api/claim-free. The token proves identity; it grants no special
  // privilege by itself — the Worker verifies it independently and
  // decides what that specific uid is allowed to do.
  async getIdToken(forceRefresh) {
    const u = _auth.currentUser;
    if (!u) return null;
    try { return await u.getIdToken(!!forceRefresh); }
    catch (e) { return null; }
  },

  init() {
    _auth.onAuthStateChanged(user => this._handleAuthChange(user));
  },

  async _handleAuthChange(user) {
    // ── Reserved-account guard (defense in depth) ─────────────────
    // Belt-and-suspenders on top of the checks in loginWithGoogle() and
    // _afterGoogleAuth(): the STOREFRONT (UserAuth) must never treat a
    // signed-in ADMIN_EMAIL session as a regular customer. Sign it out
    // immediately and stop — do not set _current or dispatch
    // auth:change for it, so no storefront UI or logic ever sees
    // "logged in as chaqx12".
    //
    // CRITICAL: this guard must NOT run on admin.html. supabase.js is
    // shared between both pages, but each page gets its OWN Supabase
    // client (see the app-isolation note above `_client`), so this
    // listener only ever fires for that page's own session — the
    // window.__IS_ADMIN check below is what lets admin.html's own
    // client authenticate as ADMIN_EMAIL without tripping this guard.
    if (!window.__IS_ADMIN && user && (user.email || '').toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
      _auth.signOut();
      return;
    }

    if (!user) {
      this._current = null;
      window.dispatchEvent(new Event('auth:change'));
      return;
    }

    // Google sign-ins need the "does this account already have a
    // completed profile (username + phone)" check before being treated
    // as logged in — see _afterGoogleAuth(). Email/password sessions
    // (created via register()/login() below, which already write/verify
    // the users doc themselves) skip straight to the normal path.
    const isGoogle = user.app_metadata && user.app_metadata.provider === 'google';
    if (isGoogle) {
      let consumingRedirect = false;
      try { consumingRedirect = sessionStorage.getItem('_googleOAuthPending') === '1'; } catch (e) {}
      if (consumingRedirect) { try { sessionStorage.removeItem('_googleOAuthPending'); } catch (e) {} }

      const result = await this._afterGoogleAuth(user);
      // Only fire the 'google-redirect-result' event (which the login
      // modal listens for — see index.html) when this session change was
      // actually caused by the redirect-back from loginWithGoogle(), not
      // every time a page loads with an existing Google session already
      // signed in (which would otherwise re-pop the modal on every visit).
      if (consumingRedirect) {
        window.dispatchEvent(new CustomEvent('google-redirect-result', { detail: result }));
      }
      return;
    }

    // Dispatch auth:change immediately from Auth data so UI renders without waiting for the users table
    this._current = { id: user.uid, email: user.email, name: user.displayName || user.email.split('@')[0] };
    window.dispatchEvent(new Event('auth:change'));
    // Then fetch the users row in the background to correct email/name if
    // needed (fixes cases where the account's email differs from the
    // registered email).
    _db.collection('users').doc(user.uid).get().then(doc => {
      if (doc.exists) {
        const data = doc.data();
        if (data.email || data.name) {
          this._current = { id: user.uid, email: data.email || user.email, name: data.name || user.displayName || user.email.split('@')[0] };
          window.dispatchEvent(new Event('auth:change'));
        }
      }
    }).catch(() => {});
  },

  current() { return this._current; },

  async register(email, password, name, phone) {
    try {
      // Never let the public sign-up form create an account using the
      // reserved admin email — that is the exact path used to hijack
      // admin access before (register on the storefront, then log into
      // /admin.html with the account you just made). This is a
      // client-side speed bump, not a hard guarantee — see the note
      // above the ADMIN_EMAIL constant for the real fix.
      if ((email || '').trim().toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
        return { error: 'This email address is not available.' };
      }

      const { data: signUpData, error: signUpErr } = await _client.auth.signUp({ email, password });
      if (signUpErr) return { error: this._msg(signUpErr.message) };
      if (!signUpData.session) {
        // Your Supabase project has "Confirm email" turned on — the
        // account was created but there's no active session yet. See
        // SETUP.md if you'd rather this behave like the old Firebase
        // setup (instant sign-in, no confirmation step).
        return { error: 'Account created — please check your email to confirm it, then log in.' };
      }
      const accessToken = signUpData.session.access_token;
      const displayName = name || email.split('@')[0];

      if (phone) {
        const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
        if (backendUrl) {
          try {
            const res = await fetch(`${backendUrl}/api/complete-google-registration`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
              body: JSON.stringify({ username: displayName, phone, checkUsername: false }),
            });
            const data = await res.json();
            if (!res.ok || data.error) {
              // Duplicate phone (or any other failure) — roll back the
              // auth account we just created so the email is free to
              // retry with, rather than leaving an orphaned account.
              // (Supabase's client SDK has no self-delete method — this
              // hits a small Worker route that verifies the token proves
              // the caller IS this exact account, then deletes it with
              // the service-role key. See POST /api/rollback-registration
              // in worker.js.)
              await fetch(`${backendUrl}/api/rollback-registration`, {
                method: 'POST', headers: { Authorization: `Bearer ${accessToken}` },
              }).catch(() => {});
              await _client.auth.signOut().catch(() => {});
              return { error: data.error || 'Registration failed. Please try again.' };
            }
            // Worker already wrote the full users row — just update the
            // Auth profile's display name and finish.
            await _client.auth.updateUser({ data: { full_name: displayName } }).catch(() => {});
            this._current = data.user;
            window.dispatchEvent(new Event('auth:change'));
            return { user: this._current };
          } catch (ne) {
            await fetch(`${backendUrl}/api/rollback-registration`, {
              method: 'POST', headers: { Authorization: `Bearer ${accessToken}` },
            }).catch(() => {});
            await _client.auth.signOut().catch(() => {});
            return { error: 'Could not reach the server. Please check your connection and try again.' };
          }
        }
        // If backendUrl isn't configured, fall through and write directly
        // below rather than blocking signup entirely over a missing check.
      }

      await _client.auth.updateUser({ data: { full_name: displayName } }).catch(() => {});
      await _db.collection('users').doc(signUpData.user.id).set({
        id: signUpData.user.id, email: email.toLowerCase(), name: displayName,
        phone: phone || '',
        phoneVerified: !!phone,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
      }, { merge: true });
      this._current = { id: signUpData.user.id, email: signUpData.user.email, name: displayName, phone: phone || '' };
      window.dispatchEvent(new Event('auth:change'));
      return { user: this._current };
    } catch (e) { return { error: this._msg(e.message) }; }
  },

  async login(email, password, remember = false) {
    try {
      try { await _auth.setPersistence(remember ? _auth.Persistence.LOCAL : _auth.Persistence.SESSION); } catch (pe) {}
      const { user } = await _auth.signInWithEmailAndPassword(email, password);
      this._current = { id: user.uid, email: user.email, name: user.displayName || user.email.split('@')[0] };
      window.dispatchEvent(new Event('auth:change'));
      // Record this sign-in for the admin's "last seen" view. Non-blocking —
      // if it fails (e.g. offline) it shouldn't stop the user from logging in.
      _db.collection('users').doc(user.uid).set({
        lastLogin: new Date().toISOString()
      }, { merge: true }).catch(() => {});
      return { user: this._current };
    } catch (e) { return { error: this._msg(e.message) }; }
  },

  // Redirect-based Google sign-in. Supabase Auth's OAuth flow is a full
  // page navigation to Google and back (there's no popup mode the way
  // Firebase had) — the browser leaves this page immediately, so this
  // never resolves normally on the click that calls it. What happens
  // after the redirect back is handled by _handleAuthChange() above
  // (which detects the pending flag set here and fires
  // 'google-redirect-result' — the login modal in index.html already
  // listens for that event, unchanged).
  async loginWithGoogle() {
    try { sessionStorage.setItem('_googleOAuthPending', '1'); } catch (e) {}
    const { error } = await _client.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: window.location.href,
        queryParams: { prompt: 'select_account' },
      },
    });
    if (error) {
      try { sessionStorage.removeItem('_googleOAuthPending'); } catch (e) {}
      return { error: this._msg(error.message) };
    }
    return { redirecting: true }; // the browser is navigating to Google now
  },

  // Shared logic for "a Google session just became active, now what" —
  // called from _handleAuthChange() for every Google-provider session,
  // whether that's a fresh redirect-back or an already-signed-in page
  // reload.
  async _afterGoogleAuth(user) {
    // ── Reserved-account guard ──────────────────────────────────
    // The admin account (ADMIN_EMAIL) must only ever be reached via
    // the dedicated admin.html email+password login (Auth.login).
    // If the browser's active Google session happens to be the
    // admin's Google account, hard-block that outcome unconditionally,
    // no matter how it happened.
    if ((user.email || '').toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
      await _auth.signOut();
      return { error: 'This Google account is not available for sign-in. Please use a different account.' };
    }

    // Check if a users row already exists with a phone (returning Google user)
    const existing = await _db.collection('users').doc(user.uid).get();
    if (existing.exists && existing.data().phone) {
      await _db.collection('users').doc(user.uid).set({
        updatedAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
      }, { merge: true });
      const data = existing.data();
      this._current = { id: user.uid, email: user.email, name: data.name || user.displayName, phone: data.phone };
      window.dispatchEvent(new Event('auth:change'));
      return { user: this._current, isNewUser: false };
    }

    // New Google user (or existing without phone) — stay signed in
    // (unlike the old Firebase flow, which signed out here — Supabase's
    // client can't cheaply resume a specific existing session the way
    // Firebase's popup could, so instead this account just isn't treated
    // as "logged in" (_current stays null) until completeGoogleRegistration()
    // below finishes the username+phone step.
    return {
      isNewUser: true,
      googleProfile: {
        uid: user.uid,
        email: user.email,
        displayName: user.displayName || '',
        photoURL: user.photoURL || '',
      }
    };
  },

  // Called after a new Google user completes the username + phone step.
  async completeGoogleRegistration(googleProfile, username, phone) {
    try {
      // Identity guard: make sure the live session really is still the
      // same Google account that started this registration — matters if,
      // say, another tab signed into a different account while this form
      // was open.
      const user = _auth.currentUser;
      if (!user || user.uid !== googleProfile.uid) {
        return { error: `Please sign in with ${googleProfile.email} again to finish registration.` };
      }
      const accessToken = await user.getIdToken();
      const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
      if (!backendUrl) return { error: 'Sign-up is temporarily unavailable (server not configured). Please contact support.' };

      let res, data;
      try {
        res = await fetch(`${backendUrl}/api/complete-google-registration`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
          body: JSON.stringify({ username, phone, photoURL: googleProfile.photoURL || '' }),
        });
        data = await res.json();
      } catch (ne) {
        return { error: 'Could not reach the server. Please check your connection and try again.' };
      }
      if (!res.ok || data.error) {
        // Duplicate username/phone (409) is a normal validation outcome —
        // the session is still live either way, so the user can just fix
        // the field and resubmit without redoing Google sign-in.
        return { error: data.error || 'Registration failed. Please try again.' };
      }

      await user.updateProfile({ displayName: data.user.name }).catch(() => {});
      this._current = data.user;
      window.dispatchEvent(new Event('auth:change'));
      return { user: this._current };
    } catch (e) {
      return { error: 'Registration failed. Please try again.' };
    }
  },

  logout() { _auth.signOut(); this._current = null; window.dispatchEvent(new Event('auth:change')); },

  // Updates the signed-in user's display name — used by the Account →
  // Settings panel. Writes to both Supabase Auth (source of truth for
  // displayName) and the 'users' row (so admin views / other reads that
  // pull from there stay in sync), then updates the in-memory _current
  // record and notifies the UI.
  async updateName(newName) {
    const user = _auth.currentUser;
    if (!user) throw new Error('You must be signed in.');
    const name = (newName || '').trim();
    if (!name) throw new Error('Name cannot be empty.');
    try {
      await user.updateProfile({ displayName: name });
    } catch (e) { throw new Error(this._msg(e.message)); }
    try { await _db.collection('users').doc(user.uid).set({ name }, { merge: true }); } catch (e) { /* non-fatal */ }
    if (this._current) this._current = { ...this._current, name };
    window.dispatchEvent(new Event('auth:change'));
    return name;
  },

  // Sends a "reset your password" email via Supabase Auth to the
  // signed-in user's own address — used by the Account → Settings panel.
  // There's no in-app password-change form; this is the standard,
  // safest flow (no need to collect/verify the current password here).
  async sendPasswordReset() {
    const email = (this._current && this._current.email) || (_auth.currentUser && _auth.currentUser.email);
    if (!email) throw new Error('No email on file for this account.');
    try {
      await _auth.sendPasswordResetEmail(email);
    } catch (e) { throw new Error(this._msg(e.message)); }
    return email;
  },

  async getAll() {
    try {
      const snap = await _db.collection('users').get();
      return snap.docs.map(d => d.data());
    } catch (e) { return []; }
  },

  _msg(message) {
    console.warn('[Auth]', message);
    const raw = String(message || '');
    if (/already registered|already been registered/i.test(raw)) return 'Email already registered.';
    if (/invalid login credentials/i.test(raw)) return 'Incorrect email or password.';
    if (/user not found/i.test(raw)) return 'No account found with this email.';
    if (/password.*(least|characters)/i.test(raw)) return 'Password must be at least 6 characters.';
    if (/invalid.*email/i.test(raw)) return 'Invalid email address.';
    if (/rate limit|too many/i.test(raw)) return 'Too many attempts. Try again later.';
    if (/network/i.test(raw)) return 'Network error. Check your connection.';
    return raw || 'Something went wrong. Please try again.';
  }
};
UserAuth.init();

// ================================================================
// PURCHASES — collection: purchases
// ================================================================
const Purchases = {
  async add(userId, userEmail, product, extra = {}) {
    const now = new Date().toISOString();

    // Proof images are already compressed base64 data URLs (converted in
    // the browser before this call). Stored directly in the JSON doc —
    // no separate object storage involved.
    const proofImageUrls = (extra.proofImages || []).filter(
      s => typeof s === 'string' && s.length > 0
    );

    const doc = {
      userId, userEmail,
      productId:     product.id    || '',
      productName:   product.name  || '',
      productImage:  (product.images||[])[0] || product.productImage || '',
      productType:   product.category || extra.productType || 'Digital',
      accessLink:    extra.accessLink  || '',
      proofImages:   proofImageUrls,
      customerName:  extra.customerName  || '',
      customerPhone: extra.customerPhone || '',
      customerEmail: extra.customerEmail || userEmail || '',
      paymentMethod: extra.paymentMethod || '',
      orderNotes:    extra.orderNotes || '',
      status:        'pending',
      purchaseDate:  now,
      createdAt:     now,
      orderId:       extra.orderId || '',
      variantLabel:  extra.variantLabel || '',
    };
    const ref = await _db.collection('purchases').add(doc);
    return { ...doc, id: ref.id };
  },

  async forUser(userId) {
    try {
      const snap = await _db.collection('purchases').where('userId', '==', userId).get();
      const docs = snap.docs.map(d => ({ ...d.data(), id: d.id }));
      docs.sort((a, b) => {
        const ta = a.purchaseDate?.toDate?.() || new Date(a.createdAt || 0);
        const tb = b.purchaseDate?.toDate?.() || new Date(b.createdAt || 0);
        return tb - ta;
      });
      return docs;
    } catch(e) { console.error('Purchases.forUser:', e); return []; }
  },

  async getAll() {
    try {
      const snap = await _db.collection('purchases').get();
      const docs = snap.docs.map(d => ({ ...d.data(), id: d.id }));
      docs.sort((a, b) => {
        const ta = a.purchaseDate?.toDate?.() || new Date(a.createdAt || 0);
        const tb = b.purchaseDate?.toDate?.() || new Date(b.createdAt || 0);
        return tb - ta;
      });
      return docs;
    } catch(e) { console.error('Purchases.getAll:', e); return []; }
  },

  async delete(id) {
    try { await _db.collection('purchases').doc(id).delete(); } catch(e) { console.error(e); }
  },

  async update(id, data) {
    const patch = { ...data };
    // Only auto-set status when delivering (accessData/accessLink change),
    // and only if status is not already a cancel or picked-up state
    const preservedStatuses = ['canceled_by_client', 'canceled_by_admin', 'picked_up'];
    const existingStatus = data._existingStatus || null;
    const isPreserved = preservedStatuses.includes(existingStatus);
    delete patch._existingStatus; // internal helper, don't write to DB

    if (!isPreserved && !('status' in data)) {
      const hasAccessData = data.accessData && Object.values(data.accessData).some(v => v);
      const hasAccessLink = 'accessLink' in data && data.accessLink && data.accessLink.trim();
      if (hasAccessData || hasAccessLink) {
        patch.status = 'completed';
        patch.deliveredAt = new Date().toISOString();
      } else if ('accessLink' in data && !data.accessLink) {
        patch.status = 'pending';
        patch.deliveredAt = null;
      }
    }
    await _db.collection('purchases').doc(id).update(patch);
  },

  onSnapshotForUser(userId, callback) {
    return _db.collection('purchases').where('userId', '==', userId)
      .onSnapshot(snap => {
        const docs = snap.docs.map(d => ({ ...d.data(), id: d.id }));
        docs.sort((a, b) => {
          const ta = a.purchaseDate?.toDate?.() || new Date(a.createdAt || 0);
          const tb = b.purchaseDate?.toDate?.() || new Date(b.createdAt || 0);
          return tb - ta;
        });
        callback(docs);
      }, err => { console.error('onSnapshotForUser:', err); callback([]); });
  },

  onSnapshotAll(callback) {
    return _db.collection('purchases')
      .onSnapshot(snap => {
        const docs = snap.docs.map(d => ({ ...d.data(), id: d.id }));
        docs.sort((a, b) => {
          const ta = a.purchaseDate?.toDate?.() || new Date(a.createdAt || 0);
          const tb = b.purchaseDate?.toDate?.() || new Date(b.createdAt || 0);
          return tb - ta;
        });
        callback(docs);
      }, err => { console.error('onSnapshotAll:', err); callback([]); });
  },
};

// ================================================================
// REVIEWS — collection: reviews
// ================================================================
const Reviews = {
  // Submit a new review (one per user per product, enforced client-side)
  async submit({ userId, userName, productId, productName, stars, comment }) {
    const data = {
      userId, userName, productId, productName,
      stars, comment: comment || '',
      status: 'pending', // pending | approved | rejected
      createdAt: new Date().toISOString(),
    };
    try {
      const ref = await _db.collection('reviews').add(data);
      return { ok: true, id: ref.id };
    } catch(e) { return { error: e.message }; }
  },

  // Check if user already reviewed a product
  async hasReviewed(userId, productId) {
    try {
      const snap = await _db.collection('reviews')
        .where('userId', '==', userId)
        .where('productId', '==', productId)
        .limit(1).get();
      return !snap.empty;
    } catch(e) { return false; }
  },

  // Get approved reviews for a product
  async forProduct(productId) {
    try {
      const snap = await _db.collection('reviews')
        .where('productId', '==', productId)
        .where('status', '==', 'approved')
        .get();
      return snap.docs.map(d => ({ ...d.data(), id: d.id }))
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    } catch(e) { return []; }
  },

  // Get all approved reviews across all products (for homepage social proof carousel)
  async allApproved(limit) {
    try {
      const snap = await _db.collection('reviews')
        .where('status', '==', 'approved')
        .get();
      const docs = snap.docs.map(d => ({ ...d.data(), id: d.id }))
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      return limit ? docs.slice(0, limit) : docs;
    } catch(e) { return []; }
  },

  // Admin: realtime listener for all reviews
  onSnapshotAll(callback) {
    return _db.collection('reviews')
      .orderBy('createdAt', 'desc')
      .onSnapshot(snap => {
        callback(snap.docs.map(d => ({ ...d.data(), id: d.id })));
      }, () => callback([]));
  },

  // Admin: update review status
  async updateStatus(id, status) {
    try {
      await _db.collection('reviews').doc(id).update({ status, updatedAt: new Date().toISOString() });
      // If approved, update the product rating average
      const doc = await _db.collection('reviews').doc(id).get();
      if (doc.exists) await Reviews._recalcProductRating(doc.data().productId);
      return true;
    } catch(e) { return false; }
  },

  // Admin: delete a review
  async delete(id) {
    try {
      const doc = await _db.collection('reviews').doc(id).get();
      const productId = doc.exists ? doc.data().productId : null;
      await _db.collection('reviews').doc(id).delete();
      if (productId) await Reviews._recalcProductRating(productId);
      return true;
    } catch(e) {
      // Log a helpful hint for the most common cause (Supabase Row Level
      // Security) — same pattern as DB.add() below, so this failure is no
      // longer silently swallowed.
      if (e.message && /row-level security|permission denied/i.test(e.message)) {
        console.error('[DIGITCH] Review delete BLOCKED by Row Level Security. The admin panel signs in via Supabase Auth as ADMIN_EMAIL (see Auth.login below) — make sure supabase/schema.sql\'s is_admin() policies were applied and that this account\'s email matches exactly.');
      } else {
        console.error('Reviews.delete:', e);
      }
      return false;
    }
  },

  // Recalculate average rating for a product based on approved reviews
  async _recalcProductRating(productId) {
    try {
      const snap = await _db.collection('reviews')
        .where('productId', '==', productId)
        .where('status', '==', 'approved').get();
      const docs = snap.docs;
      if (!docs.length) {
        await _db.collection('products').doc(productId).update({ rating: null, reviewCount: 0 });
        return;
      }
      const avg = docs.reduce((s, d) => s + (d.data().stars || 0), 0) / docs.length;
      await _db.collection('products').doc(productId).update({
        rating: Math.round(avg * 10) / 10,
        reviewCount: docs.length,
      });
      // Update local cache
      if (DB._cache.products) {
        const i = DB._cache.products.findIndex(p => p.id === productId);
        if (i >= 0) {
          DB._cache.products[i].rating = Math.round(avg * 10) / 10;
          DB._cache.products[i].reviewCount = docs.length;
          try { localStorage.setItem('dz_fc_products', JSON.stringify(DB._cache.products)); } catch(e) {}
        }
      }
    } catch(e) {}
  }
};

// ================================================================
// IMAGE COMPRESSION
// ================================================================
async function compressImage(file, maxDim = 700, quality = 0.72) {
  return new Promise(resolve => {
    const reader = new FileReader();
    reader.onload = e => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        let w = img.width, h = img.height;
        if (w > maxDim || h > maxDim) {
          if (w > h) { h = Math.round(h * maxDim / w); w = maxDim; }
          else { w = Math.round(w * maxDim / h); h = maxDim; }
        }
        canvas.width = w; canvas.height = h;
        canvas.getContext('2d').drawImage(img, 0, 0, w, h);
        resolve(canvas.toDataURL('image/jpeg', quality));
      };
      img.onerror = () => resolve('');
      img.src = e.target.result;
    };
    reader.onerror = () => resolve('');
    reader.readAsDataURL(file);
  });
}

function generatePlaceholder(text, w = 400, h = 300) {
  const abbr = (text.split(' ').slice(0,2).map(x=>x[0]||'').join('')||text.slice(0,2)).toUpperCase();
  return 'data:image/svg+xml,' + encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">` +
    `<rect width="${w}" height="${h}" fill="#1E1E1E"/>` +
    `<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" ` +
    `font-family="sans-serif" font-size="${Math.min(w,h)*0.28}" fill="rgba(255,255,255,0.15)" font-weight="bold">${abbr}</text>` +
    `</svg>`
  );
}

// ================================================================
// ADMIN AUTH — real Supabase Authentication
// ================================================================
// Admin sign-in is a real Supabase Auth account. The password is never
// stored here or checked client-side — Supabase verifies it server-side
// and hands back a signed access token, which is what actually protects
// the Worker's admin routes (see requireAdminAuth in worker.js).
// ADMIN_EMAIL below is not a secret (an email address isn't sensitive on
// its own); it just tells this file which signed-in account counts as
// "the admin."
//
// One-time setup:
//   1. Supabase dashboard → Authentication → Users → Add user
//      (pick the admin's real login email + a strong password).
//   2. Put that same email below.
//   3. On the Worker: npx wrangler secret put ADMIN_EMAIL  (same email).
const ADMIN_EMAIL = 'chaqx12@gmail.com';

const Auth = {
  isLoggedIn() {
    const u = _auth.currentUser;
    return !!u && (u.email || '').toLowerCase() === ADMIN_EMAIL.toLowerCase();
  },
  async login(pass) {
    try {
      await _auth.signInWithEmailAndPassword(ADMIN_EMAIL, pass);
      return this.isLoggedIn();
    } catch (e) {
      // Surface the real Supabase error instead of silently returning
      // false — "wrong password" was being shown for every possible
      // failure (wrong password, no such user, disabled account,
      // rate-limited, misconfigured project, etc), which makes real
      // problems impossible to diagnose. See console for e.message.
      console.error('[Auth.login] Supabase sign-in failed:', e.message);
      throw e;
    }
  },
  logout() { _auth.signOut(); },
  // Access token to send as `Authorization: Bearer <token>` on admin-only
  // Worker calls. getIdToken() auto-refreshes an expired token.
  async getIdToken(forceRefresh) {
    if (!this.isLoggedIn()) return null;
    try { return await _auth.currentUser.getIdToken(!!forceRefresh); }
    catch (e) { return null; }
  }
};

// ================================================================
// ADMIN AUDIT — login activity trail for the admin panel
// ================================================================
// The point: if the admin password is ever shared/leaked, this is how you'd
// notice — every successful sign-in gets a record with IP, approximate
// location, device, and time. It can only capture SUCCESSFUL sign-ins:
// a wrong password is rejected by Supabase's own servers before this site
// is ever involved, so failed attempts don't produce a record.
const AdminAudit = {
  // Called once after the admin panel confirms a signed-in admin session
  // (fresh login or restored session on page load).
  async logAccess() {
    const idToken = await Auth.getIdToken();
    if (!idToken) return;
    const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
    if (!backendUrl) return;
    try {
      await fetch(`${backendUrl}/api/admin/log-access`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + idToken },
      });
    } catch (e) { /* non-critical — don't block the admin from using the panel */ }
  },

  async list(limit = 100) {
    const idToken = await Auth.getIdToken();
    if (!idToken) return [];
    const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
    if (!backendUrl) return [];
    try {
      const res = await fetch(`${backendUrl}/api/admin/login-history?limit=${limit}`, {
        headers: { 'Authorization': 'Bearer ' + idToken },
      });
      const data = await res.json().catch(() => ({}));
      return Array.isArray(data.entries) ? data.entries : [];
    } catch (e) { return []; }
  },
};

// ================================================================
// ADMIN USERS — list registered users + delete a user (admin panel)
// ================================================================
// Deleting requires the Worker: removing a Supabase Auth account can't be
// done from the client SDK for anyone but the account itself, so the
// Worker does it server-side with the service-role key (see
// POST /api/delete-user in worker.js), same Bearer-token pattern as
// Storage.uploadFile/deleteFile below.
const AdminUsers = {
  async list() {
    try {
      const idToken = await Auth.getIdToken();
      if (!idToken) { console.error('[AdminUsers] list: not authenticated as admin.'); return []; }
      const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
      if (!backendUrl) { console.error('[AdminUsers] list: DIGISTORE_BACKEND_URL is not configured.'); return []; }
      const res = await fetch(`${backendUrl}/api/admin/users`, {
        headers: { Authorization: `Bearer ${idToken}` },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { console.error('[AdminUsers] list failed:', data.error || res.status); return []; }
      return data.users || [];
    } catch (e) {
      console.error('[AdminUsers] list failed:', e.message);
      return [];
    }
  },

  async remove(uid) {
    const idToken = await Auth.getIdToken();
    if (!idToken) return { error: 'Not authenticated as admin.' };
    const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
    if (!backendUrl) return { error: 'DIGISTORE_BACKEND_URL is not configured.' };
    try {
      const res = await fetch(`${backendUrl}/api/delete-user`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + idToken },
        body: JSON.stringify({ uid }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return { error: data.error || 'Failed to delete user.' };
      return { ok: true };
    } catch (e) {
      return { error: e.message };
    }
  },
};

// ================================================================
// DB — products / categories / orders
// ================================================================
const DB = {
  // --- Internal cache to allow sync-like reads after first load ---
  _cache: {},

  // How many docs to pull per collection on the initial load. `null` = no limit
  // (fetch everything, the old behavior). Set a number for collections that
  // can grow large — this is what keeps the storefront fast as the catalog grows.
  _LOAD_LIMITS: {
    products:   150,   // newest 150 products; raise this or add pagination in the UI if you need more
    categories: null,  // small collection, fine to load in full
    orders:     null,  // only ever loaded in the admin panel
  },

  // Load a collection into cache (call once on init)
  async _load(col) {
    // 1. Read from localStorage cache instantly (zero delay)
    try {
      const cached = localStorage.getItem('dz_fc_' + col);
      if (cached) {
        this._cache[col] = JSON.parse(cached);
        window.dispatchEvent(new CustomEvent('db:update', { detail: col }));
      }
    } catch(e) {}
    // 2. Fetch fresh in the background, update if changed. Use a bounded
    // query where possible instead of pulling the whole collection — this
    // is the single biggest lever for keeping page loads fast as
    // products/orders accumulate over time.
    try {
      let query = _db.collection(col);
      const limit = this._LOAD_LIMITS[col];
      if (limit) {
        // Requires a `createdAt` field on documents in this collection
        // (already set by DB.add()). Newest-first also matches what most
        // storefronts want to show by default.
        query = query.orderBy('createdAt', 'desc').limit(limit);
      }
      const snap = await query.get();
      const fresh = snap.docs.map(d => ({ ...d.data(), id: d.id }));
      this._cache[col] = fresh;
      try { localStorage.setItem('dz_fc_' + col, JSON.stringify(fresh)); } catch(e) {}
      window.dispatchEvent(new CustomEvent('db:update', { detail: col }));
    } catch(e) {
      console.error(`DB._load(${col}) failed:`, e);
      if (!this._cache[col]) this._cache[col] = [];
    }
  },

  // Fetch older products beyond the initial _LOAD_LIMITS window — call this
  // from a "Load more" button in the storefront UI instead of raising the
  // limit above indefinitely.
  async loadMoreProducts(pageSize = 60) {
    try {
      const current = this._cache.products || [];
      const oldestLoaded = current[current.length - 1];
      let query = _db.collection('products').orderBy('createdAt', 'desc').limit(pageSize);
      if (oldestLoaded && oldestLoaded.createdAt) {
        query = query.startAfter(oldestLoaded.createdAt);
      }
      const snap = await query.get();
      const more = snap.docs.map(d => ({ ...d.data(), id: d.id }));
      this._cache.products = [...current, ...more];
      try { localStorage.setItem('dz_fc_products', JSON.stringify(this._cache.products)); } catch(e) {}
      this._emit('products');
      return more.length; // caller can check if 0 came back to hide the "Load more" button
    } catch(e) {
      console.error('DB.loadMoreProducts:', e);
      return 0;
    }
  },

  // Sync read from cache (returns [] if not loaded yet)
  // Whether a collection has actually been loaded at least once (from
  // cache or the database). Lets the UI tell "still loading" apart from
  // "loaded, and there's genuinely nothing here" — getAll() alone can't,
  // since it returns [] in both cases.
  isLoaded(col) { return col in this._cache; },

  getAll(col) { return this._cache[col] || []; },

  getById(col, id) { return (this._cache[col] || []).find(x => x.id === id) || null; },

  async add(col, data) {
    try {
      const item = { ...data, createdAt: new Date().toISOString() };
      const ref = await _db.collection(col).add(item);
      const saved = { ...item, id: ref.id };
      if (!this._cache[col]) this._cache[col] = [];
      this._cache[col].unshift(saved);
      try { localStorage.setItem('dz_fc_' + col, JSON.stringify(this._cache[col])); } catch(e) {}
      this._emit(col);
      return saved;
    } catch(e) {
      // Log a helpful hint for the most common cause (Row Level Security)
      if (e.message && /row-level security|permission denied/i.test(e.message)) {
        console.error('[DIGITCH] Write BLOCKED by Row Level Security. Make sure supabase/schema.sql was run in your Supabase project, and that you\'re signed in as the ADMIN_EMAIL account.');
      } else {
        console.error('DB.add error:', e);
      }
      throw e; // Re-throw so callers (seed, admin) can show proper error messages
    }
  },

  async update(col, id, data) {
    try {
      await _db.collection(col).doc(id).update({ ...data, updatedAt: new Date().toISOString() });
      if (this._cache[col]) {
        const i = this._cache[col].findIndex(x => x.id === id);
        if (i >= 0) this._cache[col][i] = { ...this._cache[col][i], ...data, updatedAt: new Date().toISOString() };
      }
      try { localStorage.setItem('dz_fc_' + col, JSON.stringify(this._cache[col])); } catch(e) {}
      this._emit(col);
      return this._cache[col]?.find(x => x.id === id) || null;
    } catch(e) { console.error('DB.update:', e); return null; }
  },

  async delete(col, id) {
    try {
      await _db.collection(col).doc(id).delete();
      if (this._cache[col]) this._cache[col] = this._cache[col].filter(x => x.id !== id);
      try { localStorage.setItem('dz_fc_' + col, JSON.stringify(this._cache[col])); } catch(e) {}
      this._emit(col);
    } catch(e) { console.error('DB.delete:', e); }
  },

  // --- Product delivery info (admin-only) -------------------------------
  // deliveryLink / deliveryType / deliveryFiles / autoDeliver live in
  // products/{id}/private/delivery instead of on the public product doc.
  // That subdoc is never part of the products collection load above, so
  // it never ends up in every visitor's read or the dz_fc_products
  // localStorage cache — only the admin panel fetches it, one product at
  // a time, when actually opening that product to edit it. Row Level
  // Security (see supabase/schema.sql) has no policy granting anon/
  // authenticated access to this collection shape at all — only the
  // Worker's service-role key can read/write it.
  async getProductDelivery(id) {
    try {
      const doc = await _db.collection('products').doc(id).collection('private').doc('delivery').get();
      return doc.exists ? doc.data() : null;
    } catch(e) {
      console.error('DB.getProductDelivery:', e);
      return null;
    }
  },

  async setProductDelivery(id, data) {
    try {
      await _db.collection('products').doc(id).collection('private').doc('delivery')
        .set({ ...data, updatedAt: new Date().toISOString() });
      return true;
    } catch(e) {
      console.error('DB.setProductDelivery:', e);
      throw e;
    }
  },

  // --- Course/pack curriculum (admin-only) -------------------------------
  // Modules/lessons (course) or the resource list (pack) live in
  // products/{id}/private/curriculum — never on the public product doc,
  // for the same reason delivery info doesn't: it must never reach a
  // visitor who hasn't paid. The admin panel is the only caller of these
  // two methods; buyers read curriculum through the Worker's
  // GET /api/content/:id instead (see Learning.fetchContent below), which
  // checks a real purchase record before returning anything.
  async getProductCurriculum(id) {
    try {
      const doc = await _db.collection('products').doc(id).collection('private').doc('curriculum').get();
      return doc.exists ? doc.data() : null;
    } catch(e) {
      console.error('DB.getProductCurriculum:', e);
      return null;
    }
  },

  async setProductCurriculum(id, data) {
    try {
      await _db.collection('products').doc(id).collection('private').doc('curriculum')
        .set({ ...data, updatedAt: new Date().toISOString() });
      return true;
    } catch(e) {
      console.error('DB.setProductCurriculum:', e);
      throw e;
    }
  },

  _emit(col) { window.dispatchEvent(new CustomEvent('db:update', { detail: col })); }
};

// ================================================================
// LEARNING — buyer-side access to protected course/pack content.
// Always goes through the Worker (never a direct database read), so
// access is verified server-side against the caller's own purchase
// record every time, not cached or trusted from the client. See
// GET /api/content/:id and POST /api/progress in worker.js.
// ================================================================
const Learning = {
  async fetchContent(productId) {
    const idToken = await UserAuth.getIdToken();
    if (!idToken) return { error: 'Please sign in.' };
    const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
    if (!backendUrl) return { error: 'DIGISTORE_BACKEND_URL is not configured.' };
    try {
      const res = await fetch(`${backendUrl}/api/content/${encodeURIComponent(productId)}`, {
        headers: { Authorization: `Bearer ${idToken}` },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) return { error: data.error || `Request failed (${res.status})` };
      return data;
    } catch(e) {
      console.error('Learning.fetchContent:', e);
      return { error: 'Could not load this content. Please try again.' };
    }
  },

  async saveProgress(productId, lessonId, completed = true) {
    const idToken = await UserAuth.getIdToken();
    if (!idToken) return { error: 'Please sign in.' };
    const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
    if (!backendUrl) return { error: 'DIGISTORE_BACKEND_URL is not configured.' };
    try {
      const res = await fetch(`${backendUrl}/api/progress`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
        body: JSON.stringify({ productId, lessonId, completed }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) return { error: data.error || `Request failed (${res.status})` };
      return data;
    } catch(e) {
      console.error('Learning.saveProgress:', e);
      return { error: 'Could not save your progress. Please try again.' };
    }
  },
};

// ================================================================
// SETTINGS — doc: settings/store
// ================================================================
const Settings = {
  _defaults: {
    storeName:'DIGITCH', logo:null, logoLight:null, logoDark:null,
    primary:'#3454D1', secondary:'#3454D1', accent:'#3454D1', currency:'DA',
    social:{ facebook:'', instagram:'', whatsapp:'', telegram:'', tiktok:'', youtube:'' }
  },
  _data: null,

  get() {
    // Return cached data or defaults (for sync access)
    return { ...this._defaults, ...(this._data || {}) };
  },

  async load() {
    // Read localStorage cache instantly
    try {
      const cached = localStorage.getItem('dz_settings');
      if (cached) { this._data = JSON.parse(cached); }
    } catch(e) {}
    // Fetch fresh in the background
    try {
      const doc = await _db.collection('settings').doc('store').get();
      if (doc.exists) {
        this._data = doc.data();
        try { localStorage.setItem('dz_settings', JSON.stringify(this._data)); } catch(e) {}
      }
    } catch(e) { /* keep localStorage cache */ }
  },

  async save(patch) {
    this._data = { ...this.get(), ...patch };
    try {
      await _db.collection('settings').doc('store').set(this._data);
    } catch(e) { console.error('Settings.save:', e); }
    // Also keep in localStorage as instant-load cache
    try { localStorage.setItem('dz_settings', JSON.stringify(this._data)); } catch(e) {}
    window.dispatchEvent(new Event('settings:update'));
    return this._data;
  },

  applyTheme() {
    const s = this.get();
    const r = document.documentElement.style;

    // Only touch the accent color if a real, valid hex color is configured.
    const validPrimary = typeof s.primary === 'string' && /^#([a-f\d]{3}|[a-f\d]{6})$/i.test(s.primary.trim())
      ? s.primary.trim()
      : null;
    if (validPrimary) {
      r.setProperty('--accent', validPrimary); r.setProperty('--primary', validPrimary); r.setProperty('--secondary', validPrimary);
      const rgb = hexToRgb(validPrimary);
      if (rgb) {
        const v = `${rgb.r},${rgb.g},${rgb.b}`;
        r.setProperty('--accent-rgb', v); r.setProperty('--primary-rgb', v); r.setProperty('--secondary-rgb', v);
      }
      r.setProperty('--accent-dark', adjustColor(validPrimary, -20));
    }

    if (typeof s.storeName === 'string' && s.storeName.trim()) {
      document.querySelectorAll('.store-name').forEach(el => el.textContent = s.storeName.trim());
      const t = document.getElementById('page-title'); if (t) t.textContent = s.storeName.trim();
    }

    const _theme = document.documentElement.getAttribute('data-theme') || 'light';
    const _logoRaw = _theme === 'dark' ? (s.logoDark || null) : (s.logoLight || s.logo || null);
    const _logo = (typeof _logoRaw === 'string' && _logoRaw.trim()) ? _logoRaw.trim() : null;
    if (_logo) {
      document.querySelectorAll('.nav-logo-img').forEach(el => { el.src = _logo; el.style.display = 'block'; });
    } else {
      const _defaultLogo = _theme === 'dark' ? '/logob.png' : '/logo.png';
      document.querySelectorAll('.nav-logo-img').forEach(el => { el.src = _defaultLogo; el.style.display = 'block'; });
    }
  }
};

// Formats a product price for display — shows "FREE" for 0/empty prices
// instead of "0 DA", everywhere a price is rendered on the storefront.
// Shows the raw admin-panel price; the SlickPay fee is applied separately
// at checkout, not baked into the listed price.
function formatPrice(price, currency) {
  const n = Number(price) || 0;
  if (n <= 0) return 'FREE';
  return n.toLocaleString() + ' ' + (currency || 'DA');
}
window.formatPrice = formatPrice;

function hexToRgb(hex){const r=/^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);return r?{r:parseInt(r[1],16),g:parseInt(r[2],16),b:parseInt(r[3],16)}:null;}
function adjustColor(hex,amount){const rgb=hexToRgb(hex);if(!rgb)return hex;const clamp=v=>Math.max(0,Math.min(255,v+amount));return '#'+[clamp(rgb.r),clamp(rgb.g),clamp(rgb.b)].map(v=>v.toString(16).padStart(2,'0')).join('');}

// ================================================================
// CART — localStorage (per-device, intentional)
// ================================================================
const Cart = {
  get(){try{return JSON.parse(localStorage.getItem('dz_cart')||'[]');}catch{return[];}},
  _save(c){try{localStorage.setItem('dz_cart',JSON.stringify(c));}catch{}window.dispatchEvent(new Event('cart:update'));},
  add(prod,qty=1){const c=this.get();const cartId=prod.variantLabel?(prod.id+'__'+prod.variantLabel):prod.id;const ex=c.find(i=>i.id===cartId);if(ex)ex.qty+=qty;else c.push({id:cartId,productId:prod.id,name:prod.variantLabel?(prod.name+' — '+prod.variantLabel):prod.name,price:prod.price,img:(prod.images||[])[0]||null,qty,variantLabel:prod.variantLabel||null});this._save(c);},
  remove(id){this._save(this.get().filter(i=>i.id!==id));},
  setQty(id,qty){if(qty<1)return this.remove(id);const c=this.get();const it=c.find(i=>i.id===id);if(it){it.qty=qty;this._save(c);}},
  clear(){localStorage.removeItem('dz_cart');window.dispatchEvent(new Event('cart:update'));},
  total(){return this.get().reduce((s,i)=>s+i.price*i.qty,0);},
  count(){return this.get().reduce((s,i)=>s+i.qty,0);},
  // Drop any cart line whose underlying product no longer exists in the
  // live catalog (e.g. the seller deleted it). `validIds` is a Set of
  // currently-existing product ids. Returns how many lines were removed
  // so callers can toast/notify. People who already bought a product keep
  // access via the separate `purchases` collection — this prune only
  // affects items still sitting unpurchased in someone's cart.
  prune(validIds){
    const items = this.get();
    const kept = items.filter(i => validIds.has(i.productId || i.id));
    if (kept.length !== items.length) { this._save(kept); return items.length - kept.length; }
    return 0;
  },
  syncPrices(products){
    if (!Array.isArray(products) || !products.length) return false;
    const byId = new Map(products.map(p => [p.id, p]));
    const items = this.get();
    let changed = false;
    items.forEach(item => {
      const p = byId.get(item.productId || item.id);
      if (!p) return; // handled separately by prune()
      let newPrice = p.price;
      if (item.variantLabel) {
        const firstLabel = item.variantLabel.split(' / ')[0];
        let variantItems = null;
        if (p.variables && p.variables.length) variantItems = p.variables[0].items;
        else if (p.variants && p.variants.length) variantItems = p.variants;
        const match = (variantItems || []).find(v => v.label === firstLabel);
        newPrice = match && match.price != null ? match.price : p.price;
      }
      if (item.price !== newPrice) { item.price = newPrice; changed = true; }
      const newImg = (p.images || [])[0] || null;
      if (newImg && item.img !== newImg) { item.img = newImg; changed = true; }
    });
    if (changed) this._save(items);
    return changed;
  },
};

// Cross-tab sync: dz_cart lives in localStorage, and the browser's native
// 'storage' event only fires in OTHER tabs/windows of the same origin —
// never in the tab that made the change (that one already got the
// 'cart:update' dispatch from _save() above).
window.addEventListener('storage', (e) => {
  if (e.key === 'dz_cart') { window.dispatchEvent(new Event('cart:update')); }
});

// ================================================================
// WISHLIST SYNC — synced per user, fallback to localStorage
// ================================================================
const WishlistSync = {
  async save(ids) {
    const user = UserAuth.current();
    if (!user) return;
    try {
      await _db.collection('users').doc(user.id).set(
        { wishlist: ids },
        { merge: true }
      );
    } catch(e) { console.warn('WishlistSync.save:', e); }
  },

  async load() {
    const user = UserAuth.current();
    if (!user) return;
    try {
      const doc = await _db.collection('users').doc(user.id).get();
      if (doc.exists) {
        const data = doc.data();
        let cloudIds = Array.isArray(data.wishlist) ? data.wishlist : [];
        let localIds = [];
        try { localIds = JSON.parse(localStorage.getItem('dz_wishlist') || '[]'); } catch {}

        if (typeof DB !== 'undefined' && (DB.getAll('products') || []).length) {
          const validIds = new Set(DB.getAll('products').map(p => p.id));
          cloudIds = cloudIds.filter(id => validIds.has(id));
          localIds  = localIds.filter(id => validIds.has(id));
        }

        const merged = [...new Set([...cloudIds, ...localIds])];
        try { localStorage.setItem('dz_wishlist', JSON.stringify(merged)); } catch {}
        window.dispatchEvent(new Event('wishlist:update'));
        const original = Array.isArray(data.wishlist) ? data.wishlist : [];
        const changed = merged.length !== original.length || merged.some(id => !original.includes(id));
        if (changed) await this.save(merged);
      }
    } catch(e) { console.warn('WishlistSync.load:', e); }
  },

  async clear() {
    const user = UserAuth.current();
    if (!user) return;
    try {
      await _db.collection('users').doc(user.id).set({ wishlist: [] }, { merge: true });
    } catch(e) {}
  }
};

// Hook: whenever auth state changes, load or reset the wishlist
window.addEventListener('auth:change', () => {
  if (UserAuth.current()) {
    WishlistSync.load();
  } else {
    try { localStorage.removeItem('dz_wishlist'); } catch {}
    window.dispatchEvent(new Event('wishlist:update'));
  }
});

// ================================================================
// ANALYTICS — collection: product_events
// ================================================================
const Analytics = {
  _seenSet(key) {
    try {
      const raw = sessionStorage.getItem(key);
      return raw ? new Set(JSON.parse(raw)) : new Set();
    } catch(e) { return new Set(); }
  },
  _seenSave(key, set) {
    try { sessionStorage.setItem(key, JSON.stringify([...set])); } catch(e) {}
  },

  async logView(productId, productName) {
    if (!productId) return;
    const seen = this._seenSet('dz_seen_views');
    if (seen.has(productId)) return;
    seen.add(productId); this._seenSave('dz_seen_views', seen);
    try {
      await _db.collection('product_events').add({
        type: 'view', productId, productName: productName || '',
        createdAt: new Date().toISOString()
      });
    } catch(e) { console.warn('Analytics.logView:', e); }
  },

  async logCart(productId, productName) {
    if (!productId) return;
    const seen = this._seenSet('dz_seen_carts');
    if (seen.has(productId)) return;
    seen.add(productId); this._seenSave('dz_seen_carts', seen);
    try {
      await _db.collection('product_events').add({
        type: 'cart', productId, productName: productName || '',
        createdAt: new Date().toISOString()
      });
    } catch(e) { console.warn('Analytics.logCart:', e); }
  },

  async getAllEvents() {
    try {
      const snap = await _db.collection('product_events').get();
      return snap.docs.map(d => ({ ...d.data(), id: d.id }));
    } catch(e) { console.error('Analytics.getAllEvents:', e); return []; }
  },

  async resetProduct(productId) {
    if (!productId) return;
    try {
      const snap = await _db.collection('product_events').where('productId', '==', productId).get();
      if (snap.empty) return;
      const docs = snap.docs;
      for (let i = 0; i < docs.length; i += 450) {
        const batch = _db.batch();
        docs.slice(i, i + 450).forEach(d => batch.delete(d.ref));
        await batch.commit();
      }
    } catch(e) { console.error('Analytics.resetProduct:', e); throw e; }
  }
};

// ================================================================
// PRESENCE — collection: presence
// ================================================================
const Presence = {
  _sid: null,
  _productId: null,
  _timer: null,

  _getSid() {
    if (this._sid) return this._sid;
    try {
      let sid = sessionStorage.getItem('dz_sid');
      if (!sid) { sid = 'sid_' + Date.now().toString(36) + Math.random().toString(36).slice(2); sessionStorage.setItem('dz_sid', sid); }
      this._sid = sid;
    } catch(e) { this._sid = 'sid_' + Date.now() + Math.random(); }
    return this._sid;
  },

  setProduct(productId) { this._productId = productId || null; this._beat(); },

  async _beat() {
    try {
      await _db.collection('presence').doc(this._getSid()).set({
        productId: this._productId || null,
        lastSeen: new Date().toISOString()
      });
    } catch(e) { /* best-effort — never block the UI on this */ }
  },

  start() {
    if (this._timer) return;
    this._beat();
    this._timer = setInterval(() => this._beat(), 20000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) this._beat(); });
  },

  async getActive(windowSec = 45) {
    try {
      const snap = await _db.collection('presence').get();
      const now = Date.now();
      return snap.docs.map(d => d.data()).filter(x => {
        const t = x.lastSeen && x.lastSeen.toDate ? x.lastSeen.toDate().getTime() : (x.lastSeen ? new Date(x.lastSeen).getTime() : 0);
        return t && (now - t) < windowSec * 1000;
      });
    } catch(e) { console.error('Presence.getActive:', e); return []; }
  }
};

// ================================================================
// CART LIVE — collection: cart_live
// ================================================================
const CartLive = {
  _sid: null,
  _timer: null,

  _getSid() {
    if (this._sid) return this._sid;
    try {
      let sid = sessionStorage.getItem('dz_sid');
      if (!sid) { sid = 'sid_' + Date.now().toString(36) + Math.random().toString(36).slice(2); sessionStorage.setItem('dz_sid', sid); }
      this._sid = sid;
    } catch(e) { this._sid = 'sid_' + Date.now() + Math.random(); }
    return this._sid;
  },

  async _beat() {
    try {
      const cart = Cart.get();
      const productIds = [...new Set(cart.map(i => i.productId || i.id))];
      await _db.collection('cart_live').doc(this._getSid()).set({
        productIds,
        lastSeen: new Date().toISOString()
      });
    } catch(e) { console.warn('CartLive._beat (this usually means the "cart_live" collection needs a Row Level Security policy):', e.message || e); }
  },

  start() {
    if (this._timer) return;
    this._beat();
    this._timer = setInterval(() => this._beat(), 20000);
    window.addEventListener('cart:update', () => this._beat());
    document.addEventListener('visibilitychange', () => { if (!document.hidden) this._beat(); });
  },

  async getActiveCounts(windowSec = 45) {
    try {
      const snap = await _db.collection('cart_live').get();
      const now = Date.now();
      const counts = {};
      snap.docs.forEach(d => {
        const x = d.data();
        const t = x.lastSeen && x.lastSeen.toDate ? x.lastSeen.toDate().getTime() : (x.lastSeen ? new Date(x.lastSeen).getTime() : 0);
        if (t && (now - t) < windowSec * 1000 && Array.isArray(x.productIds)) {
          x.productIds.forEach(pid => { counts[pid] = (counts[pid]||0) + 1; });
        }
      });
      return counts;
    } catch(e) { console.error('CartLive.getActiveCounts:', e); return {}; }
  }
};

// ================================================================
// STORAGE (for admin storage manager)
// ================================================================
const Storage = {
  usage() {
    let bytes = 0;
    for (const k in localStorage) { if (localStorage.hasOwnProperty(k)) bytes += (k.length + (localStorage[k]||'').length) * 2; }
    return Math.round(bytes / 1024);
  },

  // Upload a file through the Worker, which stores it in Cloudflare R2.
  // folder:     storage path prefix, e.g. 'deliveries/<purchaseId>'
  // onProgress: optional callback(percent:number)
  uploadFile(file, folder, onProgress) {
    return new Promise(async (resolve, reject) => {
      const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
      if (!backendUrl) {
        reject(new Error('DIGISTORE_BACKEND_URL is not configured.'));
        return;
      }

      const idToken = await Auth.getIdToken();
      if (!idToken) {
        reject(new Error('Not signed in as admin — please log in again.'));
        return;
      }

      const formData = new FormData();
      formData.append('file', file);
      formData.append('folder', folder || 'deliveries/misc');

      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${backendUrl}/api/upload-file`, true);
      xhr.setRequestHeader('Authorization', 'Bearer ' + idToken);

      xhr.upload.onprogress = e => {
        if (onProgress && e.lengthComputable) {
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
      };

      xhr.onload = () => {
        let data;
        try {
          data = JSON.parse(xhr.responseText);
        } catch (e) {
          reject(new Error('Upload failed: invalid response from server.'));
          return;
        }
        if (xhr.status >= 200 && xhr.status < 300 && data && data.url) {
          resolve({
            url:  data.url,
            path: data.path,
            name: data.name || file.name,
            size: data.size || file.size || 0,
          });
        } else {
          reject(new Error('Upload failed: ' + (data && data.error ? data.error : `HTTP ${xhr.status}`)));
        }
      };

      xhr.onerror = () => reject(new Error('Upload failed: network error.'));

      xhr.send(formData);
    });
  },

  async deleteFile(path) {
    if (!path) return;
    const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
    if (!backendUrl) {
      console.warn('Storage.deleteFile: DIGISTORE_BACKEND_URL is not configured.');
      return;
    }
    const idToken = await Auth.getIdToken();
    if (!idToken) {
      console.warn('Storage.deleteFile: not signed in as admin.');
      return;
    }
    try {
      const res = await fetch(`${backendUrl}/api/delete-file`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + idToken },
        body: JSON.stringify({ path }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        console.warn('Storage.deleteFile:', data.error || `HTTP ${res.status}`);
      }
    } catch (e) {
      console.warn('Storage.deleteFile:', e);
    }
  }
};

// ================================================================
// INIT — load all data on startup
// ================================================================
async function initSupabaseData() {
  const COLS = window.__IS_ADMIN ? ['products', 'categories', 'orders'] : ['products', 'categories'];
  COLS.forEach(col => {
    try {
      const cached = localStorage.getItem('dz_fc_' + col);
      if (cached) DB._cache[col] = JSON.parse(cached);
    } catch(e) {}
  });
  try {
    const s = localStorage.getItem('dz_settings');
    if (s) Settings._data = JSON.parse(s);
  } catch(e) {}

  // Step 2: fire events so UI renders immediately with cached data
  window.dispatchEvent(new Event('settings:update'));
  window.dispatchEvent(new CustomEvent('db:update', { detail: 'all' }));

  // Step 3: refresh in the background (DB._load handles update)
  Settings.load().then(() => window.dispatchEvent(new Event('settings:update'))).catch(()=>{});
  Promise.all(COLS.map(col => DB._load(col))).then(() => {
    if (DB._cache.products) DB._cache.products.sort((a,b) => new Date(b.createdAt||0) - new Date(a.createdAt||0));
  }).catch(e => console.error('Data refresh:', e));
}

// Run immediately (synchronous cache part runs before first paint)
initSupabaseData().catch(e => console.error('initSupabaseData:', e));