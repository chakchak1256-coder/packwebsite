// ================================================================
// FIREBASE.JS — Firebase Auth + Firestore (fully synced)
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

const firebaseConfig = {
  apiKey: "AIzaSyAz6LUNMFRHOo4_pvLoB9UMg_u-VRc_RHA",
  authDomain: "generalwebsite-580f9.firebaseapp.com",
  projectId: "generalwebsite-580f9",
  storageBucket: "generalwebsite-580f9.firebasestorage.app",
  messagingSenderId: "566506288076",
  appId: "1:566506288076:web:58544c8c56cdab0df42369"
};

// ── App isolation (storefront vs admin) ────────────────────────────
// index.html and admin.html both load this file, but they must NOT
// share one Firebase Auth session. A single default app stores its
// session under one localStorage key regardless of which page wrote
// it, so logging into the admin panel in one tab overwrote the
// customer session in another tab (and vice versa) — Firebase would
// broadcast the change via the `storage` event and both tabs would
// end up pointed at whichever login happened most recently.
//
// Giving each page its own NAMED app gives each one its own
// persistence key (`firebase:authUser:<apiKey>:<appName>`), so the
// two sessions live side-by-side in localStorage and never overwrite
// each other. admin.html sets window.__IS_ADMIN = true before this
// file loads (see admin.html), which is what lets this file tell the
// two pages apart.
const _app = firebase.initializeApp(firebaseConfig, window.__IS_ADMIN ? 'adminApp' : 'storefrontApp');
const _auth    = firebase.auth(_app);
const _db      = firebase.firestore(_app);
const _storage = firebase.storage(_app);

// ================================================================
// USER AUTH — Firebase Authentication
// ================================================================
const UserAuth = {
  _current: null,

  // ID token for the currently signed-in customer (any user, not just the
  // admin — unlike Auth.getIdToken() above, which is deliberately gated to
  // ADMIN_EMAIL). Used to authenticate ordinary customers to Worker routes
  // that need to know *which* signed-in user is calling, e.g.
  // /api/claim-free. The token proves identity; it grants no special
  // privilege by itself — the Worker verifies it independently and decides
  // what that specific uid is allowed to do.
  async getIdToken(forceRefresh) {
    const u = _auth.currentUser;
    if (!u) return null;
    try { return await u.getIdToken(!!forceRefresh); }
    catch (e) { return null; }
  },

  init() {
    // Pick up any pending signInWithRedirect() from the popup-blocked
    // fallback in loginWithGoogle(). Safe to call even when the page
    // wasn't reached via a redirect — it just resolves to nothing.
    this._handleRedirectResult();

    _auth.onAuthStateChanged(user => {
      // ── Reserved-account guard (defense in depth) ─────────────────
      // Belt-and-suspenders on top of the checks in loginWithGoogle()
      // and completeGoogleRegistration(): the STOREFRONT (UserAuth) must
      // never treat a signed-in ADMIN_EMAIL session as a regular
      // customer. Sign it out immediately and stop — do not set
      // _current or dispatch auth:change for it, so no storefront UI or
      // logic ever sees "logged in as chaqx12".
      //
      // CRITICAL: this guard must NOT run on admin.html. firebase.js is
      // shared between both pages and this listener is global to the
      // one Firebase Auth instance, so without the __IS_ADMIN check
      // below this signed the admin BACK OUT the instant they logged in
      // successfully via Auth.login() — every real admin login looked
      // like it failed, and repeated attempts then tripped Firebase's
      // own too-many-requests lockout. admin.html sets
      // window.__IS_ADMIN = true before loading this file specifically
      // so this file can tell the two pages apart.
      if (!window.__IS_ADMIN && user && (user.email || '').toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
        _auth.signOut();
        return;
      }
      if (user) {
        // Dispatch auth:change immediately from Auth data so UI renders without waiting for Firestore
        this._current = { id: user.uid, email: user.email, name: user.displayName || user.email.split('@')[0] };
        window.dispatchEvent(new Event('auth:change'));
        // Then fetch Firestore users doc in background to correct email/name if needed
        // (fixes cases where Google account email differs from the registered email)
        _db.collection('users').doc(user.uid).get().then(doc => {
          if (doc.exists) {
            const data = doc.data();
            if (data.email || data.name) {
              this._current = { id: user.uid, email: data.email || user.email, name: data.name || user.displayName || user.email.split('@')[0] };
              window.dispatchEvent(new Event('auth:change'));
            }
          }
        }).catch(() => {});
      } else {
        this._current = null;
        window.dispatchEvent(new Event('auth:change'));
      }
    });
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

      const cred = await _auth.createUserWithEmailAndPassword(email, password);
      const displayName = name || email.split('@')[0];

      // ── Duplicate phone check + user-doc write, server-side ─────
      // This used to query `.where('phone', '==', phone)` from the
      // client BEFORE the account existed (request.auth was null), so
      // it always failed with permission-denied under any Firestore
      // rules that require authentication to query the 'users'
      // collection — it never actually worked. Now that the account
      // exists we have a valid ID token, so route the phone check and
      // the doc write through the Worker's service account instead,
      // the same way the Google sign-up flow does. checkUsername:false
      // preserves this form's original behavior of not requiring
      // unique display names (only the Google flow does that).
      if (phone) {
        const idToken = await cred.user.getIdToken();
        const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
        if (backendUrl) {
          try {
            const res = await fetch(`${backendUrl}/api/complete-google-registration`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
              body: JSON.stringify({ username: displayName, phone, checkUsername: false }),
            });
            const data = await res.json();
            if (!res.ok || data.error) {
              // Duplicate phone (or any other failure) — roll back the
              // auth account we just created so the email is free to
              // retry with, rather than leaving an orphaned account.
              await cred.user.delete().catch(() => {});
              return { error: data.error || 'Registration failed. Please try again.' };
            }
            // Worker already wrote the full user doc — just update the
            // Auth profile's displayName and finish.
            await cred.user.updateProfile({ displayName });
            this._current = data.user;
            window.dispatchEvent(new Event('auth:change'));
            return { user: this._current };
          } catch (ne) {
            await cred.user.delete().catch(() => {});
            return { error: 'Could not reach the server. Please check your connection and try again.' };
          }
        }
        // If backendUrl isn't configured, fall through and write directly
        // below rather than blocking signup entirely over a missing check.
      }

      await cred.user.updateProfile({ displayName });
      await _db.collection('users').doc(cred.user.uid).set({
        id: cred.user.uid, email: email.toLowerCase(), name: displayName,
        phone: phone || '',
        phoneVerified: !!phone,
        createdAt: firebase.firestore.FieldValue.serverTimestamp(),
        lastLogin: firebase.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
      this._current = { id: cred.user.uid, email: cred.user.email, name: displayName, phone: phone || '' };
      window.dispatchEvent(new Event('auth:change'));
      return { user: this._current };
    } catch(e) { return { error: this._msg(e.code) }; }
  },

  async login(email, password, remember = false) {
    try {
      try {
        const persistence = remember ? firebase.auth.Auth.Persistence.LOCAL : firebase.auth.Auth.Persistence.SESSION;
        await _auth.setPersistence(persistence);
      } catch(pe) {}
      const cred = await _auth.signInWithEmailAndPassword(email, password);
      this._current = { id: cred.user.uid, email: cred.user.email, name: cred.user.displayName || cred.user.email.split('@')[0] };
      window.dispatchEvent(new Event('auth:change'));
      // Record this sign-in for the admin's "last seen" view. Non-blocking —
      // if it fails (e.g. offline) it shouldn't stop the user from logging in.
      _db.collection('users').doc(cred.user.uid).set({
        lastLogin: firebase.firestore.FieldValue.serverTimestamp()
      }, { merge: true }).catch(() => {});
      return { user: this._current };
    } catch(e) { return { error: this._msg(e.code) }; }
  },

  async loginWithGoogle() {
    try {
      const provider = new firebase.auth.GoogleAuthProvider();
      provider.setCustomParameters({ prompt: 'select_account' });
      let cred;
      try {
        cred = await _auth.signInWithPopup(provider);
      } catch (popupErr) {
        // ── Popup-blocked fallback ───────────────────────────────
        // Many browsers/environments (Safari's popup rules, browsers
        // with strict third-party-cookie/popup policies, the site
        // running inside an iframe/preview pane, some mobile browsers)
        // block window.open() even though it's the direct result of a
        // click, which surfaces as auth/popup-blocked (and sometimes
        // auth/operation-not-supported-in-this-environment). Falling
        // back to a full-page redirect avoids that entirely — the
        // browser navigates to Google, then back to this page, where
        // _handleRedirectResult() (called from init(), below) picks up
        // the result and resumes the sign-in exactly as if the popup
        // had succeeded.
        if (popupErr.code === 'auth/popup-blocked' ||
            popupErr.code === 'auth/operation-not-supported-in-this-environment') {
          await _auth.signInWithRedirect(provider);
          // The page is now navigating away — this promise intentionally
          // never resolves normally from here.
          return { redirecting: true };
        }
        throw popupErr;
      }
      return await this._afterGoogleAuth(cred);
    } catch(e) {
      if (e.code === 'auth/popup-closed-by-user' || e.code === 'auth/cancelled-popup-request') {
        return { error: null };
      }
      return { error: this._msg(e.code) };
    }
  },

  // Shared logic for "just got a Google credential, now what" — used by
  // both the popup path above and the redirect-result path below, so the
  // two don't drift out of sync.
  async _afterGoogleAuth(cred) {
    const user = cred.user;
    const isNew = cred.additionalUserInfo && cred.additionalUserInfo.isNewUser;

    // ── Reserved-account guard ──────────────────────────────────
    // The admin account (ADMIN_EMAIL) must only ever be reached via
    // the dedicated admin.html email+password login (Auth.login).
    // This file shares one Firebase Auth instance between the
    // storefront (UserAuth) and the admin panel (Auth), so if the
    // browser's active/cached Google session happens to be the
    // admin's Google account, signInWithPopup/Redirect could silently
    // authenticate *that* account here — which would then also
    // satisfy Auth.isLoggedIn() (it just compares email), handing
    // out admin access through the public sign-in button. Hard-block
    // that outcome unconditionally, no matter how it happened.
    if ((user.email || '').toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
      await _auth.signOut();
      return { error: 'This Google account is not available for sign-in. Please use a different account.' };
    }

    // Check if user doc already exists with a phone (returning Google user)
    const existing = await _db.collection('users').doc(user.uid).get();
    if (existing.exists && existing.data().phone) {
      // Returning user — just update timestamp and return
      await _db.collection('users').doc(user.uid).set({
        updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
        lastLogin: firebase.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
      const data = existing.data();
      this._current = { id: user.uid, email: user.email, name: data.name || user.displayName, phone: data.phone };
      window.dispatchEvent(new Event('auth:change'));
      return { user: this._current, isNewUser: false };
    }

    // New Google user (or existing without phone) — sign them out temporarily
    // so they can complete the username+phone+OTP step before being fully registered
    await _auth.signOut();
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

  // Called once at page load (see init() below) to pick up the result of
  // a signInWithRedirect() started in loginWithGoogle()'s popup-blocked
  // fallback. If the page wasn't reached via a redirect return, this
  // resolves with no user and is a no-op. Dispatches a
  // 'google-redirect-result' event with the same shape doGoogleSignIn()
  // would have received directly, so the UI can react identically
  // whether the popup or the redirect path was used.
  async _handleRedirectResult() {
    try {
      const result = await _auth.getRedirectResult();
      if (!result || !result.user) return;

      // If completeGoogleRegistration()'s popup-blocked fallback stashed an
      // in-progress registration before redirecting, finish that instead of
      // treating this return as a plain login.
      let pendingReg = null;
      try {
        const raw = sessionStorage.getItem('_pendingGoogleReg');
        if (raw) { pendingReg = JSON.parse(raw); sessionStorage.removeItem('_pendingGoogleReg'); }
      } catch (se) { /* sessionStorage unavailable */ }

      const r = pendingReg
        ? await this._finishGoogleRegistration(result.user, pendingReg.googleProfile, pendingReg.username, pendingReg.phone)
        : await this._afterGoogleAuth(result);

      window.dispatchEvent(new CustomEvent('google-redirect-result', { detail: r }));
    } catch (e) {
      if (e.code && e.code !== 'auth/popup-closed-by-user') {
        window.dispatchEvent(new CustomEvent('google-redirect-result', { detail: { error: this._msg(e.code) } }));
      }
    }
  },

  // Called after Google user completes username + phone step
  async completeGoogleRegistration(googleProfile, username, phone) {
    try {
      // Re-authenticate with Google FIRST. loginWithGoogle() signs the user
      // out right after the initial popup (so a half-registered account
      // can't act as "logged in"), which means we're signed out at this
      // point. The duplicate-name/phone checks below read the 'users'
      // collection, and Firestore rules require request.auth != null for
      // that — running the reads before this re-auth caused every
      // completion attempt to fail with permission-denied, regardless of
      // whether the name/phone was actually taken.
      const provider = new firebase.auth.GoogleAuthProvider();
      provider.setCustomParameters({ prompt: 'none', login_hint: googleProfile.email });
      let cred;
      try {
        cred = await _auth.signInWithPopup(provider);
      } catch (popupErr) {
        // ── Popup-blocked fallback ───────────────────────────────
        // Same reasoning as loginWithGoogle(): some browsers/environments
        // block this popup even though it's silent (prompt:'none'). Stash
        // the in-progress registration in sessionStorage and fall back to
        // a redirect — _handleRedirectResult() detects the stashed state
        // on return and finishes registration instead of treating the
        // return as a plain login.
        if (popupErr.code === 'auth/popup-blocked' ||
            popupErr.code === 'auth/operation-not-supported-in-this-environment') {
          try {
            sessionStorage.setItem('_pendingGoogleReg', JSON.stringify({ googleProfile, username, phone }));
          } catch (se) { /* sessionStorage unavailable — redirect will fall back to a plain login prompt */ }
          await _auth.signInWithRedirect(provider);
          return { redirecting: true };
        }
        throw popupErr;
      }
      return await this._finishGoogleRegistration(cred.user, googleProfile, username, phone);
    } catch(e) {
      if (e.code === 'auth/popup-closed-by-user' || e.code === 'auth/cancelled-popup-request') {
        return { error: 'Google sign-in was cancelled. Please try again.' };
      }
      return { error: this._msg(e.code) };
    }
  },

  // Shared by completeGoogleRegistration()'s popup path and its
  // redirect-fallback resume path in _handleRedirectResult().
  async _finishGoogleRegistration(user, googleProfile, username, phone) {
    // ── Reserved-account guard ──────────────────────────────────
    // Same protection as in loginWithGoogle(): this re-auth step can
    // sign in SILENTLY using whatever Google session is already active
    // in the browser. If that happens to be the admin's Google account,
    // never let it complete — that would create/overwrite the admin's
    // Firestore 'users' doc from the public signup form and, since
    // Auth.isLoggedIn() just compares email against the same shared
    // _auth instance, hand out admin access. Check this before the uid
    // identity check below, since an admin-account sign-in could
    // otherwise still match if googleProfile.uid happened to be the
    // admin's uid.
    if ((user.email || '').toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
      await _auth.signOut();
      return { error: 'This Google account is not available for sign-in. Please use a different account.' };
    }

    // ── Identity guard ──────────────────────────────────────────
    // The silent re-auth (prompt:'none', or the redirect fallback) can
    // authenticate a different Google account than the one that started
    // registration if the browser has more than one active session.
    // login_hint is only a hint, not a guarantee. Without this check
    // we'd happily write the form's username/phone onto a completely
    // different person's account. Bail out hard if the authenticated
    // uid doesn't match the account that actually started registration.
    if (user.uid !== googleProfile.uid) {
      await _auth.signOut();
      return {
        error: `Signed in as ${user.email}, but registration was started with ${googleProfile.email}. ` +
               `Please make sure only that Google account is active in this browser, then try again.`
      };
    }

    // ── Complete registration server-side ────────────────────────
    // Duplicate-username/phone checks and the actual user-doc write now
    // happen in the Worker (/api/complete-google-registration), using the
    // service account instead of this client SDK. Firestore security
    // rules split "get" (read one doc by ID) from "list"/query
    // permissions — most default rule setups only grant the former, so
    // the client-side `.where('name', '==', ...)` duplicate check here
    // was hitting permission-denied on every single signup, regardless
    // of what's configured in the Firebase Console. Routing this through
    // the Worker's service account sidesteps that class of problem
    // entirely — no Firestore Rules changes needed.
    const idToken = await user.getIdToken();
    const backendUrl = (window.DIGISTORE_BACKEND_URL || '').replace(/\/+$/, '');
    if (!backendUrl) {
      await _auth.signOut();
      return { error: 'Sign-up is temporarily unavailable (server not configured). Please contact support.' };
    }
    let res, data;
    try {
      res = await fetch(`${backendUrl}/api/complete-google-registration`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
        body: JSON.stringify({ username, phone, photoURL: googleProfile.photoURL || '' }),
      });
      data = await res.json();
    } catch (ne) {
      await _auth.signOut();
      return { error: 'Could not reach the server. Please check your connection and try again.' };
    }
    if (!res.ok || data.error) {
      // Duplicate username/phone (409) is a normal validation outcome —
      // let the user fix the field and stay on the form rather than
      // signing them out.
      if (res.status !== 409) await _auth.signOut();
      return { error: data.error || 'Registration failed. Please try again.' };
    }

    await user.updateProfile({ displayName: data.user.name }).catch(() => {});
    this._current = data.user;
    window.dispatchEvent(new Event('auth:change'));
    return { user: this._current };
  },

  logout() { _auth.signOut(); this._current = null; window.dispatchEvent(new Event('auth:change')); },

  // Updates the signed-in user's display name — used by the Account →
  // Settings panel. Writes to both Firebase Auth (source of truth for
  // displayName) and the Firestore 'users' doc (so admin views / other
  // reads that pull from Firestore stay in sync), then updates the
  // in-memory _current record and notifies the UI.
  async updateName(newName) {
    const user = _auth.currentUser;
    if (!user) throw new Error('You must be signed in.');
    const name = (newName || '').trim();
    if (!name) throw new Error('Name cannot be empty.');
    try {
      await user.updateProfile({ displayName: name });
    } catch (e) { throw new Error(this._msg(e.code)); }
    try { await _db.collection('users').doc(user.uid).set({ name }, { merge: true }); } catch (e) { /* non-fatal */ }
    if (this._current) this._current = { ...this._current, name };
    window.dispatchEvent(new Event('auth:change'));
    return name;
  },

  // Sends a "reset your password" email via Firebase Auth to the
  // signed-in user's own address — used by the Account → Settings panel.
  // There's no in-app password-change form; this is the standard,
  // safest flow (no need to collect/verify the current password here).
  async sendPasswordReset() {
    const email = (this._current && this._current.email) || (_auth.currentUser && _auth.currentUser.email);
    if (!email) throw new Error('No email on file for this account.');
    try {
      await _auth.sendPasswordResetEmail(email);
    } catch (e) { throw new Error(this._msg(e.code)); }
    return email;
  },

  async getAll() {
    try {
      const snap = await _db.collection('users').get();
      return snap.docs.map(d => d.data());
    } catch(e) { return []; }
  },

  _msg(code) {
    console.warn('[Auth]', code);
    const m = {
      'auth/user-not-found': 'No account found with this email.',
      'auth/wrong-password': 'Incorrect password.',
      'auth/invalid-credential': 'Incorrect email or password.',
      'auth/invalid-login-credentials': 'Incorrect email or password.',
      'auth/email-already-in-use': 'Email already registered.',
      'auth/weak-password': 'Password must be at least 6 characters.',
      'auth/invalid-email': 'Invalid email address.',
      'auth/too-many-requests': 'Too many attempts. Try again later.',
      'auth/network-request-failed': 'Network error. Check your connection.',
      'auth/unsupported-persistence-type': 'Login not supported on file:// — use a local server.',
    };
    return m[code] || ('Error: ' + code);
  }
};
UserAuth.init();

// ================================================================
// PURCHASES — Firestore
// ================================================================
const Purchases = {
  async add(userId, userEmail, product, extra = {}) {
    const now = new Date().toISOString();

    // Proof images are already compressed base64 data URLs (converted in the browser
    // before this call). Store them directly in Firestore — no Firebase Storage involved,
    // which avoids CORS errors on workers.dev origins entirely.
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
// REVIEWS — Firestore collection: reviews
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
      // Log a helpful hint for the most common cause (Firestore security
      // rules) — same pattern as DB.add() above, so this failure is no
      // longer silently swallowed.
      if (e.code === 'permission-denied' || (e.message && e.message.includes('Missing or insufficient permissions'))) {
        console.error('[DIGITCH] Review delete BLOCKED by Firestore security rules. The admin panel signs in with Firebase Auth as ADMIN_EMAIL (see Auth.login above) — make sure your rules allow "delete" on /reviews/{id} when request.auth.token.email == "<your ADMIN_EMAIL>", not by removing the request.auth requirement entirely (that would let anyone on the internet delete reviews).');
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
// ADMIN AUTH — real Firebase Authentication
// ================================================================
// Admin sign-in used to be a plaintext password compared in this file
// (which every visitor downloads, since firebase.js also loads on the
// public storefront) plus a separate static "admin API key" sent to
// the Worker. Both were effectively public — view-source gave anyone
// the password AND the key needed to call the admin-only upload/delete
// routes directly, without ever touching /admin.html.
//
// Admin login is now a real Firebase Auth account. The password is
// never stored here or checked client-side — Firebase verifies it
// server-side and hands back a signed ID token, which is what actually
// protects the Worker's admin routes (see requireAdminAuth in
// worker.js). ADMIN_EMAIL below is not a secret (an email address
// isn't sensitive on its own); it just tells this file which signed-in
// account counts as "the admin."
//
// One-time setup:
//   1. Firebase console → Authentication → Users → Add user
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
      // Surface the real Firebase error code/message instead of silently
      // returning false — "wrong password" was being shown for every
      // possible failure (wrong password, no such user, disabled account,
      // rate-limited, bad API key, etc), which makes real problems
      // impossible to diagnose. See console for e.code / e.message.
      console.error('[Auth.login] Firebase sign-in failed:', e.code, e.message);
      const err = new Error(e.message || 'Sign-in failed');
      err.code = e.code || 'auth/unknown-error';
      throw err;
    }
  },
  logout() { _auth.signOut(); },
  // ID token to send as `Authorization: Bearer <token>` on admin-only
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
// a wrong password is rejected by Firebase's own servers before this site
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
// Listing reads the `users` collection directly (same as UserAuth.getAll,
// kept separate here so this section is self-contained for the admin UI).
// Deleting requires the Worker: removing a Firebase Auth account can't be
// done from the client SDK for anyone but the account itself, so the
// Worker does it server-side with the service-account credentials (see
// POST /api/delete-user in worker.js), same Bearer-token pattern as
// Storage.uploadFile/deleteFile below.
const AdminUsers = {
  async list() {
    // Same fix as the earlier signup bug: reading the whole 'users'
    // collection from the client SDK is a "list" query, which needs a
    // separate Firestore rules permission from "get" (read one doc by
    // ID) — most rule setups only grant the latter, so this came back
    // empty (or permission-denied) no matter how many users actually
    // existed. Routed through the Worker's service account instead,
    // which bypasses client Firestore rules entirely.
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
// DB — Firestore for products / categories / orders
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
    // 2. Fetch from Firestore in background, update if changed.
    // Use a bounded query where possible instead of pulling the whole
    // collection — this is the single biggest lever for keeping page loads
    // fast as products/orders accumulate over time.
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
      // Common failure mode here: Firestore complains it needs a composite
      // index for orderBy+limit on a collection that doesn't have one yet.
      // If that happens, click the link Firestore prints in the browser
      // console to auto-create the index, or set this collection's limit
      // to null above until you do.
      console.error(`DB._load(${col}) failed (check console for a Firestore index link if this mentions an index):`, e);
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
  // Whether a collection has actually been loaded at least once (from cache
  // or Firestore). Lets the UI tell "still loading" apart from "loaded, and
  // there's genuinely nothing here" — getAll() alone can't, since it returns
  // [] in both cases.
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
      // Log a helpful hint for the most common cause (Firestore security rules)
      if (e.code === 'permission-denied' || (e.message && e.message.includes('Missing or insufficient permissions'))) {
        console.error('[DIGITCH] Firestore write BLOCKED by security rules. Go to Firebase Console → Firestore → Rules and set: allow read, write: if true; (for testing) or proper auth rules.');
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
  // it never ends up in every visitor's Firestore read or the
  // dz_fc_products localStorage cache — only the admin panel fetches it,
  // one product at a time, when actually opening that product to edit it.
  // Firestore security rules should restrict read/write on
  // products/{id}/private/{doc} to the admin, same as other admin-only
  // writes in this file.
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
// Always goes through the Worker (never a direct Firestore read), so
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
// SETTINGS — Firestore doc: settings/store
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
    // Fetch fresh from Firestore in background
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
    // Previously an empty/invalid s.primary (or a stray value from a shared
    // Firestore doc) would still get written to --accent, overriding the
    // shipped default green. Now we validate first and simply skip applying
    // anything when there's nothing legitimate to apply.
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

    // Only swap the navbar logo when an explicit, non-empty logo URL is
    // configured. Before, a null/blank logo value (the default, and also
    // what a bad or shared settings doc can contain) would blank out and
    // HIDE the static /logo.png already sitting in the HTML. Now, with no
    // valid logo configured, we simply leave the existing markup alone.
    const _theme = document.documentElement.getAttribute('data-theme') || 'light';
    // In dark theme, only ever use s.logoDark. Previously this fell back to
    // s.logoLight/s.logo when logoDark wasn't set, which meant a store that
    // only configured one generic logo would keep showing the light logo
    // (with its light-colored background box) on the dark navbar instead of
    // falling through to the dark-optimized default asset below.
    const _logoRaw = _theme === 'dark' ? (s.logoDark || null) : (s.logoLight || s.logo || null);
    const _logo = (typeof _logoRaw === 'string' && _logoRaw.trim()) ? _logoRaw.trim() : null;
    if (_logo) {
      document.querySelectorAll('.nav-logo-img').forEach(el => { el.src = _logo; el.style.display = 'block'; });
    } else {
      // No custom logo configured — fall back to the theme-appropriate
      // default repo asset (logob.png is the dark-theme-optimized version).
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
  // `add()` freezes the product's price into the cart line at the moment
  // it's added (localStorage cache). If the seller edits the price in
  // admin afterwards — e.g. adding the 40 DA SlickPay fee on top — any
  // cart already holding that product silently keeps charging the OLD
  // price forever, since nothing ever re-reads it. That's the exact bug
  // behind "product page says 400, cart still says 360": the cart line
  // was cached before the price was updated. This resyncs every cart
  // line's price (and image) against the live catalog so the cart can
  // never drift from what the storefront and checkout actually charge.
  // `products` is the current DB.getAll('products') array. Returns true
  // if anything changed (caller can re-render).
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
        // Match the same "first group decides price" logic used on the
        // product detail page (see computeActiveVariant()): the variant
        // label may be a joined "GroupA / GroupB" string, but only the
        // first group's item price is actually charged.
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
// 'cart:update' dispatch from _save() above). Without this, adding/removing
// an item in one tab (e.g. a product page) wouldn't update the cart badge
// or the live "in cart" heartbeat in another open tab
// until that other tab was manually refreshed.
window.addEventListener('storage', (e) => {
  if (e.key === 'dz_cart') { window.dispatchEvent(new Event('cart:update')); }
});

// ================================================================
// WISHLIST SYNC — Firestore (synced per user, fallback to localStorage)
// ================================================================
const WishlistSync = {
  // Save the current wishlist array to Firestore for the logged-in user
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

  // Load the wishlist from Firestore and merge into localStorage
  async load() {
    const user = UserAuth.current();
    if (!user) return;
    try {
      const doc = await _db.collection('users').doc(user.id).get();
      if (doc.exists) {
        const data = doc.data();
        let cloudIds = Array.isArray(data.wishlist) ? data.wishlist : [];
        // Merge with any local ids (e.g. added while logged out)
        let localIds = [];
        try { localIds = JSON.parse(localStorage.getItem('dz_wishlist') || '[]'); } catch {}

        // If the product catalog is already loaded, strip ids for products
        // that no longer exist. Without this, a stale cloud copy (synced
        // before a product was deleted) can resurrect it into localStorage
        // even after the local prune already removed it — this was the
        // race causing the wishlist badge to look "un-fixed".
        if (typeof DB !== 'undefined' && (DB.getAll('products') || []).length) {
          const validIds = new Set(DB.getAll('products').map(p => p.id));
          cloudIds = cloudIds.filter(id => validIds.has(id));
          localIds  = localIds.filter(id => validIds.has(id));
        }

        const merged = [...new Set([...cloudIds, ...localIds])];
        try { localStorage.setItem('dz_wishlist', JSON.stringify(merged)); } catch {}
        window.dispatchEvent(new Event('wishlist:update'));
        // Persist back to Firestore if the set actually changed — either it
        // grew (local-only additions) or shrank (stale/deleted ids pruned).
        const original = Array.isArray(data.wishlist) ? data.wishlist : [];
        const changed = merged.length !== original.length || merged.some(id => !original.includes(id));
        if (changed) await this.save(merged);
      }
    } catch(e) { console.warn('WishlistSync.load:', e); }
  },

  // Clear wishlist from Firestore (called on logout)
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
    // Clear local wishlist when user logs out (privacy)
    try { localStorage.removeItem('dz_wishlist'); } catch {}
    window.dispatchEvent(new Event('wishlist:update'));
  }
});

// ================================================================
// ANALYTICS — Firestore collection: product_events
// Tracks product-detail views and add-to-cart actions. Each is
// deduped once per browser session per product so refreshing or
// re-opening the same product repeatedly doesn't inflate the count —
// the goal is "how many people", not "how many clicks".
// Purchases are already tracked in the 'purchases' collection, so
// admin analytics reads from there directly for the "bought" number.
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

  // Log a product-detail view (once per product per browser session)
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

  // Log an add-to-cart action (once per product per browser session)
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

  // Admin: fetch every event — filtering by date range / product happens
  // client-side (same pattern used elsewhere in this app, e.g. Purchases.getAll).
  async getAllEvents() {
    try {
      const snap = await _db.collection('product_events').get();
      return snap.docs.map(d => ({ ...d.data(), id: d.id }));
    } catch(e) { console.error('Analytics.getAllEvents:', e); return []; }
  },

  // Admin: reset the lifetime "Entered" / "Added to Cart" counters for one
  // product by deleting its product_events docs. This intentionally does
  // NOT touch the 'purchases' collection (those are real orders/deliveries,
  // not just a stat) and does NOT touch the live "Live Now" / "Live In
  // Cart" numbers, since those are real-time presence, not history.
  async resetProduct(productId) {
    if (!productId) return;
    try {
      const snap = await _db.collection('product_events').where('productId', '==', productId).get();
      if (snap.empty) return;
      // Firestore batches cap at 500 writes — chunk just in case a product has a lot of history.
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
// PRESENCE — Firestore collection: presence
// Lightweight "who's online right now" tracker for the storefront.
// Each open tab writes a heartbeat doc every 20s (tagged with the
// product page it's currently viewing, if any). The admin panel
// counts docs whose heartbeat is recent to estimate live visitors —
// no extra backend or websocket needed.
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

  // Call when entering/leaving a product detail page (null = not on one)
  setProduct(productId) { this._productId = productId || null; this._beat(); },

  async _beat() {
    try {
      await _db.collection('presence').doc(this._getSid()).set({
        productId: this._productId || null,
        lastSeen: firebase.firestore.FieldValue.serverTimestamp()
      });
    } catch(e) { /* best-effort — never block the UI on this */ }
  },

  // Start the heartbeat loop. Safe to call once per page load.
  start() {
    if (this._timer) return;
    this._beat();
    this._timer = setInterval(() => this._beat(), 20000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) this._beat(); });
  },

  // Admin: sessions with a heartbeat inside the last `windowSec` seconds
  async getActive(windowSec = 45) {
    try {
      const snap = await _db.collection('presence').get();
      const now = Date.now();
      return snap.docs.map(d => d.data()).filter(x => {
        const t = x.lastSeen && x.lastSeen.toDate ? x.lastSeen.toDate().getTime() : 0;
        return t && (now - t) < windowSec * 1000;
      });
    } catch(e) { console.error('Presence.getActive:', e); return []; }
  }
};

// ================================================================
// CART LIVE — Firestore collection: cart_live
// Tracks, per browser session, which products currently sit in that
// person's cart. Unlike Analytics.logCart (a one-way lifetime counter
// that never goes back down), this is a real-time snapshot: adding a
// product bumps its live count, removing it drops the count right
// back down. Each session writes ONE doc (its full list of product
// ids currently in cart) with a heartbeat, same pattern as Presence —
// so a closed tab/browser crash just ages out of the window instead
// of needing explicit cleanup.
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
        lastSeen: firebase.firestore.FieldValue.serverTimestamp()
      });
    } catch(e) { console.warn('CartLive._beat (this usually means the "cart_live" collection needs a Firestore security rule):', e.message || e); }
  },

  // Start the heartbeat loop + react instantly to cart changes. Safe to call once per page load.
  start() {
    if (this._timer) return;
    this._beat();
    this._timer = setInterval(() => this._beat(), 20000);
    window.addEventListener('cart:update', () => this._beat());
    document.addEventListener('visibilitychange', () => { if (!document.hidden) this._beat(); });
  },

  // Admin: live "in cart right now" count per productId, sessions with a
  // heartbeat inside the last `windowSec` seconds only.
  async getActiveCounts(windowSec = 45) {
    try {
      const snap = await _db.collection('cart_live').get();
      const now = Date.now();
      const counts = {};
      snap.docs.forEach(d => {
        const x = d.data();
        const t = x.lastSeen && x.lastSeen.toDate ? x.lastSeen.toDate().getTime() : 0;
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
// INIT — load all data from Firestore on startup
// ================================================================
async function initFirestoreData() {
  // The storefront (index.html) never reads the `orders` collection — only
  // the admin panel does. `orders` also has no _LOAD_LIMITS cap (it can grow
  // to be the largest collection in the whole app), so pulling it into every
  // customer's page load was adding a large, completely unused payload to
  // every single storefront visit. Only fetch it where it's actually used.
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

  // Step 3: refresh from Firestore in background (DB._load handles update)
  Settings.load().then(() => window.dispatchEvent(new Event('settings:update'))).catch(()=>{});
  Promise.all(COLS.map(col => DB._load(col))).then(() => {
    if (DB._cache.products) DB._cache.products.sort((a,b) => new Date(b.createdAt||0) - new Date(a.createdAt||0));
  }).catch(e => console.error('Firestore refresh:', e));
}

// Run immediately (synchronous cache part runs before first paint)
initFirestoreData().catch(e => console.error('initFirestoreData:', e));