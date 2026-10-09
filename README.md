# Mavora, Phase 1 + 2 (real build)

Static site for Cloudflare Pages + your Mavora Firebase project.

## Setup
1. Firebase Console: create project, enable **Authentication** (Email/Password + Google) and **Firestore**.
2. Add a Web app, paste its config into `firebase-config.js`.
3. Auth > Settings > Authorized domains: add your Pages domain (and `localhost`).
4. Deploy rules/indexes: `firebase deploy --only firestore` (uses `firestore.rules`, `firestore.indexes.json`).
5. Push this folder to Cloudflare Pages (no build step; output dir `/`). HTTPS is required for PWA install.
6. First admin: set the custom claim `admin: true` on your uid with the Firebase Admin SDK (never from the browser).

## Built now
Email + Google sign-in, password reset, buyer profile, seller onboarding (shop / no-shop pickup location, private data split from public profile), Light/Dark/System theme saved to your Firestore profile, PWA (manifest, icons, service worker, offline page, install button), CBM footer hidden in installed app, Firestore rules.

## Not built yet (next phases)
Listings, search/filters, cart/orders, service requests, reviews, reports, verification (Dojah), plans, promotions, admin dashboard, integrations centre + Cloudflare Worker for secrets, Rate Mavora feedback. Nothing here pretends to do these.

## Notes
- Service worker caches only the static shell; account data, orders and Firebase traffic are never cached.
- Cloudinary uploads and all provider keys must go through a Worker (Phase 7), not this frontend.
- Bump `V` in `sw.js` on each release to push updates.

## Phase 2 additions (setup)
1. **Republish rules**: Firebase Console > Firestore > Rules > paste the new `firestore.rules` > Publish.
2. **Indexes**: the first time the homepage loads, the browser console may print a link for a missing index (products/services by status + date). Click it, press Create index, wait ~1-2 minutes. (`firestore.indexes.json` lists both.)
3. **Photos (optional)**: create a free Cloudinary account, then Settings > Upload > Add upload preset > set Signing mode to **Unsigned**. Add to the bottom of `firebase-config.js`:
   `export const cloudinary = { cloudName: "YOUR_CLOUD_NAME", uploadPreset: "YOUR_PRESET" };`
   (No secret key is used in the browser. Without this, listings publish without photos.)
4. **Support email (optional)**: add `export const supportEmail = "you@example.com";` to `firebase-config.js`.
5. Re-upload the folder to Cloudflare Pages, then hard refresh (Ctrl+Shift+R).

Built in Phase 2: seller dashboard, product and service create/edit/pause/delete, categories, global search with filters (mobile drawer), item and seller pages, profile view/edit, help page, icon navigation.
Search currently filters the newest 100 listings in the browser; server-side search comes when listings grow.
