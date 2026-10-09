// Caches only the static shell. Same-origin GETs for shell files only; Firebase/Auth/Firestore (cross-origin) are never cached.
const V="mavora-v2",SHELL=["/","/offline.html","/logo.svg","/manifest.webmanifest","/icons/icon-192.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(SHELL)));self.skipWaiting()});
self.addEventListener("activate",e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==V).map(x=>caches.delete(x)))).then(()=>clients.claim())));
self.addEventListener("fetch",e=>{const r=e.request,u=new URL(r.url);if(r.method!=="GET"||u.origin!==location.origin)return;
if(r.mode==="navigate"){e.respondWith(fetch(r).catch(()=>caches.match("/offline.html")));return}
if(SHELL.includes(u.pathname)||u.pathname.startsWith("/icons/"))e.respondWith(caches.match(r).then(m=>m||fetch(r)))});
