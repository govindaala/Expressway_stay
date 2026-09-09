// Expressway Stay - Production Worker (All-in-One Engine)
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const db = env.DB || env.db; // आपकी बाइंडिंग दोनों सपोर्ट करेगी
    const SECRET_KEY = "exp-stay-super-secret-key-2026";

    // Helper: Simple Sign / Verify to prevent link tampering (IDOR Safe)
    async function signPayload(data) {
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw", enc.encode(SECRET_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      );
      const str = JSON.stringify(data);
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode(str));
      const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
      return btoa(str) + "." + sigHex;
    }

    async function verifyPayload(token) {
      if (!token || !token.includes('.')) return null;
      const [b64, sigHex] = token.split('.');
      try {
        const str = atob(b64);
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey(
          "raw", enc.encode(SECRET_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
        );
        const matchSig = new Uint8Array(sigHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const valid = await crypto.subtle.verify("HMAC", key, matchSig, enc.encode(str));
        return valid ? JSON.parse(str) : null;
      } catch (e) {
        return null;
      }
    }

    // CORS Headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // ==========================================
    // 1. API: PUBLIC EXPLORE (होटल, रूम, रेस्टोरेंट)
    // ==========================================
    if (url.pathname === "/api/explore") {
      try {
        const hotelsRes = await db.prepare(
          `SELECT h.*, l.name as location_name 
           FROM hotels h 
           LEFT JOIN locations l ON h.location_id = l.id 
           WHERE h.is_active = 1`
        ).all();

        const roomsRes = await db.prepare(`SELECT * FROM room_types`).all();
        const restRes = await db.prepare(`SELECT * FROM restaurants WHERE is_active = 1`).all();
        const locationsRes = await db.prepare(`SELECT * FROM locations WHERE is_active = 1`).all();

        // ग्रुप रूम डेटा अंदर होटल्स
        const hotels = (hotelsRes.results || []).map(hotel => {
          const rooms = (roomsRes.results || []).filter(r => r.hotel_id === hotel.id);
          const totalAvail = rooms.reduce((acc, r) => acc + (r.available_rooms || 0), 0);
          return { ...hotel, rooms, total_available: totalAvail };
        });

        return new Response(JSON.stringify({
          success: true,
          locations: locationsRes.results || [],
          hotels,
          restaurants: restRes.results || []
        }), {
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500, headers: corsHeaders
        });
      }
    }

    // ==========================================
    // 2. API: AUTH LOGIN (होटल मालिक और एडमिन)
    // ==========================================
    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const { username, password } = await request.json();

        // सुपर एडमिन बैकडोर (सीक्रेट मास्टर लॉगिन)
        if (username === "admin" && password === "admin99") {
          const token = await signPayload({ role: "admin", username: "admin" });
          return new Response(JSON.stringify({ success: true, token, role: "admin" }), {
            headers: { "Content-Type": "application/json", ...corsHeaders }
          });
        }

        // होटल मालिक लॉगिन डेटाबेस से
        const user = await db.prepare(
          `SELECT * FROM users WHERE username = ? AND password_hash = ? AND is_active = 1`
        ).bind(username, password).first();

        if (!user) {
          return new Response(JSON.stringify({ success: false, error: "अमान्य मोबाइल नंबर या पासवर्ड" }), {
            status: 401, headers: corsHeaders
          });
        }

        const hotel = await db.prepare(`SELECT * FROM hotels WHERE id = ?`).bind(user.hotel_id).first();
        const token = await signPayload({
          user_id: user.id,
          hotel_id: user.hotel_id,
          role: user.role
        });

        return new Response(JSON.stringify({
          success: true,
          token,
          role: user.role,
          hotel
        }), {
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // ==========================================
    // 3. API: OWNER - GET HIS ROOMS (IDOR सुरक्षित)
    // ==========================================
    if (url.pathname === "/api/owner/rooms") {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifyPayload(token);

      if (!session || (session.role !== "hotel_owner" && session.role !== "admin")) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
      }

      const hotel = await db.prepare(`SELECT * FROM hotels WHERE id = ?`).bind(session.hotel_id).first();
      const rooms = await db.prepare(`SELECT * FROM room_types WHERE hotel_id = ?`).bind(session.hotel_id).all();

      return new Response(JSON.stringify({ success: true, hotel, rooms: rooms.results || [] }), {
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    // ==========================================
    // 4. API: OWNER - UPDATE ROOM COUNT (सुरक्षित)
    // ==========================================
    if (url.pathname === "/api/owner/update-room" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifyPayload(token);

      if (!session || session.role !== "hotel_owner") {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
      }

      const { room_id, available_rooms } = await request.json();

      // सख्त जांच: क्या यह कमरा इसी मालिक के होटल का है?
      const checkRoom = await db.prepare(
        `SELECT id FROM room_types WHERE id = ? AND hotel_id = ?`
      ).bind(room_id, session.hotel_id).first();

      if (!checkRoom) {
        return new Response(JSON.stringify({ error: "सुरक्षा उल्लंघन: आप केवल अपने होटल का डेटा बदल सकते हैं" }), {
          status: 403, headers: corsHeaders
        });
      }

      await db.prepare(
        `UPDATE room_types SET available_rooms = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
      ).bind(Number(available_rooms), room_id).run();

      await db.prepare(
        `UPDATE hotels SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`
      ).bind(session.hotel_id).run();

      return new Response(JSON.stringify({ success: true, message: "उपलब्धता सुरक्षित रूप से अपडेट हो गई" }), {
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    // ==========================================
    // 5. API: ADMIN - CREATE OWNER CREDENTIAL
    // ==========================================
    if (url.pathname === "/api/admin/create-owner" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifyPayload(token);

      if (!session || session.role !== "admin") {
        return new Response(JSON.stringify({ error: "केवल एडमिन को अनुमति है" }), { status: 403, headers: corsHeaders });
      }

      const { hotel_id, mobile, password } = await request.json();
      const userId = "usr-" + Date.now();

      await db.prepare(
        `INSERT INTO users (id, hotel_id, username, password_hash, role) VALUES (?, ?, ?, ?, 'hotel_owner')`
      ).bind(userId, hotel_id, mobile, password).run();

      return new Response(JSON.stringify({ success: true, message: "मालिक का लॉगिन तैयार हो गया!" }), {
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    // ==========================================
    // 6. FRONTEND (पूरी मोबाइल-फर्स्ट वेब ऐप्लिकेशन)
    // ==========================================
    return new Response(renderHTML(), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
};

// HTML & Frontend Engine
function renderHTML() {
  return `<!DOCTYPE html>
<html lang="hi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Expressway Stay | Delhi-Mumbai Expressway</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Plus Jakarta Sans', sans-serif; -webkit-tap-highlight-color: transparent; }
    [x-cloak] { display: none !important; }
  </style>
</head>
<body class="bg-slate-100 text-slate-900 pb-20" x-data="app()" x-init="init()" x-cloak>

  <!-- शीर्ष रोल स्विच बार (केवल आपके लिए आसान टेस्टिंग हेतु) -->
  <header class="bg-slate-950 text-white px-4 py-2.5 flex items-center justify-between text-xs sticky top-0 z-50 border-b border-slate-800">
    <div class="flex items-center gap-1.5 font-bold">
      <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
      <span>LIVE EXPRESSWAY STAY</span>
    </div>
    <div class="flex bg-slate-800 p-1 rounded-lg gap-1 font-semibold">
      <button @click="view = 'traveller'" :class="view === 'traveller' ? 'bg-amber-500 text-black' : 'text-slate-300'" class="px-2 py-1 rounded">यात्री</button>
      <button @click="view = 'owner'" :class="view === 'owner' ? 'bg-indigo-600 text-white' : 'text-slate-300'" class="px-2 py-1 rounded">होटल मालिक</button>
      <button @click="view = 'admin'" :class="view === 'admin' ? 'bg-rose-600 text-white' : 'text-slate-300'" class="px-2 py-1 rounded">एडमिन</button>
    </div>
  </header>

  <!-- ============================================== -->
  <!-- 1. TRAVELLER VIEW (सार्वजनिक यात्री - NO LOGIN) -->
  <!-- ============================================== -->
  <main x-show="view === 'traveller'" class="max-w-md mx-auto p-4">
    <!-- बैनर -->
    <div class="bg-gradient-to-r from-amber-500 to-amber-600 rounded-2xl p-4 text-slate-950 shadow-md mb-4">
      <h1 class="text-xl font-extrabold flex items-center gap-2">
        <span>🏨</span> Expressway Stay
      </h1>
      <p class="text-xs font-semibold text-amber-950 mt-1">
        Delhi–Mumbai Expressway के आसपास तुरंत कमरे व ढाबा खोजें
      </p>
      
      <!-- केटेगरी टॉगल -->
      <div class="flex gap-2 mt-4">
        <button @click="tab = 'hotels'" :class="tab === 'hotels' ? 'bg-slate-950 text-white' : 'bg-amber-400 text-slate-900'" class="flex-1 py-2 rounded-xl font-bold text-xs shadow-sm transition">
          🏨 होटल्स (लाइव कमरे)
        </button>
        <button @click="tab = 'restaurants'" :class="tab === 'restaurants' ? 'bg-slate-950 text-white' : 'bg-amber-400 text-slate-900'" class="flex-1 py-2 rounded-xl font-bold text-xs shadow-sm transition">
          🍴 रेस्टोरेंट / ढाबा
        </button>
      </div>
    </div>

    <!-- लोडिंग स्थिति -->
    <div x-show="loading" class="text-center py-10">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-4 border-amber-500 border-t-transparent"></div>
      <p class="text-xs font-bold text-slate-500 mt-2">हाईवे डेटा लोड हो रहा है...</p>
    </div>

    <!-- HOTELS LIST -->
    <div x-show="!loading && tab === 'hotels'" class="space-y-4">
      <template x-for="hotel in hotels" :key="hotel.id">
        <div class="bg-white rounded-2xl p-4 shadow-sm border border-slate-200">
          <div class="flex justify-between items-start gap-2">
            <div>
              <div class="flex items-center gap-1.5 flex-wrap">
                <h3 class="font-extrabold text-base text-slate-900" x-text="hotel.name"></h3>
                <span x-show="hotel.is_verified" class="bg-blue-100 text-blue-700 text-[10px] font-bold px-1.5 py-0.5 rounded">✓ Verified</span>
              </div>
              <p class="text-xs text-slate-500 mt-0.5" x-text="'📍 ' + hotel.address"></p>
            </div>
            <div class="text-right whitespace-nowrap">
              <span class="text-[10px] text-slate-400 block font-medium">शुरुआती किराया</span>
              <span class="text-base font-extrabold text-emerald-600" x-text="'₹' + hotel.starting_price"></span>
            </div>
          </div>

          <!-- लाइव रूम स्थिति कार्ड -->
          <div class="mt-3 p-3 rounded-xl border flex items-center justify-between"
               :class="hotel.total_available > 0 ? 'bg-emerald-50 border-emerald-200' : 'bg-rose-50 border-rose-200'">
            <div class="flex items-center gap-2">
              <span class="w-3 h-3 rounded-full" :class="hotel.total_available > 0 ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'"></span>
              <span class="text-xs font-extrabold" 
                    :class="hotel.total_available > 0 ? 'text-emerald-900' : 'text-rose-900'"
                    x-text="hotel.total_available > 0 ? '🟢 ' + hotel.total_available + ' कमरे तुरंत उपलब्ध' : '🔴 अभी सभी कमरे भरे हैं'">
              </span>
            </div>
            <span class="text-[10px] font-semibold text-slate-400">लाइव अपडेट</span>
          </div>

          <!-- रूम के प्रकार -->
          <div class="mt-2 text-xs text-slate-600 space-y-1">
            <template x-for="room in hotel.rooms" :key="room.id">
              <div class="flex justify-between py-0.5 border-b border-dashed border-slate-100">
                <span x-text="room.name"></span>
                <span class="font-bold" :class="room.available_rooms > 0 ? 'text-emerald-700' : 'text-slate-400'"
                      x-text="room.available_rooms + ' उपलब्ध (₹' + room.price_inr + ')'"></span>
              </div>
            </template>
          </div>

          <!-- त्वरित कॉल और व्हाट्सएप बटन -->
          <div class="grid grid-cols-3 gap-2 mt-4 pt-2 border-t border-slate-100">
            <a :href="'tel:' + hotel.phone" class="flex items-center justify-center gap-1 bg-slate-900 active:bg-black text-white text-xs font-bold py-2.5 rounded-xl">
              📞 Call
            </a>
            <a :href="'https://wa.me/91' + hotel.whatsapp + '?text=नमस्ते, मुझे एक्सप्रेसवे स्टे पर आपका होटल दिखा। क्या कमरा उपलब्ध है?'" target="_blank" class="flex items-center justify-center gap-1 bg-emerald-600 active:bg-emerald-700 text-white text-xs font-bold py-2.5 rounded-xl">
              💬 WhatsApp
            </a>
            <a :href="'https://maps.google.com/?q=' + encodeURIComponent(hotel.name + ' ' + hotel.address)" target="_blank" class="flex items-center justify-center gap-1 bg-blue-600 active:bg-blue-700 text-white text-xs font-bold py-2.5 rounded-xl">
              📍 Map
            </a>
          </div>
        </div>
      </template>
    </div>

    <!-- RESTAURANTS LIST -->
    <div x-show="!loading && tab === 'restaurants'" class="space-y-4">
      <template x-for="rest in restaurants" :key="rest.id">
        <div class="bg-white rounded-2xl p-4 shadow-sm border border-slate-200">
          <div class="flex justify-between items-start">
            <div>
              <h3 class="font-extrabold text-base text-slate-900" x-text="rest.name"></h3>
              <p class="text-xs text-slate-500 mt-0.5" x-text="'📍 ' + rest.address"></p>
            </div>
            <span class="bg-amber-100 text-amber-900 text-[10px] font-bold px-2 py-0.5 rounded-full" x-text="rest.food_type"></span>
          </div>

          <div class="grid grid-cols-2 gap-2 mt-4">
            <a :href="'tel:' + rest.phone" class="flex items-center justify-center gap-1 bg-slate-900 text-white text-xs font-bold py-2.5 rounded-xl">
              📞 Call Dhaba
            </a>
            <a :href="'https://maps.google.com/?q=' + encodeURIComponent(rest.name + ' ' + rest.address)" target="_blank" class="flex items-center justify-center gap-1 bg-blue-600 text-white text-xs font-bold py-2.5 rounded-xl">
              📍 Get Route
            </a>
          </div>
        </div>
      </template>
    </div>
  </main>

  <!-- ============================================== -->
  <!-- 2. OWNER PORTAL (होटल मालिक डैशबोर्ड) -->
  <!-- ============================================== -->
  <section x-show="view === 'owner'" class="max-w-md mx-auto p-4">
    <!-- अगर लॉगिन नहीं है -->
    <div x-show="!ownerToken" class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
      <div class="text-center mb-6">
        <div class="w-12 h-12 bg-indigo-100 text-indigo-600 rounded-full flex items-center justify-center text-xl mx-auto mb-2 font-black">🏨</div>
        <h2 class="text-lg font-extrabold">होटल मालिक लॉगिन</h2>
        <p class="text-xs text-slate-500">एडमिन द्वारा दिया गया मोबाइल नंबर और पासवर्ड दर्ज करें</p>
      </div>

      <div class="space-y-3">
        <div>
          <label class="text-xs font-bold text-slate-700 block mb-1">मोबाइल नंबर</label>
          <input type="text" x-model="ownerPhone" placeholder="9829012345" class="w-full border rounded-xl p-2.5 text-sm font-semibold focus:ring-2 focus:ring-indigo-500 outline-none">
        </div>
        <div>
          <label class="text-xs font-bold text-slate-700 block mb-1">पासवर्ड</label>
          <input type="password" x-model="ownerPass" placeholder="••••••••" class="w-full border rounded-xl p-2.5 text-sm font-semibold focus:ring-2 focus:ring-indigo-500 outline-none">
        </div>
        <p x-show="loginError" class="text-xs font-bold text-rose-600" x-text="loginError"></p>
        <button @click="loginOwner()" class="w-full bg-indigo-600 text-white font-bold py-3 rounded-xl shadow text-sm active:scale-95 transition">
          लॉगिन करें (Dashboard)
        </button>
      </div>
    </div>

    <!-- अगर मालिक लॉगिन है -->
    <div x-show="ownerToken" class="space-y-4">
      <div class="bg-slate-900 text-white p-4 rounded-2xl flex justify-between items-center shadow-sm">
        <div>
          <p class="text-[10px] text-indigo-300 font-bold uppercase">आपका होटल</p>
          <h2 class="text-base font-extrabold" x-text="myHotel.name"></h2>
        </div>
        <button @click="logoutOwner()" class="text-xs bg-slate-800 text-slate-300 px-2.5 py-1.5 rounded-lg border border-slate-700 font-semibold">
          लॉगआउट
        </button>
      </div>

      <h3 class="font-extrabold text-sm text-slate-800">आज की खाली कमरा संख्या (Tap to Update)</h3>

      <template x-for="r in myRooms" :key="r.id">
        <div class="bg-white p-4 rounded-2xl border border-slate-200 shadow-sm flex items-center justify-between">
          <div>
            <h4 class="font-bold text-sm text-slate-900" x-text="r.name"></h4>
            <p class="text-xs text-slate-400" x-text="'कुल कमरे: ' + r.total_rooms + ' | ₹' + r.price_inr"></p>
          </div>

          <!-- + / - बटन्स -->
          <div class="flex items-center gap-3">
            <button @click="changeRoomCount(r, -1)" class="w-10 h-10 rounded-xl bg-slate-100 active:bg-slate-200 text-slate-800 font-black text-xl flex items-center justify-center">−</button>
            <span class="text-xl font-black w-6 text-center text-indigo-600" x-text="r.available_rooms"></span>
            <button @click="changeRoomCount(r, 1)" class="w-10 h-10 rounded-xl bg-indigo-50 active:bg-indigo-100 text-indigo-700 font-black text-xl flex items-center justify-center">+</button>
          </div>
        </div>
      </template>

      <div class="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs rounded-xl font-semibold text-center">
        ✓ बटन दबाते ही डेटाबेस में ऑटो-सेव हो जाता है
      </div>
    </div>
  </section>

  <!-- ============================================== -->
  <!-- 3. ADMIN PORTAL (सुपर एडमिन कंट्रोल) -->
  <!-- ============================================== -->
  <section x-show="view === 'admin'" class="max-w-md mx-auto p-4">
    <!-- एडमिन पिन -->
    <div x-show="!adminToken" class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
      <h2 class="text-base font-extrabold text-slate-900 mb-1">सुपर एडमिन एक्सेस</h2>
      <p class="text-xs text-slate-500 mb-4">मास्टर पासवर्ड दर्ज करें (डिफ़ॉल्ट: admin99)</p>
      
      <input type="password" x-model="adminPass" placeholder="Master Password" class="w-full border rounded-xl p-2.5 text-sm mb-3">
      <button @click="loginAdmin()" class="w-full bg-rose-600 text-white font-bold py-2.5 rounded-xl text-sm">
        एडमिन पैनल खोलें
      </button>
    </div>

    <!-- एडमिन अनलॉक -->
    <div x-show="adminToken" class="space-y-4">
      <div class="bg-rose-950 text-white p-4 rounded-2xl flex justify-between items-center">
        <div>
          <span class="text-[10px] text-rose-300 font-bold">MASTER ADMIN</span>
          <h2 class="text-sm font-black">Expressway Control Center</h2>
        </div>
        <button @click="adminToken = ''" class="text-xs bg-rose-900 px-2 py-1 rounded">लॉगआउट</button>
      </div>

      <!-- होटल मालिक आईडी बनाएं -->
      <div class="bg-white p-4 rounded-2xl border border-slate-200 shadow-sm space-y-3">
        <h3 class="font-extrabold text-sm text-slate-900">होटल मालिक का लॉगिन जनरेट करें</h3>
        
        <div>
          <label class="text-[11px] font-bold text-slate-600">होटल चुनें</label>
          <select x-model="newOwner.hotel_id" class="w-full border rounded-xl p-2 text-xs font-semibold mt-1">
            <template x-for="h in hotels" :key="h.id">
              <option :value="h.id" x-text="h.name"></option>
            </template>
          </select>
        </div>

        <div>
          <label class="text-[11px] font-bold text-slate-600">मालिक का मोबाइल नंबर</label>
          <input type="text" x-model="newOwner.mobile" placeholder="9829012345" class="w-full border rounded-xl p-2 text-xs mt-1">
        </div>

        <div>
          <label class="text-[11px] font-bold text-slate-600">अस्थायी पासवर्ड</label>
          <input type="text" x-model="newOwner.password" placeholder="Dausa@123" class="w-full border rounded-xl p-2 text-xs mt-1">
        </div>

        <button @click="createOwnerAccount()" class="w-full bg-slate-900 text-white text-xs font-bold py-2.5 rounded-xl">
          मालिक अकाउंट बनाएं
        </button>
      </div>
    </div>
  </section>

  <!-- Alpine Application Script -->
  <script>
    function app() {
      return {
        view: 'traveller',
        tab: 'hotels',
        loading: true,
        hotels: [],
        restaurants: [],
        
        // Owner Data
        ownerPhone: '',
        ownerPass: '',
        ownerToken: '',
        loginError: '',
        myHotel: {},
        myRooms: [],

        // Admin Data
        adminPass: '',
        adminToken: '',
        newOwner: { hotel_id: 'ht-1', mobile: '', password: '' },

        async init() {
          await this.fetchData();
        },

        async fetchData() {
          this.loading = true;
          try {
            const res = await fetch('/api/explore');
            const data = await res.json();
            if (data.success) {
              this.hotels = data.hotels;
              this.restaurants = data.restaurants;
            }
          } catch (e) {
            console.error(e);
          } finally {
            this.loading = false;
          }
        },

        async loginOwner() {
          this.loginError = '';
          const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: this.ownerPhone, password: this.ownerPass })
          });
          const data = await res.json();
          if (data.success && data.role === 'hotel_owner') {
            this.ownerToken = data.token;
            this.loadOwnerDashboard();
          } else {
            this.loginError = data.error || 'लॉगिन विफल';
          }
        },

        async loadOwnerDashboard() {
          const res = await fetch('/api/owner/rooms', {
            headers: { 'Authorization': 'Bearer ' + this.ownerToken }
          });
          const data = await res.json();
          if (data.success) {
            this.myHotel = data.hotel;
            this.myRooms = data.rooms;
          }
        },

        async changeRoomCount(room, delta) {
          const nextVal = room.available_rooms + delta;
          if (nextVal < 0 || nextVal > room.total_rooms) return;
          room.available_rooms = nextVal;

          await fetch('/api/owner/update-room', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'Authorization': 'Bearer ' + this.ownerToken
            },
            body: JSON.stringify({ room_id: room.id, available_rooms: nextVal })
          });

          // बैकग्राउंड में पब्लिक डेटा भी रीफ्रेश
          this.fetchData();
        },

        logoutOwner() {
          this.ownerToken = '';
          this.ownerPhone = '';
          this.ownerPass = '';
        },

        async loginAdmin() {
          const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: 'admin', password: this.adminPass })
          });
          const data = await res.json();
          if (data.success && data.role === 'admin') {
            this.adminToken = data.token;
          } else {
            alert('गलत मास्टर पासवर्ड');
          }
        },

        async createOwnerAccount() {
          if (!this.newOwner.mobile || !this.newOwner.password) {
            alert('कृपया मोबाइल नंबर और पासवर्ड भरें');
            return;
          }
          const res = await fetch('/api/admin/create-owner', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'Authorization': 'Bearer ' + this.adminToken
            },
            body: JSON.stringify(this.newOwner)
          });
          const data = await res.json();
          if (data.success) {
            alert('सफलता: मालिक का लॉगिन तैयार हो गया! आप यह आईडी-पासवर्ड मालिक को WhatsApp पर भेज सकते हैं।');
            this.newOwner.mobile = '';
            this.newOwner.password = '';
          } else {
            alert('त्रुटि: ' + data.error);
          }
        }
      };
    }
  </script>
</body>
</html>`;
}
