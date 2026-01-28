/* ==========================
   1. TOURNAMENT DETAILS POPUP
========================== */
let currentTournamentId = null;

function openTournamentDetails(
    a, b, c, d, e, f, g, h, i, j, k = "", l = "", m = ""
) {
    document.getElementById("tdGame").innerText = arguments[10] || "BGMI";
document.getElementById("tdMap").innerText = arguments[11] || "-";
document.getElementById("tdMode").innerText = arguments[12] || "-";
document.getElementById("tdType").innerText = arguments[13] || "-";

    const box = document.getElementById("tournamentDetailsBox");
    if (!box) return;

    box.style.display = "flex";
    document.body.classList.add("no-scroll");

    let data = {};

    // 🔹 CASE 1: full parameters passed
    if (typeof a === "number" && typeof b === "string") {
        data = {
            id: a,
            name: b,
            desc: c,
            location: d,
            date: e,
            entry: f,
            prize: g,
            current: h,
            max: i,
            image: j,
            rules: k,
            roomid: l,
            roompass: m,
            joined: "no"
        };
    }

    // 🔹 CASE 2: object passed (t or data)
    else if (typeof a === "object") {
        data = {
            id: a.id || a.tid,
            name: a.name || "",
            desc: a.desc || "",
            location: a.location || "",
            date: a.date || "",
            entry: a.entry || "",
            prize: a.prize || "",
            current: a.current || 0,
            max: a.max || 0,
            image: a.image || "",
            rules: a.rules || "",
            roomid: a.roomid || "",
            roompass: a.roompass || "",
            joined: a.joined || a.joined_status || "no"
        };
    }

    // 🔹 CASE 3: only ID passed
    else {
        data = { id: a };
    }

    currentTournamentId = data.id;

    // ===== BASIC DETAILS =====
    const set = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.innerText = val || "";
    };

    const banner = document.getElementById("tdBanner");
    if (banner && data.image) banner.src = data.image;

    set("tdName", data.name);
    set("tdDesc", data.desc);
    set("tdLocation", data.location);
    set("tdEntry", data.entry);
    set("tdPrize", data.prize);
    set("tdDate", data.date);
    set("tdPlayers", `${data.current} / ${data.max}`);
    set("tdRules", data.rules || "No rules added yet.");
    set("tdRoomId", data.roomid || "Not available");
    set("tdRoomPass", data.roompass || "Not available");

    // ===== BUTTON LOGIC (JOIN / UPLOAD / WAIT) =====
    const joinBtn = document.getElementById("tdJoinBtn") || document.getElementById("popupJoinBtn");
    const uploadBtn = document.getElementById("tdUploadBtn") || document.getElementById("popupUploadBtn");
    const waitMsg = document.getElementById("tdWait");

    if (joinBtn) joinBtn.style.display = "none";
    if (uploadBtn) uploadBtn.style.display = "none";
    if (waitMsg) waitMsg.style.display = "none";

    if (data.joined === "no") {
        if (joinBtn) joinBtn.style.display = "block";
    }
    if (data.joined === "joined") {
        if (uploadBtn) uploadBtn.style.display = "block";
    }
    if (data.joined === "submitted") {
        if (waitMsg) waitMsg.style.display = "block";
    }

    // ===== ACTIONS =====
    if (joinBtn) {
        joinBtn.onclick = () => {
            window.location.href = "/join_form/" + data.id;
        };
    }

    if (uploadBtn) {
        uploadBtn.onclick = () => {
            openResultModal(data.id);
        };
    }
}



function closeTournamentDetails() {
    document.getElementById("tournamentDetailsBox").style.display = "none";
    document.body.classList.remove("no-scroll");
}


/* ==========================
   2. RESULT MODAL
========================== */

function openResultModal(id) {
    const modal = document.getElementById("resultModal-" + id);
    if (modal) modal.style.display = "flex";
}

function closeResultModal(id) {
    document.getElementById("resultModal-" + id).style.display = "none";
}

/* ==========================
   PROFILE PAGE OPEN FIX
========================== */

document.addEventListener("DOMContentLoaded", () => {

    // 🔹 1. TOP-RIGHT PROFILE ICON
    const topProfile = document.getElementById("profileArea");
    if (topProfile) {
        topProfile.addEventListener("click", () => {
            showPage("profilePage");
        });
    }

    // 🔹 2. SIDE MENU PROFILE BUTTON
    const smProfile = document.getElementById("smProfile");
    if (smProfile) {
        smProfile.addEventListener("click", () => {
            showPage("profilePage");
        });
    }
});

/* ==========================
   FIX: toggleMenu function missing
========================== */

function toggleMenu() {
    const sideMenu = document.getElementById("sideMenu");
    if (sideMenu) sideMenu.classList.remove("active");
}

/* ==========================
   3. CATEGORY FILTER
========================== */

function showCategory(category) {
    document.querySelectorAll('.category-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.tournament-navbar button').forEach(b => b.classList.remove('active'));

    document.getElementById("category-" + category).classList.add("active");
    event.target.classList.add("active");
}


/* FIX: profile page open listener */
const smProfile = document.getElementById("smProfile");
if (smProfile) {
    smProfile.addEventListener("click", () => {
        showPage("profilePage");
    });
}
const topProfile = document.getElementById("profileArea");
if (topProfile) {
    topProfile.addEventListener("click", () => {
        showPage("profilePage");
    });
}

/* ==========================
   4. SIDE MENU FIXED
========================== */

const sideMenu = document.getElementById("sideMenu");
const menuIcon = document.getElementById("menuIcon");

// Only open/close when user clicks menu icon
menuIcon.addEventListener("click", () => {
    sideMenu.classList.toggle("active");
});

// Close side menu when clicking any link
document.querySelectorAll("#sideMenu a").forEach(link => {
    link.addEventListener("click", () => {
        sideMenu.classList.remove("active");
    });
});


/* ==========================
   5. PAGE SWITCHING
========================== */

function showPage(id, btn = null) {
    document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
    document.getElementById(id).classList.add("active");

    // bottom nav highlight
    document.querySelectorAll(".bottom-nav .nav-item").forEach(a => a.classList.remove("active"));
    if (btn) btn.classList.add("active");

    toggleMenu(); // auto close menu
    window.scrollTo({ top: 0, behavior: "smooth" });
}


/* ==========================
   6. FADE-IN ANIMATION (MERGED)
========================== */

document.addEventListener("DOMContentLoaded", () => {

    const observer = new IntersectionObserver((entries, obs) => {
        entries.forEach(entry => {
            if (!entry.isIntersecting) return;

            entry.target.classList.add("show");
            obs.unobserve(entry.target);
        });
    }, { threshold: 0.2 });

    // 🔹 observe both fade-in elements & tournament cards
    document
        .querySelectorAll(".fade-in, .tournament-card")
        .forEach(el => observer.observe(el));

});




/* ==========================
   7. BUTTON RIPPLE EFFECT
========================== */

document.addEventListener("click", e => {
    if (!e.target.matches("button")) return;

    const btn = e.target;
    const circle = document.createElement("span");
    const diameter = Math.max(btn.clientWidth, btn.clientHeight);
    const radius = diameter / 2;

    circle.style.width = circle.style.height = diameter + "px";
    circle.style.left = e.clientX - btn.offsetLeft - radius + "px";
    circle.style.top = e.clientY - btn.offsetTop - radius + "px";
    circle.classList.add("ripple");

    btn.appendChild(circle);
    setTimeout(() => circle.remove(), 600);
});


/* ==========================
   8. SLIDER AUTO ROTATION
========================== */

let slideIndex = 0;
setInterval(() => {
    const slides = document.querySelectorAll(".slider-container .slide");
    if (!slides.length) return;
    slides.forEach(s => s.classList.remove("active"));
    slides[slideIndex].classList.add("active");
    slideIndex = (slideIndex + 1) % slides.length;
}, 3000);


/* ==========================
   9. LOGOUT
========================== */

function logout() {
    window.location.href = "/logout";
}
document.addEventListener("DOMContentLoaded", () => {

    const lazyCards = document.querySelectorAll(".tournament-card");

    const observer = new IntersectionObserver((entries, obs) => {
        entries.forEach(entry => {
            if (!entry.isIntersecting) return;

            const el = entry.target;
            const bg = el.getAttribute("data-bg");

            if (bg) {
                el.style.backgroundImage = `url('${bg}')`;
            }

            obs.unobserve(el);
        });
    }, { threshold: 0.1 });

    lazyCards.forEach(card => observer.observe(card));
});
let offset = 0;
const limit = 5;
let loading = false;

async function loadMoreTournaments() {
    if (loading) return;
    loading = true;

    const res = await fetch(`/tournaments/load/${offset}`);
    const data = await res.json();

    data.tournaments.forEach(t => {
        const card = document.createElement("div");
        card.classList.add("tournament-card");
        card.setAttribute("data-bg", `/static/uploads/${t.image}`);

        card.innerHTML = `
            <div class="overlay"></div>
            <div class="tournament-content">
                <h3>${t.name}</h3>
                <p>${t.desc}</p>
                <p><b>Location:</b> ${t.location}</p>
                <p><b>Entry Fee:</b> ${t.entry_fee}</p>
                <p><b>Prize Pool:</b> ${t.prize_pool}</p>
                <p><b>Date:</b> ${t.date}</p>
                <p><b>Players:</b> ${t.current_players} / ${t.max_players}</p>
            </div>
        `;

        document.getElementById("category-all").appendChild(card);
    });

    offset += limit;
    loading = false;
}

// scroll par load
window.addEventListener("scroll", () => {
    if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 200) {
        loadMoreTournaments();
    }
});







