/* ======================================================
   OFFICIAL & ORIGINAL LOGIC (Home_Page.js extracted)
   Tournament Version using DATA-ATTRIBUTES
====================================================== */

let currentTournamentId = null;

/* ==========================
   OPEN POPUP (Option B)
========================== */

function openTournamentDetails(el) {
    const box = document.getElementById("tournamentDetailsBox");
    box.style.display = "flex";
    document.body.classList.add("no-scroll");

    // READ DATA FROM ATTRIBUTES
    const data = {
        id: el.dataset.id,
        name: el.dataset.name,
        desc: el.dataset.desc,
        entry: el.dataset.entry,
        prize: el.dataset.prize,
        date: el.dataset.date,
        location: el.dataset.location,
        current: el.dataset.current,
        max: el.dataset.max,
        rules: el.dataset.rules,
        image: el.dataset.image,
        roomid: el.dataset.roomid,
        roompass: el.dataset.roompass,
        joined_status: el.dataset.joined
    };

    currentTournamentId = data.id;

    // FILL UI
    document.getElementById("tdBanner").src = data.image || "";
    document.getElementById("tdName").innerText = data.name || "";
    document.getElementById("tdDesc").innerText = data.desc || "";
    document.getElementById("tdLocation").innerText = data.location || "";
    document.getElementById("tdPrize").innerText = data.prize || "";
    document.getElementById("tdEntry").innerText = data.entry || "";
    document.getElementById("tdDate").innerText = data.date || "";
    document.getElementById("tdPlayers").innerText = `${data.current} / ${data.max}`;

    // EXTRA
    document.getElementById("tdRules").innerText = data.rules || "No rules added.";
    document.getElementById("tdRoomId").innerText = data.roomid || "Not available";
    document.getElementById("tdRoomPass").innerText = data.roompass || "Not available";

    updatePopupUI(data.joined_status);

    // Disable background clicks
    document.querySelectorAll(".page, .bottom-nav, .side-menu")
        .forEach(elm => elm.style.pointerEvents = "none");
}


/* ==========================
   UPDATE UI BASED ON STATUS
========================== */

function updatePopupUI(status) {
    const joinBtn = document.getElementById("popupJoinBtn");
    const uploadBtn = document.getElementById("popupUploadBtn");
    const waitMsg = document.getElementById("tdWait");

    joinBtn.style.display = "none";
    uploadBtn.style.display = "none";
    if (waitMsg) waitMsg.style.display = "none";

    if (status === "no") joinBtn.style.display = "block";
    if (status === "joined") uploadBtn.style.display = "block";
    if (status === "submitted" && waitMsg) waitMsg.style.display = "block";

    joinBtn.onclick = () => window.location.href = "/join_form/" + currentTournamentId;
}


/* ==========================
   CLOSE POPUP
========================== */

function closeTournamentDetails() {
    document.getElementById("tournamentDetailsBox").style.display = "none";
    document.body.classList.remove("no-scroll");

    document.querySelectorAll(".page, .bottom-nav, .side-menu")
        .forEach(el => el.style.pointerEvents = "auto");
}


/* ==========================
   RESULT MODALS
========================== */

function openResultModal(id) {
    const modal = document.getElementById("resultModal-" + id);
    if (modal) modal.style.display = "flex";
}

function closeResultModal(id) {
    const modal = document.getElementById("resultModal-" + id);
    if (modal) modal.style.display = "none";
}

function openScreenshotModal(id) {
    openResultModal(id);
}


/* ==========================
   CATEGORY FILTER
========================== */

function showCategory(category) {
    document.querySelectorAll('.category-section')
        .forEach(s => s.classList.remove('active'));

    document.getElementById("category-" + category)?.classList.add("active");

    document.querySelectorAll('.tournament-navbar button')
        .forEach(btn => btn.classList.remove('active'));

    if (event && event.target) {
        event.target.classList.add('active');
    }
}


/* ==========================
   TIMER (ORIGINAL)
========================== */

function initTournamentTimers() {
    document.querySelectorAll('.tournament-card').forEach(card => {
        let timerEl = card.querySelector('.timer');
        if (!timerEl) return;

        let startTS = parseInt(card.dataset.start) * 1000;
        let endTS = parseInt(card.dataset.end) * 1000;

        function update() {
            let now = Date.now();
            if (now < startTS) {
                timerEl.innerHTML = "Starts in: " + formatTime(startTS - now);
            } else if (now >= startTS && now <= endTS) {
                timerEl.innerHTML = "Ends in: " + formatTime(endTS - now);
            } else {
                timerEl.innerHTML = "Event Over";
            }
        }

        update();
        setInterval(update, 1000);
    });
}


function formatTime(ms) {
    let sec = Math.floor(ms / 1000);
    let m = Math.floor(sec / 60);
    let h = Math.floor(m / 60);
    let d = Math.floor(h / 24);

    sec %= 60; m %= 60; h %= 24;

    return `${d}d ${h}h ${m}m ${sec}s`;
}


/* ==========================
   INIT
========================== */

document.addEventListener("DOMContentLoaded", () => {
    initTournamentTimers();
});
