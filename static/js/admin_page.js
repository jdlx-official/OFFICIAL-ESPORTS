document.addEventListener("DOMContentLoaded", () => {

  /* SECTION SWITCHING */
  window.showSection = function(id){
    document.querySelectorAll(".section").forEach(s => s.style.display = "none");
    document.getElementById(id).style.display = "block";
  };

  /* MODALS */
  window.openAddModal = () => document.getElementById("addModal").style.display = "flex";
  window.closeModal = id => document.getElementById(id).style.display = "none";

  /* -------- EDIT TOURNAMENT -------- */
  window.openTournamentEditModal = function(id,name,loc,date,entry,prize,desc){

    fetch("/get_csrf").then(r=>r.text()).then(token=>{
      document.querySelector("#editForm input[name='csrf_token']").value = token;
    });

    document.getElementById("editModal").style.display="flex";

    document.getElementById("editName").value = name;
    document.getElementById("editLocation").value = loc;
    document.getElementById("editDate").value = date;
    document.getElementById("editEntryFee").value = entry;
    document.getElementById("editPrize").value = prize;
    document.getElementById("editDesc").value = desc;

    document.getElementById("editForm").action = "/edit_tournament/" + id;
  };

  /* -------- VIEW TOURNAMENT -------- */
  window.viewTournament = function(id){
    fetch(`/admin/tournament/${id}`)
    .then(res => res.text())
    .then(html => {
      const panel = document.getElementById("tournamentViewPanel");
      panel.innerHTML = html;
      panel.style.display = "block";
    });
  };

  /* -------- EDIT USER MODAL -------- */
  window.openUserEditModal = function(id,name,email,mobile){
    document.getElementById("editUserModal").style.display="flex";
    document.getElementById("editUsername").value=name;
    document.getElementById("editEmail").value=email;
    document.getElementById("editMobile").value=mobile;
    document.getElementById("editUserForm").action="/edit_user/"+id;
  };

  window.closeUserEditModal = () =>
    document.getElementById("editUserModal").style.display="none";

});

window.onerror = function (msg, url, line, col, error) {
    fetch("/client_error", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            message: msg,
            url: url,
            line: line,
            col: col,
            error: error ? error.stack : null
        })
    });
};

function getCurrentUser() {
    return fetch("/whoami")
      .then(r => r.json())
      .catch(() => null);
}

window.addEventListener("beforeunload", function () {
  navigator.sendBeacon("/set_offline");
});

setInterval(() => {
    fetch("/get_csrf")
       .then(r=>r.text())
       .then(token => {
           document.querySelectorAll("input[name='csrf_token']")
             .forEach(el => el.value = token);
       });
}, 300000); // 5 min

document.addEventListener("click", function(e){
    const box = document.getElementById("searchResults");
    if (box && !e.target.closest(".search-box")) {
        box.classList.remove("visible");
    }
});

window.viewTournament = function(id){
    fetch(`/admin/tournament/${id}`)
      .then(res => res.text())
      .then(html => {
          const panel = document.getElementById("tournamentViewPanel");
          panel.innerHTML = html;
          panel.style.display = "block";
          window.scrollTo({ top: 0, behavior:"smooth" });
      })
      .catch(err => alert("Error loading tournament!"));
};

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("td").forEach(td => {
        if (td.textContent.trim() === "None") td.textContent = "-";
    });
});

window.openTournamentEditModal = function(id,name,loc,date,entry,prize,desc){
    
    // Refresh CSRF every time
    fetch("/get_csrf")
      .then(r=>r.text())
      .then(token => {
        document.querySelector("#editForm input[name='csrf_token']").value = token;
      });

    document.getElementById("editModal").style.display="flex";

    document.getElementById("editName").value = name || "";
    document.getElementById("editLocation").value = loc || "";
    document.getElementById("editDate").value = date || "";
    document.getElementById("editEntryFee").value = entry || "";
    document.getElementById("editPrize").value = prize || "";
    document.getElementById("editDesc").value = desc || "";

    // Start/End time avoid breaking values
    document.getElementById("editStart").value = "";
    document.getElementById("editEnd").value = "";

    document.getElementById("editForm").action = "/edit_tournament/" + id;
};



window.openUserEditModal = function(id,name,email,mobile){
    document.getElementById("editUserModal").style.display="flex";
    document.getElementById("editUsername").value = name;
    document.getElementById("editEmail").value    = email;
    document.getElementById("editMobile").value   = mobile;

    document.getElementById("editUserForm").action = "/edit_user/" + id;
};


function viewTournament(id) {
    fetch(`/admin/tournament/${id}`)
        .then(res => res.text())
        .then(html => {
            document.getElementById("tournamentDetailsPanel").innerHTML = html;
            document.getElementById("tournamentDetailsPanel").style.display = "block";
        });
}

document.addEventListener("DOMContentLoaded", () => {
    const buttons = document.querySelectorAll(".sidebar button");

    buttons.forEach(btn => {
        btn.addEventListener("click", () => {
            buttons.forEach(b => b.classList.remove("active-section"));
            btn.classList.add("active-section");
        });
    });
});
const rules = {
  ERANGEL: {
    duration: 60,
    solo: { players: 100 },
    duo: { teams: 50, players: 100 },
    squad: { teams: 25, players: 100 },
    image: "erangel.jpg"
  },
  LIVIK: {
    duration: 30,
    solo: { players: 52 },
    duo: { teams: 26, players: 52 },
    squad: { teams: 13, players: 52 },
    image: "livik.jpg"
  },
  TDM: {
    duration: 20,
    teams: 2,
    players: 8,
    image: "tdm.jpg"
  }
};

function applyRules() {
  const map = document.getElementById("mapSelect").value;
  const mode = document.getElementById("modeSelect").value;
  if (!map || !mode) return;

  const r = rules[map];

  if (map === "TDM") {
    maxTeams.value = r.teams;
    maxPlayers.value = r.players;
  } else {
    maxTeams.value = r[mode].teams || 0;
    maxPlayers.value = r[mode].players;
  }

  document.getElementById("mapImage").value = r.image;
}

document.getElementById("mapSelect").onchange = applyRules;
document.getElementById("modeSelect").onchange = applyRules;

