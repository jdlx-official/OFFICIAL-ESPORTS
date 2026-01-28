function updateMapLogic() {
    let map = document.getElementById("mapSelect").value;
    let mode = document.getElementById("modeSelect").value;

    let maxPlayers = document.getElementById("maxPlayers");
    let maxTeams = document.getElementById("maxTeams");
    let mapImage = document.getElementById("mapImage");

    let players = 0;
    let teams = 0;

    if (map === "Erangel") {
        mapImage.value = "maps/erangel.jpg";

        if (mode === "Squad") { players = 100; teams = 25; }
        if (mode === "Duo")   { players = 100; teams = 50; }
        if (mode === "Solo")  { players = 100; teams = 100; }
    }

    if (map === "Livik") {
        mapImage.value = "maps/livik.jpg";

        if (mode === "Squad") { players = 52; teams = 13; }
        if (mode === "Duo")   { players = 52; teams = 26; }
        if (mode === "Solo")  { players = 52; teams = 52; }
    }

    if (map === "TDM") {
        mapImage.value = "maps/tdm.jpg";

        if (mode === "Squad") { players = 8; teams = 2; }
        if (mode === "Duo")   { players = 4; teams = 2; }
        if (mode === "Solo")  { players = 2; teams = 2; }
    }

    maxPlayers.value = players;
    maxTeams.value = teams;
}

document.addEventListener("DOMContentLoaded", updateMapLogic);
let duration = 0;
if (map === "Erangel") duration = 60;
if (map === "Livik") duration = 30;
if (map === "TDM") duration = 20;

document.getElementById("duration").value = duration;
