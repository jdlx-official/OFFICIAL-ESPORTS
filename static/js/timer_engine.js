function updateAllTimers() {
    const cards = document.querySelectorAll(".tournament-card");

    cards.forEach(card => {
        const start = parseInt(card.dataset.start);
        const end = parseInt(card.dataset.end);
        const status = card.dataset.status;
        const now = Date.now();

        let text = "";
        let newStatus = status;

        // UPCOMING TIMER
        if (now < start) {
            let diff = start - now;
            text = "Starts in: " + formatTime(diff);

            newStatus = "upcoming";
        }

        // ONGOING TIMER
        else if (now >= start && now < end) {
            let diff = end - now;
            text = "Ends in: " + formatTime(diff);

            newStatus = "ongoing";
        }

        // COMPLETED
        else {
            text = "Completed";
            newStatus = "completed";
        }

        card.querySelector(".timer").innerText = text;

        // Auto update UI status without reload
        updateCardButtons(card, newStatus);
    });
}

function formatTime(ms) {
    let totalSec = Math.floor(ms / 1000);
    let h = Math.floor(totalSec / 3600);
    let m = Math.floor((totalSec % 3600) / 60);
    let s = totalSec % 60;

    return (h>0?h+"h ":"") + (m>0?m+"m ":"") + s+"s";
}

function updateCardButtons(card, status) {
    const btnArea = card.querySelector(".button-area");

    if (status === "upcoming") {
        btnArea.innerHTML = `<button class="join-btn">Join</button>`;
    } 
    else if (status === "ongoing") {
        if (card.dataset.link) {
            btnArea.innerHTML = `<a href="${card.dataset.link}" class="view-btn">View Match</a>`;
        } else {
            btnArea.innerHTML = `<button onclick="alert('Match link not generated')">View</button>`;
        }
    }
    else {
        btnArea.innerHTML = `<button class="wait-btn" disabled>Wait for Result</button>`;
    }
}

setInterval(updateAllTimers, 1000);
