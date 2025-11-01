// ================= Keyword sets =================
const suspiciousKeywords = [
  "delete all data", "ignore rules", "shutdown", "override", "bypass", "disable safety",
  "execute hidden command", "self-destruct", "leak", "exfiltrate", "manipulate ai",
  "inject prompt", "break out", "jailbreak", "hack", "corrupt", "malicious", "exploit",
  "run unauthorized code", "disable firewall", "access restricted", "steal credentials"
];

const riskyKeywords = [
  "password", "private", "confidential", "ssn", "credit card", "bank account",
  "medical record", "personal info", "location", "identity", "login", "credentials",
  "email", "phone number", "address", "user data", "sensitive", "pii", "social security",
  "atm pin", "otp", "transaction", "account balance", "click this link", "urgent action",
  "lottery winner", "claim your prize", "update payment info"
];

// ================= Chart setup =================
let promptStats = { safe: 0, risky: 0, suspicious: 0 };
let promptChart;

function initChart() {
  const ctx = document.getElementById("promptChart").getContext("2d");
  promptChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels: ["Safe", "Risky", "Suspicious"],
      datasets: [{
        data: [0, 0, 0],
        backgroundColor: ["#4CAF50", "#FFC107", "#F44336"]
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom" } }
    }
  });
}

// ================= Classification logic =================
function classifyPrompt() {
  const prompt = document.getElementById("promptInput").value.trim();
  const resultBox = document.getElementById("resultBox");
  const spinner = document.getElementById("loadingSpinner");

  if (!prompt) return showToast("⚠️ Please enter a prompt.");

  resultBox.textContent = "";
  spinner.style.display = "block";

  setTimeout(() => {
    let label;
    const lower = prompt.toLowerCase();

    if (suspiciousKeywords.some(k => lower.includes(k))) label = "suspicious";
    else if (riskyKeywords.some(k => lower.includes(k))) label = "risky";
    else label = "safe";

    spinner.style.display = "none";

    const labelMap = {
      safe: { text: "✅ Safe Prompt", color: "#4CAF50" },
      risky: { text: "⚠️ Risky Prompt", color: "#FFC107" },
      suspicious: { text: "🚨 Suspicious Prompt", color: "#F44336" }
    };

    resultBox.textContent = labelMap[label].text;
    resultBox.style.color = labelMap[label].color;

    promptStats[label]++;
    promptChart.data.datasets[0].data = [promptStats.safe, promptStats.risky, promptStats.suspicious];
    promptChart.update();

    const li = document.createElement("li");
    li.textContent = `Prompt: "${prompt}" → ${label.toUpperCase()}`;
    li.style.color = resultBox.style.color;
    document.getElementById("historyList").prepend(li);

    showToast("✅ Prompt checked successfully!");
  }, 800);
}

// ================= History & Toast =================
function clearHistory() {
  document.getElementById("historyList").innerHTML = "";
  showToast("🗑️ Prompt history cleared.");
}

function showToast(msg) {
  const toast = document.getElementById("toast");
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2000);
}

// ================= Navigation =================
function showSection(name) {
  const sections = {
    demoIntro: document.getElementById("demoIntroSection"),
    demo: document.getElementById("demoSection"),
    features: document.getElementById("featuresSection"),
    usecases: document.getElementById("usecasesSection")
  };

  Object.values(sections).forEach(sec => sec.style.display = "none");

  if (name === "demo") {
    sections.demoIntro.style.display = "block";
  } else if (name === "features") {
    sections.features.style.display = "block";
  } else if (name === "usecases") {
    sections.usecases.style.display = "block";
  } else if (name === "tryNow") {
    sections.demo.style.display = "block";

    if (!promptChart) {
      setTimeout(() => initChart(), 100);
    } else {
      promptChart.resize();
      promptChart.update();
    }
  }

  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.addEventListener("DOMContentLoaded", () => {
  showSection("demo");

  const tryNowBtn = document.getElementById("tryNowBtn");
  if (tryNowBtn) tryNowBtn.addEventListener("click", () => showSection("tryNow"));

  const tryNowNavBtn = document.getElementById("tryNowNavBtn");
  if (tryNowNavBtn) {
    tryNowNavBtn.addEventListener("click", (e) => {
      e.preventDefault();
      showSection("tryNow");
    });
  }
});
