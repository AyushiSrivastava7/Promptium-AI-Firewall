document.getElementById("scanBtn").addEventListener("click", async () => {
  const prompt = document.getElementById("promptInput").value.trim();
  const resultDiv = document.getElementById("result");

  if (!prompt) {
    resultDiv.textContent = "⚠️ Please enter a prompt.";
    resultDiv.style.color = "orange";
    return;
  }

  // Mock scanning logic (for now)
  if (
    prompt.toLowerCase().includes("ignore rules") ||
    prompt.toLowerCase().includes("bypass") ||
    prompt.toLowerCase().includes("delete") ||
    prompt.toLowerCase().includes("disable safety")
  ) {
    resultDiv.textContent = "🚨 Suspicious prompt detected!";
    resultDiv.style.color = "red";
  } else {
    resultDiv.textContent = "✅ Safe prompt!";
    resultDiv.style.color = "green";
  }
});
