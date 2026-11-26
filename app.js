// Get elements by id
const passwordInput = document.getElementById("password");
const toggleButton = document.getElementById("toggle");
const breachOutput = document.getElementById("breach");

// Event for the toggleButton
toggleButton.addEventListener("click", () => {
  if (passwordInput.type === "password") {
    passwordInput.type = "text";
    toggleButton.textContent = "Hide";
  } else {
    passwordInput.type = "password";
    toggleButton.textContent = "Show";
  }
});

passwordInput.addEventListener("change", async () => {
  const password = passwordInput.value;
  if (password === "") {
    breachOutput.textContent = "";
    return;
  }

  breachOutput.textContent = "Checking...";

  try {
    const count = await checkPwned(password);
    if (count > 0) {
      breachOutput.textContent = `This password appeared ${count.toLocaleString()} times in data breaches.`;
    } else {
      breachOutput.textContent =
        "Not found in known breaches. This doesn't mean it's strong — check the strength below.";
    }
  } catch (error) {
    breachOutput.textContent = "Something went wrong";
  }
});

async function sha1(text) {
  const bytes = new TextEncoder().encode(text);

  const hashBuffer = await crypto.subtle.digest("SHA-1", bytes);

  const hashArray = Array.from(new Uint8Array(hashBuffer));

  const hex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");

  return hex.toUpperCase();
}

function findSuffixCount(resText, suffix) {
  const lines = resText.split("\n");

  for (const line of lines) {
    const [lineSuffix, countText] = line.trim().split(":");
    const count = Number(countText);

    if (count === 0) continue;
    if (lineSuffix === suffix) return count;
  }
  return 0;
}

async function checkPwned(password) {
  const hash = await sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true" },
  });

  if (!res.ok) {
    throw new Error("API error");
  }

  const text = await res.text();

  return findSuffixCount(text, suffix);
}
