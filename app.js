// Get elements by id
const passwordInput = document.getElementById("password");
const toggleButton = document.getElementById("toggle");
const breachOutput = document.getElementById("breach");
const strengthOutput = document.getElementById("strength");
const strengthMeter = document.getElementById("strength-meter");
const feedbackOutput = document.getElementById("feedback");
const generateButton = document.getElementById("generate");
const passphraseOutput = document.getElementById("passphrase");
const passphraseInfo = document.getElementById("passphrase-info");

let debounceTimer;
let latestRequestId = 0;
let wordList = [];

const WORD_COUNT = 5;

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

passwordInput.addEventListener("input", () => {
  clearTimeout(debounceTimer);

  const password = passwordInput.value;
  showStrength(password);

  if (password === "") {
    latestRequestId++;
    breachOutput.textContent = "";
    return;
  }

  debounceTimer = setTimeout(() => {
    checkAndShow(password);
  }, 500);
});

async function loadWordList() {
  const res = await fetch("wordlists/eff_large_wordlist.txt");

  if (!res.ok) throw new Error("Could not load word list");

  const text = await res.text();
  wordList = text
    .trim()
    .split("\n")
    .map((line) => line.split("\t")[1].trim());
}

function secureRandomInt(max) {
  const limit = Math.floor(2 ** 32 / max) * max;
  const buffer = new Uint32Array(1);

  let value;

  do {
    crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);
  return value % max;
}

function generatePassphrase(count) {
  const words = [];
  for (let i = 0; i < count; i++) {
    words.push(wordList[secureRandomInt(wordList.length)]);
  }
  return words.join("-");
}

generateButton.addEventListener("click", async () => {
  try {
    if (wordList.length === 0) {
      await loadWordList();
    }

    passphraseOutput.textContent = generatePassphrase(WORD_COUNT);

    const entropy = WORD_COUNT * Math.log2(wordList.length);
    passphraseInfo.textContent = `${WORD_COUNT} words from a list of ${wordList.length} → ${entropy.toFixed(1)} bits of entropy`;
  } catch (error) {
    passphraseInfo.textContent = "Could not generate a passphrase";
  }
});

async function checkAndShow(password) {
  const requestId = ++latestRequestId;

  breachOutput.textContent = "Checking...";

  try {
    const count = await checkPwned(password);

    if (requestId !== latestRequestId) return;

    if (count > 0) {
      breachOutput.textContent = `This password appeared ${count.toLocaleString()} times in data breaches.`;
    } else {
      breachOutput.textContent =
        "Not found in known breaches. This doesn't mean it's strong — check the strength below.";
    }
  } catch (error) {
    if (requestId !== latestRequestId) return;
    breachOutput.textContent = "Something went wrong";
  }
}

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

function naiveEntropy(password) {
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

  if (poolSize === 0) return 0;
  return password.length * Math.log2(poolSize);
}

function showStrength(password) {
  if (password === "") {
    strengthOutput.textContent = "";
    feedbackOutput.textContent = "";
    strengthMeter.value = 0;
    return;
  }

  const entropy = Math.round(naiveEntropy(password));
  const result = zxcvbn(password);

  strengthMeter.value = result.score;
  strengthOutput.textContent =
    `Naive entropy: ${entropy} bits · zxcvbn score: ${result.score}/4 · \n` +
    `Time to crack (offline with slow hashing): ${result.crack_times_display.offline_slow_hashing_1e4_per_second}\n` +
    `Time to crack (offline with fast hashing): ${result.crack_times_display.offline_fast_hashing_1e10_per_second}`;

  feedbackOutput.textContent = [
    result.feedback.warning,
    ...result.feedback.suggestions,
  ].join(" ");
}
