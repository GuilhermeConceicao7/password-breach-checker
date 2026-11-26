// Get elements by id
const passwordInput = document.getElementById("password");
const toggleButton = document.getElementById("toggle");

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

async function sha1(text) {
  
  const bytes = new TextEncoder().encode(text);
 
  const hashBuffer =  await crypto.subtle.digest("SHA-1", bytes);

  const hashArray = Array.from(new Uint8Array(hashBuffer));
 
  const hex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  
  return hex.toUpperCase();
}

