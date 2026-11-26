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