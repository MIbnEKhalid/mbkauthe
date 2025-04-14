async function logout() {
  const confirmation = confirm("Are you sure you want to logout?");
  if (!confirmation) {
    return;
  }
  try {
    const response = await fetch("/mbkauthe/api/logout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    });
    const result = await response.json();
    if (response.ok) {
      alert(result.message);
      clearAllCookies();
      window.location.reload();
    } else {
      alert(result.message);
    }
  } catch (error) {
    console.error("Error during logout:", error);
    alert("Logout failed");
  }
}

const validateSessionInterval = 60000;
// 1 minutes in milliseconds Function to check session validity by sending a request to the server
function checkSession() {
  fetch("/validate-session")
    .then((response) => {
      if (!response.ok) {
        // Redirect or handle errors (session expired, user inactive, etc.)
        window.location.reload(); // Reload the page to update the session status
      }
    })
    .catch((error) => console.error("Error checking session:", error));
}
// Call validateSession every 2 minutes (120000 milliseconds)
// setInterval(checkSession, validateSessionInterval);

function clearAllCookies() {
  const cookies = document.cookie.split("; ");
  for (const cookie of cookies) {
    const eqPos = cookie.indexOf("=");
    const name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
    document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
  }
}
