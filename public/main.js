async function logout() {
  const confirmation = confirm("Are you sure you want to logout?");
  if (!confirmation) {
    return;
  }

  try {
    // First, logout from server
    const response = await fetch("/mbkauthe/api/logout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache"
      },
      credentials: "include"
    });

    const result = await response.json();

    if (response.ok) {
      // Then clear all caches after successful logout (except rememberedUsername)
      await selectiveCacheClear();
      // selectiveCacheClear already redirects, so no need for additional redirect
    } else {
      alert(result.message);
    }
  } catch (error) {
    console.error("[mbkauthe] Error during logout:", error);
    alert(`Logout failed: ${error.message}`);
  }
}

async function selectiveCacheClear() {
  try {

    const cookiesToClear = [
      'sessionId',
      'mbkauthe.sid',
      'fullName',
      '_csrf'
    ];

    const localStorageToClear = [
      'sessionId',
      'mbkauthe.sid',
      'fullName',
      '_csrf'
    ];

    // 1. Clear selected localStorage keys
    localStorageToClear.forEach(key => {
      localStorage.removeItem(key);
    });

    // 2. Clear selected cookies
    cookiesToClear.forEach(name => {
      document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
      document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=${window.location.hostname}`;
      document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=.${window.location.hostname}`;
    });

    // 3. Optional reload
    window.location.reload();

  } catch (error) {
    console.error('[mbkauthe] selective cache clear failed:', error);
    window.location.reload();
  }
}

async function logoutuser() {
  await logout();
}

const validateSessionInterval = 60000;
// 1 minutes in milliseconds Function to check session validity by sending a request to the server
function checkSession() {
  fetch("/api/validate-session")
    .then((response) => {
      if (!response.ok) {
        // Redirect or handle errors (session expired, user inactive, etc.)
        window.location.reload(); // Reload the page to update the session status
      }
    })
    .catch((error) => console.error("[mbkauthe] Error checking session:", error));
}
// Call validateSession every 2 minutes (120000 milliseconds)
// setInterval(checkSession, validateSessionInterval);

function getCookieValue(cookieName) {
  const cookies = document.cookie.split('; ');
  for (let cookie of cookies) {
    const [name, value] = cookie.split('=');
    if (name === cookieName) {
      return decodeURIComponent(value);
    }
  }
  return null; // Return null if the cookie is not found
}

function loadpage(url) {
  window.location.href = url;
}

function formatDate(date) {
  return new Date(date).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric', hour12: true });
}

function reloadPage() {
  window.location.reload();
}