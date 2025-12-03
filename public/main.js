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
      await nuclearCacheClear();
      // nuclearCacheClear already redirects, so no need for additional redirect
    } else {
      alert(result.message);
    }
  } catch (error) {
    console.error("[mbkauthe] Error during logout:", error);
    alert(`Logout failed: ${error.message}`);
  }
}

async function nuclearCacheClear() {
  try {
    // Preserve rememberedUsername before clearing storage
    const rememberedUsername = localStorage.getItem('rememberedUsername');

    // 1. Clear all possible caches
    if ('caches' in window) {
      const cacheNames = await caches.keys();
      await Promise.all(cacheNames.map(cacheName => caches.delete(cacheName)));
    }

    // 2. Clear service workers
    if ('serviceWorker' in navigator) {
      const registrations = await navigator.serviceWorker.getRegistrations();
      await Promise.all(registrations.map(registration => registration.unregister()));
    }

    // 3. Clear all storage except rememberedUsername
    localStorage.clear();
    sessionStorage.clear();
    if (rememberedUsername) {
      localStorage.setItem('rememberedUsername', rememberedUsername);
    }

    if ('indexedDB' in window) {
      try {
        const dbs = await window.indexedDB.databases();
        await Promise.all(dbs.map(db => {
          if (db.name) {
            return window.indexedDB.deleteDatabase(db.name);
          }
          return Promise.resolve();
        }));
      } catch (error) {
        console.error("[mbkauthe] Error clearing IndexedDB:", error);
      }
    }

    // 4. Clear cookies (except those you want to preserve)
    document.cookie.split(';').forEach(cookie => {
      const eqPos = cookie.indexOf('=');
      const name = eqPos > -1 ? cookie.substr(0, eqPos).trim() : cookie.trim();

      // Skip cookies you want to preserve (add conditions as needed)
      if (!name.startsWith('preserve_')) {  // Example condition
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=${window.location.hostname}`;
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=.${window.location.hostname}`;
      }
    });

    // 5. Force hard reload with cache busting
    window.location.reload();

  } catch (error) {
    console.error('[mbkauthe] Nuclear cache clear failed:', error);
    window.location.reload(true);
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