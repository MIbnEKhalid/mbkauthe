(() => {
  const SESSION_KEYS = [
    'sessionId',
    'mbkauthe.sid',
    'fullName',
    '_csrf',
    'profileImageUser',
    'profileImageUrl'
  ];
  const LOG_PREFIX = '[mbkauthe]';
  const EXPIRED_COOKIE = 'expires=Thu, 01 Jan 1970 00:00:00 GMT';
  const dateFormatter = new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    hour12: true
  });

  const reloadPage = () => window.location.reload();

  const getCookieDomains = () => {
    const hostname = window.location.hostname;

    if (!hostname) {
      return [];
    }

    return [...new Set([hostname, hostname.includes('.') ? `.${hostname}` : null].filter(Boolean))];
  };

  const clearCookie = (name) => {
    document.cookie = `${name}=; ${EXPIRED_COOKIE}; path=/`;

    getCookieDomains().forEach((domain) => {
      document.cookie = `${name}=; ${EXPIRED_COOKIE}; path=/; domain=${domain}`;
    });
  };

  const parseJson = async (response) => {
    try {
      return await response.json();
    } catch {
      return {};
    }
  };

  async function logout({ confirmLogout = true } = {}) {
    if (confirmLogout && !confirm('Are you sure you want to logout?')) {
      return false;
    }

    try {
      const response = await fetch('/mbkauthe/api/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache'
        },
        credentials: 'include',
        cache: 'no-store'
      });
      const result = await parseJson(response);

      if (response.ok) {
        selectiveCacheClear();
        return true;
      }

      alert(result.message || 'Logout failed. Please try again.');
    } catch (error) {
      console.error(`${LOG_PREFIX} Error during logout:`, error);
      alert(`Logout failed: ${error.message}`);
    }

    return false;
  }

  function selectiveCacheClear() {
    try {
      SESSION_KEYS.forEach((key) => localStorage.removeItem(key));
      SESSION_KEYS.forEach(clearCookie);
    } catch (error) {
      console.error(`${LOG_PREFIX} selective cache clear failed:`, error);
    } finally {
      reloadPage();
    }
  }

  async function logoutuser() {
    return logout();
  }

  function checkSession() {
    return fetch('/mbkauthe/api/checkSession', {
      credentials: 'include',
      cache: 'no-store'
    })
      .then(async (response) => {
        if (!response.ok) {
          reloadPage();
          return;
        }

        const session = await parseJson(response);
        if (session.sessionValid === false) {
          reloadPage();
        }
      })
      .catch((error) => console.error(`${LOG_PREFIX} Error checking session:`, error));
  }

  function getCookieValue(cookieName) {
    if (!cookieName) {
      return null;
    }

    const prefix = `${cookieName}=`;
    const cookie = document.cookie
      .split('; ')
      .find((entry) => entry.startsWith(prefix));

    if (!cookie) {
      return null;
    }

    const value = cookie.slice(prefix.length);

    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }

  function loadpage(url) {
    if (url) {
      window.location.href = url;
    }
  }

  function formatDate(date) {
    const parsedDate = new Date(date);
    return Number.isNaN(parsedDate.getTime()) ? 'Invalid Date' : dateFormatter.format(parsedDate);
  }

  const api = {
    checkSession,
    formatDate,
    getCookieValue,
    loadpage,
    logout,
    logoutuser,
    reloadPage,
    selectiveCacheClear
  };

  window.mbkauthe = Object.assign(window.mbkauthe || {}, api);
  Object.assign(window, api);
})();
