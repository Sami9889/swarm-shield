/**
 * Auth Module - Handles sign-in, API key management, and JWT storage.
 */
const Auth = (() => {
    const TOKEN_KEY = 'swarm_shield_token';
    const API_KEY_KEY = 'swarm_shield_api_key';

    let currentToken = null;

    function init() {
        const stored = localStorage.getItem(TOKEN_KEY);
        if (stored) {
            currentToken = stored;
        }
    }

    function isLoggedIn() {
        return currentToken !== null;
    }

    function getToken() {
        return currentToken;
    }

    function setToken(token) {
        currentToken = token;
        localStorage.setItem(TOKEN_KEY, token);
    }

    function getAPIKey() {
        return localStorage.getItem(API_KEY_KEY) || '';
    }

    function setAPIKey(key) {
        localStorage.setItem(API_KEY_KEY, key);
    }

    function logout() {
        currentToken = null;
        localStorage.removeItem(TOKEN_KEY);
    }

    async function login(apiKey) {
        const res = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ apiKey }),
        });

        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.error || 'Login failed');
        }

        setToken(data.token);
        setAPIKey(apiKey);
        return data;
    }

    async function generateAPIKey(name) {
        const res = await fetch(`${API_BASE}/api/auth/keys`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getToken()}`,
            },
            body: JSON.stringify({ name }),
        });

        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.error || 'Failed to generate API key');
        }
        return data;
    }

    async function listKeys() {
        const res = await fetch(`${API_BASE}/api/auth/keys`, {
            headers: {
                'Authorization': `Bearer ${getToken()}`,
            },
        });

        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.error || 'Failed to list keys');
        }
        return data;
    }

    init();

    return {
        isLoggedIn,
        getToken,
        setToken,
        getAPIKey,
        setAPIKey,
        logout,
        login,
        generateAPIKey,
        listKeys,
    };
})();
