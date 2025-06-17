const { app } = require('@azure/functions');
const { DefaultAzureCredential } = require('@azure/identity');
const { SecretClient } = require('@azure/keyvault-secrets');
const axios = require('axios');
require('dotenv').config();

// Key Vault configuration
const KEY_VAULT_URL = process.env.KEY_VAULT_URL;
const credential = new DefaultAzureCredential();
const secretClient = new SecretClient(KEY_VAULT_URL, credential);

// Configuration
const CONFIG = {
    EXACT_TOKEN_URL: process.env.EXACT_TOKEN_URL,
    EXACT_AUTH_URL: process.env.EXACT_AUTH_URL,
    MIN_REFRESH_INTERVAL: 570000, // 9.5 minutes in milliseconds
    TOKEN_BUFFER: 60000 // 1 minute buffer before expiry
};

// In-memory cache for credentials (to avoid repeated Key Vault calls)
let credentialsCache = {
    CLIENT_ID: null,
    CLIENT_SECRET: null,
    REDIRECT_URI: null,
    lastFetch: 0,
    cacheDuration: 300000 // 5 minutes cache
};

// Token storage - in production, consider storing refresh tokens in Key Vault too
let tokenStore = {
    access_token: null,
    refresh_token: null,
    expires_at: 0,
    last_refresh: 0
};

/**
 * Get credentials from Key Vault with caching
 */
async function getCredentials() {
    const now = Date.now();
    
    // Return cached credentials if still valid
    if (credentialsCache.CLIENT_ID && (now - credentialsCache.lastFetch) < credentialsCache.cacheDuration) {
        return credentialsCache;
    }

    try {
        // Fetch from Key Vault - adjust secret names to match your Key Vault
        const [clientIdSecret, clientSecretSecret, redirectUriSecret] = await Promise.all([
            secretClient.getSecret('exact-client-id'),
            secretClient.getSecret('exact-client-secret'),
            secretClient.getSecret('exact-redirect-uri')
        ]);

        // Update cache
        credentialsCache.CLIENT_ID = clientIdSecret.value;
        credentialsCache.CLIENT_SECRET = clientSecretSecret.value;
        credentialsCache.REDIRECT_URI = redirectUriSecret.value;
        credentialsCache.lastFetch = now;

        console.log('Credentials fetched from Key Vault');
        return credentialsCache;

    } catch (error) {
        console.error('Failed to fetch credentials from Key Vault:', error.message);
        throw new Error('Could not retrieve credentials from Key Vault');
    }
}

/**
 * Store refresh token in Key Vault for persistence
 */
async function storeRefreshToken(refreshToken) {
    try {
        await secretClient.setSecret('exact-refresh-token', refreshToken);
        console.log('Refresh token stored in Key Vault');
    } catch (error) {
        console.error('Failed to store refresh token in Key Vault:', error.message);
    }
}

/**
 * Retrieve refresh token from Key Vault
 */
async function getStoredRefreshToken() {
    try {
        const secret = await secretClient.getSecret('exact-refresh-token');
        return secret.value;
    } catch (error) {
        console.log('No refresh token found in Key Vault');
        return null;
    }
}

/**
 * Initialize token store from Key Vault on startup
 */
async function initializeTokenStore() {
    try {
        const storedRefreshToken = await getStoredRefreshToken();
        if (storedRefreshToken) {
            tokenStore.refresh_token = storedRefreshToken;
            console.log('Refresh token loaded from Key Vault');
        }
    } catch (error) {
        console.error('Failed to initialize token store:', error.message);
    }
}

/**
 * Checks if the current access token is valid and not expired
 */
function isTokenValid() {
    if (!tokenStore.access_token) return false;
    
    const now = Date.now();
    const expiresWithBuffer = tokenStore.expires_at - CONFIG.TOKEN_BUFFER;
    
    return now < expiresWithBuffer;
}

/**
 * Checks if enough time has passed since the last refresh
 */
function canRefreshToken() {
    const now = Date.now();
    const timeSinceLastRefresh = now - tokenStore.last_refresh;
    
    return timeSinceLastRefresh >= CONFIG.MIN_REFRESH_INTERVAL;
}

/**
 * Refreshes the access token using the refresh token
 */
async function refreshAccessToken() {
    console.log('Starting token refresh process...');
    console.log('Current token store state:', {
        hasAccessToken: !!tokenStore.access_token,
        hasRefreshToken: !!tokenStore.refresh_token,
        expiresAt: tokenStore.expires_at,
        lastRefresh: tokenStore.last_refresh
    });
    
    if (!tokenStore.refresh_token) {
        console.log('No refresh token in memory, checking Key Vault...');
        // Try to load from Key Vault
        const storedRefreshToken = await getStoredRefreshToken();
        if (storedRefreshToken) {
            console.log('Refresh token retrieved from Key Vault');
            tokenStore.refresh_token = storedRefreshToken;
        } else {
            console.error('No refresh token found in Key Vault');
            throw new Error('No refresh token available. Initial authorization required.');
        }
    }

    if (!canRefreshToken()) {
        throw new Error('Cannot refresh token yet. Must wait 9.5 minutes between refreshes.');
    }

    const credentials = await getCredentials();
    
    const params = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokenStore.refresh_token,
        client_id: credentials.CLIENT_ID,
        client_secret: credentials.CLIENT_SECRET,
        redirect_uri: credentials.REDIRECT_URI
    });

    try {
        const response = await axios.post(CONFIG.EXACT_TOKEN_URL, params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const now = Date.now();
        
        // Update token store
        tokenStore.access_token = response.data.access_token;
        tokenStore.refresh_token = response.data.refresh_token;
        tokenStore.expires_at = now + (response.data.expires_in * 1000);
        tokenStore.last_refresh = now;

        // Store new refresh token in Key Vault
        await storeRefreshToken(response.data.refresh_token);

        console.log('Tokens refreshed successfully');
        
        return tokenStore.access_token;
    } catch (error) {
        console.error('Token refresh failed:', {
            message: error.message,
            response: error.response?.data,
            status: error.response?.status,
            headers: error.response?.headers
        });
        
        // Provide more specific error message based on the error
        if (error.response?.status === 400) {
            throw new Error(`Refresh token invalid or expired: ${JSON.stringify(error.response.data)}`);
        } else if (error.response?.status === 401) {
            throw new Error('Refresh token unauthorized. Re-authorization required.');
        } else {
            throw new Error(`Failed to refresh token: ${error.message}`);
        }
    }
}

/**
 * Exchanges authorization code for initial tokens
 */
async function exchangeCodeForTokens(authCode) {
    const credentials = await getCredentials();
    
    const params = new URLSearchParams({
        grant_type: 'authorization_code',
        code: authCode,
        client_id: credentials.CLIENT_ID,
        client_secret: credentials.CLIENT_SECRET,
        redirect_uri: credentials.REDIRECT_URI
    });

    try {
        const response = await axios.post(CONFIG.EXACT_TOKEN_URL, params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const now = Date.now();
        
        // Store initial tokens
        tokenStore.access_token = response.data.access_token;
        tokenStore.refresh_token = response.data.refresh_token;
        tokenStore.expires_at = now + (response.data.expires_in * 1000);
        tokenStore.last_refresh = now;

        // Store refresh token in Key Vault
        await storeRefreshToken(response.data.refresh_token);

        console.log('Initial tokens obtained successfully');
        
        return response.data;
    } catch (error) {
        console.error('Token exchange failed:', error.response?.data || error.message);
        throw new Error('Failed to exchange authorization code for tokens');
    }
}

// Initialize token store when the app starts
initializeTokenStore().catch(console.error);

// Azure Function: Get valid access token
app.http('getToken', {
    methods: ['GET'],
    authLevel: 'function',
    handler: async (request, context) => {
        try {
            // Check if we have a valid token
            if (isTokenValid()) {
                return {
                    status: 200,
                    jsonBody: {
                        access_token: tokenStore.access_token,
                        expires_at: tokenStore.expires_at,
                        status: 'valid'
                    }
                };
            }

            // Try to refresh the token
            if (tokenStore.refresh_token || await getStoredRefreshToken()) {
                context.log('Attempting to refresh token...');
                try {
                    const newToken = await refreshAccessToken();
                    context.log('Token refresh successful');
                    return {
                        status: 200,
                        jsonBody: {
                            access_token: newToken,
                            expires_at: tokenStore.expires_at,
                            status: 'refreshed'
                        }
                    };
                } catch (refreshError) {
                    context.log.error('Token refresh failed:', refreshError.message);
                    // Fall through to return authorization required error
                }
            }

            // No tokens available - need authorization
            const credentials = await getCredentials();
            return {
                status: 401,
                jsonBody: {
                    error: 'No valid tokens available',
                    message: 'Initial authorization required',
                    auth_url: `${CONFIG.EXACT_AUTH_URL}?client_id=${credentials.CLIENT_ID}&redirect_uri=${encodeURIComponent(credentials.REDIRECT_URI)}&response_type=code`
                }
            };

        } catch (error) {
            console.error('Error in getToken:', error.message);
            return {
                status: 500,
                jsonBody: {
                    error: 'Internal server error',
                    message: error.message
                }
            };
        }
    }
});

// Azure Function: Handle OAuth callback and exchange code for tokens
app.http('authorize', {
    methods: ['GET', 'POST'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        try {
            const authCode = request.query.get('code') || request.body?.code;
            
            if (!authCode) {
                return {
                    status: 400,
                    jsonBody: {
                        error: 'Missing authorization code',
                        message: 'Authorization code is required'
                    }
                };
            }

            const tokens = await exchangeCodeForTokens(authCode);
            
            return {
                status: 200,
                jsonBody: {
                    message: 'Authorization successful',
                    access_token: tokens.access_token,
                    expires_in: tokens.expires_in,
                    token_type: tokens.token_type
                }
            };

        } catch (error) {
            console.error('Error in authorize:', error.message);
            return {
                status: 500,
                jsonBody: {
                    error: 'Authorization failed',
                    message: error.message
                }
            };
        }
    }
});

// Azure Function: Get authorization URL for initial setup
app.http('authUrl', {
    methods: ['GET'],
    authLevel: 'function',
    handler: async (request, context) => {
        try {
            const credentials = await getCredentials();
            
            const authUrl = `${CONFIG.EXACT_AUTH_URL}?client_id=${credentials.CLIENT_ID}&redirect_uri=${encodeURIComponent(credentials.REDIRECT_URI)}&response_type=code`;
            
            return {
                status: 200,
                jsonBody: {
                    auth_url: authUrl,
                    instructions: 'Visit this URL to authorize the application'
                }
            };

        } catch (error) {
            return {
                status: 500,
                jsonBody: {
                    error: 'Configuration error',
                    message: error.message
                }
            };
        }
    }
});

// Azure Function: Health check and token status
app.http('status', {
    methods: ['GET'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        const now = Date.now();
        const hasTokens = !!tokenStore.access_token;
        const isValid = isTokenValid();
        const canRefresh = canRefreshToken();
        
        return {
            status: 200,
            jsonBody: {
                service: 'Exact Online Authentication Gateway',
                timestamp: new Date().toISOString(),
                token_status: {
                    has_tokens: hasTokens,
                    is_valid: isValid,
                    can_refresh: canRefresh,
                    expires_at: tokenStore.expires_at ? new Date(tokenStore.expires_at).toISOString() : null,
                    last_refresh: tokenStore.last_refresh ? new Date(tokenStore.last_refresh).toISOString() : null
                },
                keyvault_status: {
                    url: KEY_VAULT_URL,
                    credentials_cached: !!credentialsCache.CLIENT_ID
                }
            }
        };
    }
});

module.exports = { app };