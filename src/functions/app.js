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
        console.log('Attempting to retrieve refresh token from Key Vault...');
        const secret = await secretClient.getSecret('exact-refresh-token');
        console.log('Refresh token retrieved from Key Vault:', {
            hasValue: !!secret.value,
            valueLength: secret.value ? secret.value.length : 0,
            secretName: secret.name,
            properties: {
                enabled: secret.properties?.enabled,
                createdOn: secret.properties?.createdOn,
                updatedOn: secret.properties?.updatedOn
            }
        });
        return secret.value;
    } catch (error) {
        console.error('Failed to retrieve refresh token from Key Vault:', {
            message: error.message,
            code: error.code,
            statusCode: error.statusCode
        });
        return null;
    }
}

/**
 * Initialize token store from Key Vault on startup
 */
async function initializeTokenStore() {
    console.log('Initializing token store from Key Vault...');
    console.log('Initial token store state:', {
        hasAccessToken: !!tokenStore.access_token,
        hasRefreshToken: !!tokenStore.refresh_token,
        expiresAt: tokenStore.expires_at,
        lastRefresh: tokenStore.last_refresh
    });
    
    try {
        const storedRefreshToken = await getStoredRefreshToken();
        if (storedRefreshToken) {
            tokenStore.refresh_token = storedRefreshToken;
            console.log('Refresh token loaded from Key Vault into memory');
            console.log('Updated token store state:', {
                hasAccessToken: !!tokenStore.access_token,
                hasRefreshToken: !!tokenStore.refresh_token,
                expiresAt: tokenStore.expires_at,
                lastRefresh: tokenStore.last_refresh
            });
        } else {
            console.log('No refresh token found in Key Vault during initialization');
        }
    } catch (error) {
        console.error('Failed to initialize token store:', {
            message: error.message,
            stack: error.stack
        });
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
    
    console.log('canRefreshToken check:', {
        now: new Date(now).toISOString(),
        lastRefresh: tokenStore.last_refresh ? new Date(tokenStore.last_refresh).toISOString() : 'never',
        timeSinceLastRefresh: timeSinceLastRefresh,
        minRefreshInterval: CONFIG.MIN_REFRESH_INTERVAL,
        canRefresh: timeSinceLastRefresh >= CONFIG.MIN_REFRESH_INTERVAL
    });
    
    // If last_refresh is 0 (never refreshed), allow refresh
    if (tokenStore.last_refresh === 0) {
        console.log('Never refreshed before, allowing refresh');
        return true;
    }
    
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
        console.error('Refresh blocked by time constraint');
        throw new Error('Cannot refresh token yet. Must wait 9.5 minutes between refreshes.');
    }

    const credentials = await getCredentials();
    console.log('Credentials loaded for refresh:', {
        hasClientId: !!credentials.CLIENT_ID,
        hasClientSecret: !!credentials.CLIENT_SECRET,
        hasRedirectUri: !!credentials.REDIRECT_URI,
        redirectUri: credentials.REDIRECT_URI
    });
    
    const params = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokenStore.refresh_token,
        client_id: credentials.CLIENT_ID,
        client_secret: credentials.CLIENT_SECRET,
        redirect_uri: credentials.REDIRECT_URI
    });
    
    console.log('Refresh request parameters:', {
        grant_type: 'refresh_token',
        hasRefreshToken: !!tokenStore.refresh_token,
        refreshTokenLength: tokenStore.refresh_token ? tokenStore.refresh_token.length : 0,
        clientId: credentials.CLIENT_ID,
        redirectUri: credentials.REDIRECT_URI,
        tokenUrl: CONFIG.EXACT_TOKEN_URL
    });

    try {
        console.log('Sending refresh request to:', CONFIG.EXACT_TOKEN_URL);
        const response = await axios.post(CONFIG.EXACT_TOKEN_URL, params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        console.log('Refresh response received:', {
            status: response.status,
            hasAccessToken: !!response.data?.access_token,
            hasRefreshToken: !!response.data?.refresh_token,
            expiresIn: response.data?.expires_in
        });

        const now = Date.now();
        
        // Update token store
        tokenStore.access_token = response.data.access_token;
        tokenStore.refresh_token = response.data.refresh_token;
        tokenStore.expires_at = now + (response.data.expires_in * 1000);
        tokenStore.last_refresh = now;

        // Store new refresh token in Key Vault
        await storeRefreshToken(response.data.refresh_token);

        console.log('Tokens refreshed successfully', {
            expiresAt: new Date(tokenStore.expires_at).toISOString(),
            lastRefresh: new Date(tokenStore.last_refresh).toISOString()
        });
        
        return tokenStore.access_token;
    } catch (error) {
        console.error('Token refresh failed - Full error details:', {
            message: error.message,
            code: error.code,
            response: {
                status: error.response?.status,
                statusText: error.response?.statusText,
                data: error.response?.data,
                headers: error.response?.headers
            },
            request: {
                method: error.config?.method,
                url: error.config?.url,
                headers: error.config?.headers,
                data: error.config?.data
            }
        });
        
        // Provide more specific error message based on the error
        if (error.response?.status === 400) {
            const errorData = error.response.data;
            console.error('400 Bad Request details:', errorData);
            
            // Check for specific error codes from Exact Online
            if (errorData?.error === 'invalid_grant') {
                throw new Error(`Refresh token is invalid or expired. Re-authorization required. Details: ${JSON.stringify(errorData)}`);
            }
            throw new Error(`Refresh request rejected: ${JSON.stringify(errorData)}`);
        } else if (error.response?.status === 401) {
            throw new Error('Refresh token unauthorized. Re-authorization required.');
        } else if (error.response?.status === 403) {
            throw new Error('Refresh forbidden. Check client credentials and permissions.');
        } else if (!error.response) {
            throw new Error(`Network error during refresh: ${error.message}`);
        } else {
            throw new Error(`Failed to refresh token: ${error.message} (Status: ${error.response?.status})`);
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
console.log('Starting Exact Online Auth Gateway...');
console.log('Environment configuration:', {
    keyVaultUrl: KEY_VAULT_URL,
    exactTokenUrl: CONFIG.EXACT_TOKEN_URL,
    exactAuthUrl: CONFIG.EXACT_AUTH_URL,
    minRefreshInterval: CONFIG.MIN_REFRESH_INTERVAL,
    tokenBuffer: CONFIG.TOKEN_BUFFER
});

initializeTokenStore().catch(error => {
    console.error('Failed to initialize token store:', error);
});

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
            context.log('Token invalid or missing, checking refresh capability...');
            const hasRefreshTokenInMemory = !!tokenStore.refresh_token;
            const refreshTokenFromVault = hasRefreshTokenInMemory ? null : await getStoredRefreshToken();
            
            context.log('Refresh token check:', {
                hasRefreshTokenInMemory,
                foundRefreshTokenInVault: !!refreshTokenFromVault,
                canAttemptRefresh: hasRefreshTokenInMemory || !!refreshTokenFromVault
            });
            
            if (hasRefreshTokenInMemory || refreshTokenFromVault) {
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
                    context.log('ERROR: Token refresh failed:', {
                        error: refreshError.message,
                        stack: refreshError.stack
                    });
                    // Fall through to return authorization required error
                }
            } else {
                context.log('No refresh token available in memory or Key Vault');
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