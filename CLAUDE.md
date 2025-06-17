# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an Azure Functions application that serves as an OAuth 2.0 authentication gateway between Azure Data Factory and Exact Online's API. It handles token management, automatic refresh, and respects Exact Online's strict 9.5-minute refresh interval requirement.

## Development Commands

```bash
# Install dependencies
npm install

# Run locally (requires Azure Functions Core Tools)
npm start
# or
func start

# No tests or linting configured - test script exits with 0
```

## Architecture & Key Concepts

### Single-File Architecture
All application logic is contained in `src/functions/app.js`. This includes:
- 4 HTTP-triggered endpoints (getToken, authUrl, authorize, status)
- Token management with in-memory caching
- Azure Key Vault integration for secrets
- OAuth 2.0 flow implementation

### Critical Implementation Details

1. **Token Refresh Logic**: The application enforces a 9.5-minute minimum between token refreshes (Exact Online requirement). When implementing changes to token refresh, ensure this constraint is maintained.

2. **Key Vault Integration**: All secrets are stored in Azure Key Vault. The application uses DefaultAzureCredential with credential caching (5-minute cache) to minimize Key Vault calls.

3. **Error Handling Pattern**: Functions return structured error responses with helpful messages for common scenarios (missing tokens, initial setup needed).

### Environment Configuration

For local development, create a `.env` file with:
```
AZURE_KEYVAULT_URL=https://your-keyvault.vault.azure.net/
EXACT_ONLINE_BASE_URL=https://start.exactonline.nl
EXACT_ONLINE_AUTH_URL=https://start.exactonline.nl/api/oauth2/auth
EXACT_ONLINE_TOKEN_URL=https://start.exactonline.nl/api/oauth2/token
```

### Azure Functions Configuration

- Runtime: Node.js v18+ (targeting v22)
- Function timeout: 5 minutes (configured in host.json)
- Application Insights sampling enabled
- Extension bundle v4-5

### Key Dependencies

- `@azure/functions` - Azure Functions runtime
- `@azure/identity` - Azure authentication 
- `@azure/keyvault-secrets` - Secret management
- `axios` - HTTP client for Exact Online API calls
- `dotenv` - Local environment variables

## When Making Changes

1. **Token Management**: Any changes to token refresh logic must respect the 9.5-minute minimum refresh interval
2. **Error Responses**: Maintain consistent error response format with status codes and helpful messages
3. **Key Vault Access**: Use the existing credential caching pattern to avoid excessive Key Vault calls
4. **Logging**: Use context.log for Azure Functions logging that integrates with Application Insights