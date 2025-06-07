**OAuth2 Grant types:**  
These are different ways to acquire access tokens for different clients as these access tokens are used by clients to perform some action on the resources. The acquiring of these tokens depend upon the relationship between the clients and the resource owner.

Common Oauth2 grant types are:  
- Authorization code  
- Authorization code with PKCE  
- Client credentials  
- Device code  
- Implicit  
- Resource owner password credential  

---

## Authorization Code Grant (without PKCE)  
1. User opens client app and clicks Sign in.  
2. Client redirects user to Auth Server's Authorization Endpoint with:  
   - `response_type=code`  
   - `client_id`  
   - `redirect_uri`  
3. User authenticates on Auth Server.  
4. Auth Server redirects back to client with Authorization Code.  
5. Client sends Authorization Code to Token Endpoint with:  
   - `grant_type=authorization_code`  
   - `code`  
   - `redirect_uri`  
   - `client_id` and `client_secret`  
6. Auth Server validates the code and credentials.  
7. Auth Server issues Access Token (and optionally Refresh Token).  
8. Client uses Access Token to access protected resources.  

---

## Authorization Code with PKCE  
Similar to authorization code except that it uses code challenge and code verifier. When a user gets on the application/client and clicks sign in using OAuth2, the client generates the code challenge and code verifier. It stores the code verifier and sends the code challenge and code challenge method along with other parameters like redirect URI when redirecting to the auth server. The auth server prompts the user to login and once authentication is successful, it stores the code challenge and method, generates the auth code, and returns it to the client app. The client app then sends this auth code to the auth server again along with the code verifier. The auth server uses the challenge method and code verifier to generate the code challenge and matches it with the original one received earlier. If everything matches, the client is presented with an access token.  

### Full Flow:  
1. User opens the mobile app or SPA in browser.  
2. User clicks "Sign in with OAuth2".  
3. Client checks it doesn’t have a valid access token.  
4. Client generates a `code_verifier` (a high-entropy random string) and derives a `code_challenge` by hashing the `code_verifier` using the S256 method (SHA-256 and base64-url-encoded).  
5. Client stores the `code_verifier` locally (e.g., in memory or session storage), then redirects the user to the Authorization Endpoint of the Auth Server with parameters including:  
   - `response_type=code`  
   - `client_id`  
   - `redirect_uri`  
   - `code_challenge` (hashed verifier)  
   - `code_challenge_method=S256`  
6. Auth Server authenticates the user. Upon success, it stores the authorization code and associates it with the `code_challenge` and `code_challenge_method` (note: the server does not store the `code_verifier` itself).  
7. Auth Server sends back an Authorization Code to the client via the redirect URI (e.g., in the URL query parameters).  
8. Client receives the Authorization Code and makes a POST request to the Token Endpoint with:  
   - `grant_type=authorization_code`  
   - `code` (authorization code)  
   - `redirect_uri`  
   - `client_id`  
   - `code_verifier` (the original random string)  
9. Auth Server receives the `code_verifier` from the client, hashes it with the same method (S256), and compares it to the originally stored `code_challenge` for that auth code.  
10. If they match and the authorization code is valid and unused, the Auth Server issues an Access Token (and optionally a Refresh Token) to the client.  
11. Client uses the Access Token to access protected resources from the Resource Server.  

---

## Implicit Grant  
**Note:** Implicit Grant is mostly deprecated for security reasons in favor of Authorization Code with PKCE.  

1. User opens SPA and clicks Sign in.  
2. Client redirects user to Auth Server’s Authorization Endpoint with:  
   - `response_type=token`  
   - `client_id`  
   - `redirect_uri`  
3. User authenticates on Auth Server.  
4. Auth Server redirects back to client with Access Token in URL fragment (`#access_token=...`).  
5. Client extracts Access Token from URL and uses it directly to access protected resources.  
6. No Refresh Token is issued.  

---

## Client Credentials Grant  
1. Used for server-to-server communication, no user involved.  
2. Client sends a POST request directly to Token Endpoint with:  
   - `grant_type=client_credentials`  
   - `client_id` and `client_secret`  
3. Auth Server validates credentials.  
4. Auth Server issues Access Token.  
5. Client uses Access Token to access protected resources.  

---

## Resource Owner Password Credentials Grant  
**Note:** This flow is discouraged unless legacy or trusted environments.  

1. User provides username and password directly to the client app.  
2. Client sends a POST request to Token Endpoint with:  
   - `grant_type=password`  
   - `username`  
   - `password`  
   - `client_id` and `client_secret`  
3. Auth Server validates credentials.  
4. Auth Server issues Access Token (and optionally Refresh Token).  
5. Client uses Access Token to access protected resources.  

---

## Device Code Grant Flow (OAuth 2.0 Device Authorization Grant)  
1. Client requests a device code by POSTing to the Device Authorization Endpoint with:  
   - `client_id`  
   - (optional scopes)  
2. Auth Server responds with:  
   - `device_code`  
   - `user_code`  
   - `verification_uri` (URL where user enters the code)  
   - `expires_in`  
   - `interval` (polling interval)  
3. Client shows the `user_code` and `verification_uri` to the user, asking them to visit the URL on another device (like a browser on a PC or phone).  
4. User visits the verification URI in their browser and enters the `user_code`.  
5. User authenticates and approves the device access on the Auth Server.  
6. Client polls the Token Endpoint periodically with:  
   - `grant_type=device_code`  
   - `device_code`  
   - `client_id`  
7. Auth Server responds:  
   - If user hasn’t approved yet: `authorization_pending` error → client keeps polling.  
   - If user denied: `access_denied`.  
   - If approved and valid: returns Access Token (and optionally Refresh Token).  
8. Client uses Access Token to access protected resources.  

---

## Device Code Grant Flow with PKCE (Extension)  
1. Client generates a `code_verifier` and `code_challenge` as in PKCE flow.  
2. Client requests a device code by POSTing to Device Authorization Endpoint with:  
   - `client_id`  
   - `code_challenge`  
   - `code_challenge_method` (usually S256)  
3. Auth Server responds with `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval`.  
4. Client displays `user_code` and `verification_uri` to the user.  
5. User visits verification URI and authenticates & approves.  
6. Client polls the Token Endpoint with:  
   - `grant_type=device_code`  
   - `device_code`  
   - `client_id`  
   - `code_verifier`  
7. Auth Server hashes `code_verifier` to verify it matches the earlier `code_challenge` stored with the device code.  
8. If matched and authorized, Auth Server returns Access Token (and optionally Refresh Token).  
9. Client uses Access Token to access protected resources.  

---

# OpenID Connect  
- OIDC is an identity layer on top of OAuth2 protocol.  
- Asserts the identity of the end user.  
- More focused on identity authentication part.  
- Protocol designed for SSO and user profile sharing.  
- Implements authentication as an extension of OAuth2 authorization by:  
  - Requesting scope `openid` in the authorization request.  
  - Returning a JWT called ID Token in addition to access token.  

---

## OIDC Token  
- It is an identity token issued by the identity provider.  
- It is a JSON Web Token (JWT) which is signed (must) and encrypted (optional).  
- It asserts the identity of the end user.  
- Endpoint: `/oauth2/idtokeninfo`.  
- Contains claims about the authentication of the user and who issued it.  

---

## Scopes and Claims in OIDC  
- **Scope**: What identity data can a client request.  
  Scopes like permissions the app asks for.  
  - Example scopes:  
    - `openid` (just to log you in).  
    - `profile` (to get your name, picture, etc.).  
    - `email` (to get your email).  
  - So scopes = what info the app is asking for.  

- **Claim**: What identity data a user has received.  
  Claims are the actual user information sent back to the app.  
  - Example claims:  
    ```json
    {
      "name": "Alice Johnson",
      "email": "alice@example.com",
      "email_verified": true
    }
    ```  
  - Each piece of data (name, email, etc.) is called a claim.  
  - So claims = the user info returned.  

Scopes and claims in the ID token provide information about the end user, what they have requested, what permissions they have, and what they are allowed to do.  

---

# OAuth2 Client Authentication Methods  
Clients need to authenticate against the authorization server, and there are different ways to do that. Client authentication is required when a confidential client needs to connect to a protected endpoint (e.g., authorization or token).  

## Form Parameters  
1. Client secret shared by client and auth server.  
2. Configuration in AM: `client-secret-post` method.  
3. Example:  
   ```bash
   curl --request POST --data client_id=clientid --data client_secret=anysecret ... https://myam.example.com/login/oauth2/access_token
