**Enhancing Intelligent Authentication:**
Bussiness either offer a service or resource. Bussiness is resposible for producing those services or resources but bussiness doesn't want to handle access control so they delegate access control to a access management solution like pingam or ibm security verify access or any other. An access management solutions control access to a service/resource through:
1- **Authentication:** Verifies the identity of a user or a digital entity
2- **Authorization:** Determines whether a specific user has sufficient privileges to access a protected resource

**AM Authentication:**
- AM uses authentication to verify  a user or an entity's identity
- The result of successful authentication is an am session stored in an **SSOToken**.
- The **SSOTOKENID** which is a refrence to the session is used to identify the user to all AM-enabled edge devices
 




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

---
# Oauth2 Client Authentication Methods

Clients need to authenticate against the authorization server, and there are different ways to do that. Client authentication is required when confidential clients need to connect to a protected endpoint, e.g., authorization or token.

* Form Parameters
* Authorization Headers
* JWT Profiles
* mTLS

---

## Form Parameters

* Client secret shared by client and auth server
* Configuration in AM: `client-secret-post` method
* `curl --request POST --data client_id=clientid --data client_secret=anysecret ... https://myam.example.com/login/oauth2/access_token`

---

## Authorization Headers

* Client secret shared by client and auth server
* Configuration in AM: `client-secret-basic` method
* Uses a basic authorization header to provide the secret and the header value is base64 encoded in such a way that `base64(clientid:clientsecret)`
* `curl --request POST --header "Authorization: Basic bxdfasfsdfsfsx=*" ... "https://myam.example.com/login/oauth2/access_token"`

---

## JWT Profiles

* Provides a signed JWT client assertion to prove identity
* Configuration in AM: `private_key_jwt`
* Uses a "client assertion" parameter to provide JWT
* `curl --request POST --data client_id=myclient --data client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer --data client_assertion=jwttoken ... "https://myam.example.com/login/oauth2/access_token"`
* Usually assertion generated by client as shown in the example:
    ```json
    {
      "iss": "myclient",
      "sub": "myclient",
      "aud": "[https://myam.example.com/login/oauth2/access_token](https://myam.example.com/login/oauth2/access_token)",
      "jti": "id012345",
      "exp": 243342342
    }
    ```
* The assertion is a signed JWT which means client used its private key to sign the assertion so the AM server needs to have the public key to verify the signature which can be configured in AM as follows:
    * as an x.509 cert
    * as a public url containing keys
    * as a json web key set
    * which can be configured in signing and encryption section in AM under a client profile

---

## Mutual Transport Layer Security

* Both client and server make use of the TLS connection providing the certs. Clients provide identity by providing its cert to the server and server also does the same
* Configuration in AM : `tls_client_auth` or `self_signed_tls_client_auth`
* `curl --request POST --data client_id=myclient --cert=clientcert.pem --key=clientkey.pem ... "https://myam.example.com/login/oauth2/access_token"`
* AM knows that the certificate is sent by a specific client by using its `client_id` parameter
* Client cert contains a DN
* The DN needs to be registered for that particular client in AM
* Cert is valid only if the cert is provided by a Trusted CA trusted by both client and auth server and the register DN corresponds to the DN in the cert
* The variables or options to be taken care of in mTLS:
    * In Advanced select mTLS:
        * Token Endpoint Authentication Method = `tls_client_auth`
    * In signing and encryption:
        * MTLS SUBJECT DN should match the ones in the cert:

### Self Signed Certs in mTLS

* Client registers an X.509 cert with its profile in AM
* Cert is valid only if the cert provided by client matches exactly the cert specified in the client profile in AM
* The cert can be configured in AM using method `self_signed_tls_client_authentication` option in advanced tab under profile and the cert can be provided in three ways:
    * using jwk uri
    * using jwk
    * or uploading the content of cert in option `mtls self signed cert`

----------------------------------------------------
---
# Transforming OAuth2 Tokens

* **Security tokens** contain information related to security and identity.
* ForgeRock AM comes with **OAuth2 Token Exchange**, which is responsible for issuing tokens. AM, when configured as an authorization server, is responsible for exchanging different types of tokens:
    * Access tokens for new access tokens
    * Access tokens for ID tokens
    * ID tokens for new ID tokens
    * ID tokens for access tokens

The reason for exchanging these tokens lies in the scope. For example, when an authenticated client requested an ID token and now wants to perform some operation on a resource, the client can exchange that ID token for a new access token as the scope of the work has changed.

---

## Types of Exchanged Tokens

* **Subject Token**: Represents the identity for whom the request is made. E.g., Raju.
* **Exchanged Token**: The new token that is the result of token exchange.
* **Actor Token**: Represents the identity of the acting party. E.g., a Bot acting on behalf of Raju.

**Scenario Example:**

Alice (user) → gives her token (subject token) → asks for access to a new system.
The auth server → verifies and issues a new token (exchange token).
If needed, it can also say "This request is being made by a system or service on behalf of Alice" (actor token).

---

## Reason for Token Exchange

A client may want to exchange tokens for:

* **Impersonation**
    * Used by a client to act as a subject on another client.
    * Has a subject token.
* **Delegation**
    * Used by a subject to act on behalf of another subject.
    * Has a subject and actor token. The actor identity is stored in the `'act'` claim.

---

## Token Exchange with AM

* Copies claims and values that must stay the same, from the subject token into the new token.
* Derives scopes from the scope implementation used in OAuth2/OIDC grant types flows.
* Adds the `act` and `may_act` claims.

---

## Token Scopes and Claims

When requesting a token, a client can indicate on which desired target services it intends to use that token by using the `"audience"` and `"resource"` parameters and the desired scope of the requested token using the `"scope"` parameter.

### `may_act` Claim

The `may_act` claim is a part of the subject token that specifies:

* Who may act on behalf of the client.
* Acts as a condition for the authorization server issuing exchange tokens where:
    * The client making the exchange must be authorized in the claim.
    * The subject of the actor token must also be authorized in the claim of the subject token (delegation).

### `act` Claim

The `act` claim is part of the exchanged token:

* Identifies the party acting on behalf of the token's subject.
* Expresses that delegation has occurred.

---

## Token Restriction and Expansion

* Exchanged token scopes and claims do not necessarily need to be the ones in the original subject tokens.
* Exchanged token scopes and claims can be expanded or restricted.

-----------------------------------------------

# SAML

SAML (Security Assertion Markup Language) is an XML-based open standard for exchanging authentication and authorization data between parties, particularly between an Identity Provider (IdP) and a Service Provider (SP). It enables Single Sign-On (SSO), allowing users to log in once and access multiple services without re-entering credentials.

---

## Key Components of SAML

### 1. SAML Assertions

SAML assertions are XML documents that carry authentication, authorization, and attribute information about a user. There are three types:

* **Authentication Assertion**: Confirms that the user has been authenticated (e.g., via username/password, MFA).
* **Attribute Assertion**: Provides user attributes (e.g., email, role, department).
* **Authorization Decision Assertion**: Specifies whether the user is allowed/denied access to a resource.
### 2. Metadata

XML files exchanged between IdP and SP to establish trust.

Contains:

* Entity IDs
* Certificate for signing/encryption
* Endpoint URLs (SSO, SLO)
### 3. Circle of Trust
* The entities that are part of the system and those have agreed to build a trust on 
### 4. SAML Protocol Objects

These define how SAML requests and responses are exchanged:

* **SAML Authentication Request  (AuthnRequest)**
    * Initiated by the Service Provider (SP) to request authentication from the Identity Provider (IdP).
* **SAML Response**
    * Sent by the IdP to the SP containing the user’s authentication status and attributes.
* **SAML Single Logout (SLO)**
    * Allows a user to log out from all connected services at once.
      ![image](https://github.com/user-attachments/assets/81c078ee-d921-41d2-8626-6b72b9707162)


### 5. SAML Bindings

These define how SAML messages are transported between entities:

* **HTTP Redirect Binding**
    * SAML messages are sent via URL parameters (limited size).
* **HTTP POST Binding**
    * SAML messages are sent in an HTML form (used for larger assertions).
    ![image](https://github.com/user-attachments/assets/11a7c044-dd09-4c41-bc7f-089d3aa586e3)

* **SAML SOAP Binding**
    * Uses SOAP (Simple Object Access Protocol) for web services.
* **SAML Artifact Binding**
    * Uses a reference (artifact) instead of sending the full SAML message.
    ![image](https://github.com/user-attachments/assets/b9a56bbd-98bd-4e5e-b3f4-fa9329244dda)

### 6. SAML Roles

* **Identity Provider (IdP)**
    * Authenticates users and issues SAML assertions (e.g., Okta, Azure AD, ADFS).
* **Service Provider (SP)**
    * Relies on the IdP for authentication (e.g., Salesforce, AWS, Gmail).
* **Principal (User)**
    * The entity trying to access a service.

### Federation 

---

## How SAML Works (SSO Flow)

1.  User tries to access a Service Provider (SP).
2.  SP generates a SAML AuthnRequest and redirects the user to the IdP.
3.  IdP authenticates the user (e.g., via password, MFA).
4.  IdP sends back a SAML Response (assertion) to the SP.
5.  SP validates the assertion and grants access.

---

## Advantages of SAML

* ✔ **Single Sign-On (SSO)** – Users log in once for multiple services.
* ✔ **Security** – Uses XML encryption and digital signatures.
* ✔ **Standardized** – Widely adopted in enterprise environments.
* ✔ **Federation** – Enables trust between different organizations (B2B).

---

## Use Cases

* Enterprise SSO (e.g., accessing Office 365 via Azure AD)
* Cloud application authentication (Salesforce, AWS)
* Federated identity (B2B collaborations)

## Explain the SAML2 flow from the IdP point of view
IDP Tasks during SAML2 SSO HTTP-POST profile:
1. Monitoring the SSO service endpoint for any incoming Authentication Requests
2. Validating the authentication request received from an SP
3. Authenticating end user
4. Creating an assertion
5. Sending the response
   
![image](https://github.com/user-attachments/assets/5dc809ca-7fe3-4919-980c-5e8d62051078)

- **SSO Service endpoint Receives an Authentication Request**:
    The IDP receives a SAML2 authentication request at its SSO service. The auth request are of two types:
     - SP initiated SSO:       SP redirects the end user to IDP endpoint with a SAML authentication request
     - IDP initiated SSO:      user redirected to specialized link on the idp instance. PingAM uses idpssoinit.jsp
