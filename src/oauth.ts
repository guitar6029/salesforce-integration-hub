import { createHash, randomBytes } from "node:crypto";
import type { SalesforceConfig } from "./config.js";

export interface OAuthTransaction {
    state: string;
    verifier: string;
    createdAt: number;
}

/** Create a high-entropy state and PKCE S256 pair for one authorization attempt. */
export function createOAuthTransaction(now = Date.now()): OAuthTransaction {
    const verifier = randomBytes(32).toString("base64url");
    return {
        state: randomBytes(32).toString("base64url"),
        verifier,
        createdAt: now,
    };
}

export function buildAuthorizationUrl(
    config: SalesforceConfig,
    transaction: OAuthTransaction,
): URL {
    const url = new URL("/services/oauth2/authorize", config.loginUrl);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", config.callbackUrl);
    url.searchParams.set("state", transaction.state);
    url.searchParams.set(
        "code_challenge",
        createHash("sha256").update(transaction.verifier).digest("base64url"),
    );
    url.searchParams.set("code_challenge_method", "S256");
    return url;
}
