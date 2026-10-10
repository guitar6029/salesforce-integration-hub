import { randomBytes } from "node:crypto";
import express, { type Express } from "express";
import session from "express-session";
import { loadConfig, type SalesforceConfig } from "./config.js";
import { buildAuthorizationUrl, createOAuthTransaction } from "./oauth.js";

declare module "express-session" {
    interface SessionData {
        oauthTransaction?: ReturnType<typeof createOAuthTransaction>;
    }
}

export interface AppOptions {
    loadConfig?: () => SalesforceConfig;
}

const transactionLifetimeMs = 5 * 60 * 1000;

export function createApp(options: AppOptions = {}): Express {
    const app = express();
    const getConfig = options.loadConfig ?? loadConfig;

    app.disable("x-powered-by");
    app.use(session({
        // A process-local random key keeps the session cookie signed. OAuth data is stored
        // in the server-side session store, never in the browser cookie.
        secret: randomBytes(32).toString("hex"),
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: transactionLifetimeMs,
        },
    }));

    app.get("/health", (_request, response) => {
        response.json({ status: "ok" });
    });

    app.get("/oauth/authorize", (request, response) => {
        if (request.session.oauthTransaction) {
            response.status(409).json({
                error: "An OAuth authorization is already in progress for this session.",
            });
            return;
        }

        try {
            const config = getConfig();
            const transaction = createOAuthTransaction();
            request.session.oauthTransaction = transaction;
            response.redirect(buildAuthorizationUrl(config, transaction).toString());
        } catch {
            response.status(503).json({ error: "OAuth authorization is unavailable." });
        }
    });

    return app;
}
