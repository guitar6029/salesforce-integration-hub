import { pathToFileURL } from "node:url";
import { createApp } from "./app.js";

export function getStartupMessage(): string {
    return "Salesforce Integration Hub starting...";
}

export function startServer(): void {
    const port = Number(process.env.PORT ?? 3000);
    createApp().listen(port, () => {
        console.log(getStartupMessage());
    });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    startServer();
}
