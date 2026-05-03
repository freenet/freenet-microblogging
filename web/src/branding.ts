// Consumer-facing branding loaded once from `web/branding/app.json`.
// Single source of truth for the product name, shared with any future
// test suites that read the same file.
import branding from "../branding/app.json";
import logoUrl from "../branding/raven-logo.svg?url";

export const APP_NAME: string = branding.name;
export const APP_LOGO_URL: string = logoUrl;
