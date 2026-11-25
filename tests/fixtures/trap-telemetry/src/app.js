import posthog from "posthog-js";
import * as Sentry from "@sentry/browser";
import { FullStory } from "fullstory";

posthog.init("phc_example", { api_host: "https://eu.i.posthog.com" });
Sentry.init({ dsn: "https://key@o1.ingest.sentry.io/42" });
FullStory.init({ orgId: "EXAMPLE" });

const script = document.createElement("script");
script.src = "https://www.googletagmanager.com/gtag/js?id=G-EXAMPLE1";
document.head.appendChild(script);
posthog.identify(user.id, { email: user.email });
