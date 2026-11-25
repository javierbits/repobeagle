document.cookie = "session=" + id + "; path=/";
localStorage.setItem("visitor", fingerprint);
fetch("https://api.widget.dev/v1/ping");
Sentry.init({ dsn: 'https://k@o1.ingest.sentry.io/1', sendDefaultPii: true });
