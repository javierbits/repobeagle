document.cookie = "session=" + id + "; path=/";
localStorage.setItem("visitor", fingerprint);
fetch("https://api.widget.dev/v1/ping");
