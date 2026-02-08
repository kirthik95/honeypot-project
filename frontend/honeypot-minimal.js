(() => {
  const API_URL = "http://127.0.0.1:5000/api/track";
  const sessionId = crypto.randomUUID();

  const session = {
    start: Date.now(),
    mouse: 0,
    keys: 0,
    focus: 0,
    paste: 0
  };

  document.addEventListener("mousemove", () => session.mouse++);
  document.addEventListener("keydown", () => session.keys++);

  document.querySelectorAll("input").forEach(i => {
    i.addEventListener("focus", () => session.focus++);
    i.addEventListener("paste", () => session.paste++);
  });

  const form = document.getElementById("loginForm");
  if (!form) return;

  form.addEventListener("submit", async e => {
    e.preventDefault();

    const data = new FormData(form);
    const time = (Date.now() - session.start) / 1000;

    const payload = {
      session_id: sessionId,
      mouse_movements: session.mouse,
      keystrokes: session.keys,
      focus_events: session.focus,
      paste_events: session.paste,
      time_to_submit: time,
      rapid_submission: time < 3 ? 1 : 0,
      honeypot_filled: 0,
      honeypot_total_length: 0,
      email_length: (data.get("email") || "").length,
      password_length: (data.get("password") || "").length,
      cookies_enabled: navigator.cookieEnabled ? 1 : 0
    };

    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const result = await res.json();

    if (result.success && result.is_attack) {
      window.location.href = "/processing.html";
    } else {
      alert("Login successful (demo mode)");
    }
  });
})();
