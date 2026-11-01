// Site configuration. Everything here is public; never put secrets in this file.
window.TERRAGUARD_CONFIG = {
  repo: "Karthik-099/TERRAGUARD",

  // Serve the editor, graph and Markdown libraries from this origin instead of
  // a CDN (the Docker image sets "vendor" so air-gapped installs work).
  assetsBase: "",

  // Public anonymous usage counters (numbers only, never code). Deploy
  // stats-worker/ to Cloudflare and paste its URL, e.g.
  // "https://terraguard-stats.<your-subdomain>.workers.dev". Empty = off.
  statsUrl: "",

  // GitHub Discussions embed via giscus (https://giscus.app). Enable Discussions
  // on the repo, install the giscus app, then copy the two IDs from giscus.app.
  giscus: { repoId: "", categoryId: "", category: "General" },
};
