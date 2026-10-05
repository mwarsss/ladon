// Build-time Tailwind config for the scenario dashboard. Rebuild with scripts/build_css.sh.
// Every colour points at a web/theme.css token, so the page follows light/dark.
const scale = (name) => Object.fromEntries([50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950]
  .map((s) => [s, `oklch(var(--${name}-${s}) / <alpha-value>)`]));

module.exports = {
  content: ["./web/index.html", "./web/app.js"],
  // The outcome banner builds these class names at runtime from its tone.
  safelist: ["rose", "emerald", "sky"].flatMap((t) => [`bg-${t}-500/10`, `border-${t}-500`, `text-${t}-400`]),
  theme: {
    extend: {
      colors: {
        slate: scale("n"), gray: scale("n"),
        emerald: scale("safe"), green: scale("safe"), teal: scale("safe"),
        rose: scale("loss"), red: scale("loss"),
        amber: scale("hold"), yellow: scale("hold"),
        cyan: scale("ink"), sky: scale("ink"), purple: scale("ink"), indigo: scale("ink"),
        white: "oklch(var(--hi) / <alpha-value>)",
        onfill: "#ffffff",
      },
      fontFamily: {
        sans: ["Public Sans", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
        display: ["Archivo", "Arial Narrow", "sans-serif"],
      },
      borderRadius: { lg: "3px", xl: "4px", "2xl": "4px" },
      boxShadow: { sm: "none", DEFAULT: "none", md: "none", lg: "none", xl: "none", "2xl": "none" },
    },
  },
};
