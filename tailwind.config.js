const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

module.exports = {
  content: ["./public/**/*.html", "./src/**/*.{js,jsx,mjs}"],
  theme: {
    extend: {
      colors: {
        paper: token("paper"),
        surface: token("surface"),
        ink: token("ink"),
        muted: token("muted"),
        line: token("line"),
        seal: token("seal"),
        "seal-ink": token("seal-ink"),
        mint: token("mint"),
        alert: token("alert"),
        "alert-tint": token("alert-tint"),
        caution: token("caution"),
        "caution-tint": token("caution-tint"),
      },
      fontFamily: {
        sans: ["system-ui", "-apple-system", "Segoe UI", "Roboto", "Noto Sans", "Helvetica Neue", "Arial", "sans-serif"],
        figures: ["ui-rounded", "SF Pro Rounded", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
      },
    },
  },
  plugins: [],
};
