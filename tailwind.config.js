/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,jsx,ts,tsx}",
    "./components/**/*.{js,jsx,ts,tsx}"
  ],
  presets: [require("nativewind/preset")],
  theme: {
    extend: {
      colors: {
        primary: "#0069ff",
        "primary-dark": "#0052cc",
        "primary-light": "#4d94ff",
        "slate-dark": "#031b4e",
        "slate-mid": "#1e3a6e",
        background: "#f3f5f9"
      }
    }
  },
  plugins: []
};
