/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: 'rgb(var(--base) / <alpha-value>)',
          raised: 'rgb(var(--base-raised) / <alpha-value>)',
          panel: 'rgb(var(--base-panel) / <alpha-value>)',
          border: 'rgb(var(--base-border) / <alpha-value>)',
        },
        ink: {
          DEFAULT: 'rgb(var(--ink) / <alpha-value>)',
          muted: 'rgb(var(--ink-muted) / <alpha-value>)',
        },
        accent: {
          DEFAULT: 'rgb(var(--accent) / <alpha-value>)',
        },
        sev: {
          critical: 'rgb(var(--sev-critical) / <alpha-value>)',
          high: 'rgb(var(--sev-high) / <alpha-value>)',
          medium: 'rgb(var(--sev-medium) / <alpha-value>)',
          low: 'rgb(var(--sev-low) / <alpha-value>)',
          info: 'rgb(var(--sev-info) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        display: ['Baloo 2', 'Comfortaa', 'ui-rounded', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'IBM Plex Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '8px',
      },
    },
  },
  plugins: [],
}
