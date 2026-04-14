/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        phish: {
          red: '#EF4444',
          amber: '#F59E0B',
          green: '#22C55E',
          dark: '#0F172A',
          card: '#1E293B',
          border: '#334155',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
