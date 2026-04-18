/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base:    '#080c14',
          surface: '#0d1117',
          raised:  '#131d2e',
          overlay: '#1a2540',
        },
        border: {
          DEFAULT: '#1e2d45',
          subtle:  '#161f30',
          strong:  '#2a3f5f',
        },
        text: {
          primary:   '#e2e8f0',
          secondary: '#8899aa',
          muted:     '#4a5568',
          inverted:  '#080c14',
        },
        accent: {
          50: '#eff6ff', 100: '#dbeafe', 200: '#bfdbfe', 300: '#93c5fd',
          400: '#60a5fa', 500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8',
          800: '#1e40af', 900: '#1e3a8a', DEFAULT: '#3b82f6',
        },
        danger: {
          50: '#fef2f2', 100: '#fee2e2', 200: '#fecaca', 300: '#fca5a5',
          400: '#f87171', 500: '#ef4444', 600: '#dc2626', 700: '#b91c1c',
          800: '#991b1b', 900: '#7f1d1d', DEFAULT: '#ef4444',
        },
        warning: {
          50: '#fffbeb', 100: '#fef3c7', 200: '#fde68a', 300: '#fcd34d',
          400: '#fbbf24', 500: '#f59e0b', 600: '#d97706', 700: '#b45309',
          800: '#92400e', 900: '#78350f', DEFAULT: '#f59e0b',
        },
        safe: {
          50: '#ecfdf5', 100: '#d1fae5', 200: '#a7f3d0', 300: '#6ee7b7',
          400: '#34d399', 500: '#10b981', 600: '#059669', 700: '#047857',
          800: '#065f46', 900: '#064e3b', DEFAULT: '#10b981',
        },
        // Legacy aliases so existing component classes don't break
        primary: {
          50: '#eff6ff', 100: '#dbeafe', 200: '#bfdbfe', 300: '#93c5fd',
          400: '#60a5fa', 500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8',
          800: '#1e40af', 900: '#1e3a8a', DEFAULT: '#3b82f6',
        },
        secondary: {
          50: '#f8fafc', 100: '#f1f5f9', 200: '#e2e8f0', 300: '#cbd5e1',
          400: '#94a3b8', 500: '#64748b', 600: '#475569', 700: '#334155',
          800: '#1e293b', 900: '#0f172a', DEFAULT: '#64748b',
        },
        success: {
          50: '#ecfdf5', 100: '#d1fae5', 200: '#a7f3d0', 300: '#6ee7b7',
          400: '#34d399', 500: '#10b981', 600: '#059669', 700: '#047857',
          800: '#065f46', 900: '#064e3b', DEFAULT: '#10b981',
        },
        neutral: {
          50: '#f8fafc', 100: '#f1f5f9', 200: '#e2e8f0', 300: '#cbd5e1',
          400: '#94a3b8', 500: '#64748b', 600: '#475569', 700: '#334155',
          800: '#1e293b', 900: '#0f172a',
        },
        cream: '#0d1117',
      },
      fontFamily: {
        sans: ['"DM Sans"', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"DM Mono"', '"JetBrains Mono"', 'monospace'],
      },
      fontSize: {
        'heading-1': ['2.25rem', { lineHeight: '1.2', fontWeight: '700', letterSpacing: '-0.02em' }],
        'heading-2': ['1.75rem', { lineHeight: '1.3', fontWeight: '600', letterSpacing: '-0.015em' }],
        'heading-3': ['1.375rem', { lineHeight: '1.4', fontWeight: '600', letterSpacing: '-0.01em' }],
        'heading-4': ['1.125rem', { lineHeight: '1.5', fontWeight: '600' }],
      },
      borderRadius: {
        'card':   '0.5rem',
        'button': '0.375rem',
        'badge':  '0.25rem',
      },
      boxShadow: {
        'card':         '0 1px 3px 0 rgb(0 0 0 / 0.4), 0 1px 2px -1px rgb(0 0 0 / 0.4)',
        'card-hover':   '0 4px 16px 0 rgb(0 0 0 / 0.5), 0 2px 8px -2px rgb(0 0 0 / 0.4)',
        'glow-danger':  '0 0 24px 0 rgb(239 68 68 / 0.25)',
        'glow-warning': '0 0 24px 0 rgb(245 158 11 / 0.25)',
        'glow-safe':    '0 0 24px 0 rgb(16 185 129 / 0.25)',
        'glow-accent':  '0 0 24px 0 rgb(59 130 246 / 0.3)',
        'inner-sm':     'inset 0 1px 2px 0 rgb(0 0 0 / 0.3)',
      },
      animation: {
        'float':      'float 6s ease-in-out infinite',
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line':  'scanLine 2s ease-in-out infinite',
        'blink':      'blink 1.2s step-end infinite',
      },
      keyframes: {
        float:    { '0%, 100%': { transform: 'translateY(0px)' }, '50%': { transform: 'translateY(-12px)' } },
        scanLine: { '0%': { transform: 'translateY(-100%)', opacity: '0' }, '20%': { opacity: '1' }, '80%': { opacity: '1' }, '100%': { transform: 'translateY(400%)', opacity: '0' } },
        blink:    { '0%, 100%': { opacity: '1' }, '50%': { opacity: '0' } },
      },
    },
  },
  plugins: [],
}