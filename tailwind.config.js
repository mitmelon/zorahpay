/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        './template/**/*.html',
        './**/*.php',
        './asset/ui/**/*.js',
        './asset/ui/**/*.html'
    ],
    safelist: [
        'sidebar-open-mobile',
        'sidebar-closed-mobile',
        'ease-smooth-glide',
        'dropdown-enter',
        'dropdown-active',
        'transition-card',
        { pattern: /^(md|sm|lg):/ },
        { pattern: /^(hover|group-hover|focus|active):/ }
    ],
  theme: {
      extend: {
          fontFamily: {
              sans: ['Inter', 'sans-serif'],
          },
          colors: {
              gray: {
                  50: '#F9FAFB', 100: '#F3F4F6', 200: '#E5E7EB', 300: '#D1D5DB',
                  400: '#9CA3AF', 500: '#6B7280', 600: '#4B5563', 700: '#374151',
                  800: '#1F2937', 900: '#111827',
              }
          },
          // Updated to smooth "Luxury" curves (removed bouncy/slacky)
          transitionTimingFunction: {
              'smooth-glide': 'cubic-bezier(0.4, 0, 0.2, 1)',
              'soft-arrival': 'cubic-bezier(0.2, 0.8, 0.2, 1)',
          }
      }
  },
    plugins: [],
};