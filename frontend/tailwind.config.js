/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        indigo: {
          50: '#F5EEFE',
          100: '#E8DBFC',
          200: '#CDB0FB',
          300: '#B289FA',
          400: '#9E67FF',
          500: '#8430FF',
          600: '#6B21E4', // Vibrant purple from the screenshot
          700: '#5415B8',
          800: '#3D0B8C',
          900: '#280561',
          950: '#1A0042',
        },
        cyber: {
          bg: '#0A0314', // Deep purple-black background
          card: '#160A29', // Dark purple-tinted card
          border: '#2B154E', // Dark purple border
          primary: '#6B21E4', // Vibrant purple from image
          success: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
          glow: '#A160FF' // Light purple glow
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
