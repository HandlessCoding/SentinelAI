import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

const localServer = {
  host: '127.0.0.1',
  port: 5173,
  strictPort: true,
  proxy: {
    '/api/': {
      target: 'http://127.0.0.1:8001',
      rewrite: (path: string) => path.replace(/^\/api/, ''),
    },
  },
}

export default defineConfig({
  plugins: [react()],
  server: localServer,
  preview: localServer,
  test: { environment: 'jsdom' },
})
