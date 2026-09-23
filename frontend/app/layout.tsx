import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'SiteGuard — Website Security Assessment',
  description: 'Identify security weaknesses and public exposures on your website.',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#0b0e16] text-gray-100 antialiased">
        <header className="border-b border-gray-800 bg-[#0d1017]">
          <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
            <a href="/" className="flex items-center gap-2 font-semibold text-cyan-400 hover:text-cyan-300 transition-colors">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              SiteGuard
            </a>
            <span className="text-xs text-gray-500 mono">passive · defensive · non-intrusive</span>
          </div>
        </header>
        <main className="max-w-6xl mx-auto px-6 py-10">
          {children}
        </main>
      </body>
    </html>
  )
}
