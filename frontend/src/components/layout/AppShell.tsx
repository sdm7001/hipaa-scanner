import { useState } from 'react'
import { Shield, Users, BarChart3, FileText, Settings, LogOut, Menu, X, ChevronDown } from 'lucide-react'
import clsx from 'clsx'
import { useAuthStore } from '@/store/auth'
import { api } from '@/lib/api'

const NAV = [
  { href: '#/dashboard', label: 'Dashboard', icon: BarChart3 },
  { href: '#/clients', label: 'Clients', icon: Users },
  { href: '#/scans', label: 'Scans', icon: Shield },
  { href: '#/reports', label: 'Reports', icon: FileText },
]

function NavItem({ href, label, icon: Icon }: { href: string; label: string; icon: React.ElementType }) {
  const active = window.location.hash === href || (href === '#/dashboard' && window.location.hash === '')
  return (
    <a
      href={href}
      className={clsx(
        'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
        active
          ? 'bg-blue-600/20 text-blue-400'
          : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
      )}
    >
      <Icon className="w-4 h-4 flex-shrink-0" />
      {label}
    </a>
  )
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false)
  const { user, logout } = useAuthStore()

  const handleLogout = async () => {
    try { await api.post('/auth/logout') } catch {}
    logout()
    window.location.hash = '/login'
  }

  const Sidebar = () => (
    <aside className="flex flex-col h-full bg-gray-900 border-r border-gray-800">
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-gray-800">
        <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center flex-shrink-0">
          <Shield className="w-4 h-4 text-white" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-semibold text-white truncate">HIPAA Scanner</p>
          <p className="text-[11px] text-gray-500 truncate">MSP Compliance Platform</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
        {NAV.map((item) => (
          <NavItem key={item.href} {...item} />
        ))}
      </nav>

      {/* User */}
      <div className="p-3 border-t border-gray-800">
        <div className="flex items-center gap-3 px-3 py-2">
          <div className="w-7 h-7 rounded-full bg-blue-700 flex items-center justify-center flex-shrink-0 text-xs font-bold text-white">
            {user?.first_name?.[0]}{user?.last_name?.[0]}
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium text-gray-200 truncate">{user?.first_name} {user?.last_name}</p>
            <p className="text-[11px] text-gray-500 truncate capitalize">{user?.role?.replace('_', ' ')}</p>
          </div>
        </div>
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 w-full px-3 py-2 rounded-lg text-sm text-gray-400 hover:bg-gray-800 hover:text-gray-200 transition-colors mt-1"
        >
          <LogOut className="w-4 h-4" />
          Sign out
        </button>
      </div>
    </aside>
  )

  return (
    <div className="flex h-screen overflow-hidden bg-gray-950">
      {/* Desktop sidebar */}
      <div className="hidden md:flex md:w-56 flex-shrink-0">
        <div className="w-full">
          <Sidebar />
        </div>
      </div>

      {/* Mobile sidebar */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
          <div className="relative w-56 flex flex-col">
            <Sidebar />
          </div>
        </div>
      )}

      {/* Main */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile header */}
        <header className="md:hidden flex items-center gap-3 px-4 py-3 bg-gray-900 border-b border-gray-800">
          <button onClick={() => setMobileOpen(!mobileOpen)} className="text-gray-400 hover:text-white">
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
          <span className="text-sm font-semibold text-white">HIPAA Scanner</span>
        </header>

        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
