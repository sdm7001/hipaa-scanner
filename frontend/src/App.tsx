import { useEffect, useState } from 'react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Clients from './pages/Clients'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import AuditLog from './pages/AuditLog'
import AppShell from './components/layout/AppShell'
import { useAuthStore } from './store/auth'
import { api } from './lib/api'

const qc = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 30_000 } } })

function ClientDetail({ clientId }: { clientId: string }) {
  const { data: client } = useQuery({
    queryKey: ['client', clientId],
    queryFn: async () => (await api.get(`/clients/${clientId}`)).data,
  })

  const { data: scans } = useQuery({
    queryKey: ['client-scans', clientId],
    queryFn: async () => (await api.get(`/scans/?client_id=${clientId}`)).data,
  })

  return (
    <div className="space-y-4">
      <button onClick={() => { window.location.hash = '/clients' }} className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-white transition-colors">
        ← Back to Clients
      </button>
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h1 className="text-lg font-semibold text-white">{client?.name ?? '…'}</h1>
        <div className="mt-2 text-xs text-gray-500 space-y-0.5">
          {client?.contact_name && <p>Contact: {client.contact_name}</p>}
          {client?.contact_email && <p>Email: {client.contact_email}</p>}
          {client?.industry && <p>Industry: {client.industry}</p>}
        </div>
      </div>
      <div>
        <h2 className="text-sm font-semibold text-white mb-3">Scan History</h2>
        {!scans || scans.length === 0
          ? <p className="text-sm text-gray-600">No scans for this client yet.</p>
          : (
            <div className="space-y-2">
              {scans.map((s: { id: string; completed_at: string | null; overall_score: number | null; risk_level: string | null }) => (
                <button
                  key={s.id}
                  onClick={() => { window.location.hash = `/scans/${s.id}` }}
                  className="w-full flex items-center justify-between bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 hover:bg-gray-800/50 transition-colors text-left"
                >
                  <div className="text-sm text-white">
                    {s.completed_at ? new Date(s.completed_at).toLocaleDateString() : 'In progress'}
                  </div>
                  <div className="flex items-center gap-3">
                    {s.overall_score !== null && (
                      <span className="text-sm font-bold text-white">{s.overall_score.toFixed(0)}</span>
                    )}
                    <span className="text-xs text-gray-400">{s.risk_level ?? '—'}</span>
                    <span className="text-gray-600">→</span>
                  </div>
                </button>
              ))}
            </div>
          )
        }
      </div>
    </div>
  )
}

function Router() {
  const [hash, setHash] = useState(window.location.hash)
  const { token } = useAuthStore()

  useEffect(() => {
    const onHash = () => setHash(window.location.hash)
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  if (!token) return <Login />

  const path = hash.replace(/^#/, '') || '/dashboard'
  const scanDetailMatch = path.match(/^\/scans\/(.+)$/)
  const clientDetailMatch = path.match(/^\/clients\/(.+)$/)

  const content = (() => {
    if (scanDetailMatch) return <ScanDetail scanId={scanDetailMatch[1]} />
    if (clientDetailMatch) return <ClientDetail clientId={clientDetailMatch[1]} />
    if (path === '/clients') return <Clients />
    if (path === '/scans') return <Scans />
    if (path === '/reports') return <Reports />
    if (path === '/settings') return <Settings />
    if (path === '/audit-log') return <AuditLog />
    return <Dashboard />
  })()

  return <AppShell>{content}</AppShell>
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <Router />
    </QueryClientProvider>
  )
}
