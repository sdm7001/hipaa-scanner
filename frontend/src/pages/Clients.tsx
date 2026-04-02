import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Plus, Search, Building2, ChevronRight, X } from 'lucide-react'
import clsx from 'clsx'

interface Client {
  id: string
  name: string
  contact_name: string | null
  contact_email: string | null
  industry: string | null
  is_active: boolean
  latest_score: number | null
  latest_risk_level: string | null
}

function RiskBadge({ level }: { level: string | null }) {
  if (!level) return <span className="text-gray-600 text-xs">No scan</span>
  const map: Record<string, string> = {
    MINIMAL: 'bg-green-900/30 text-green-400 border border-green-800/50',
    LOW: 'bg-green-900/20 text-green-500 border border-green-900/50',
    MODERATE: 'bg-yellow-900/30 text-yellow-400 border border-yellow-800/50',
    ELEVATED: 'bg-orange-900/30 text-orange-400 border border-orange-800/50',
    HIGH: 'bg-red-900/30 text-red-400 border border-red-800/50',
  }
  return (
    <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', map[level] ?? 'bg-gray-800 text-gray-400')}>
      {level}
    </span>
  )
}

function ScoreBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-gray-600 text-xs">—</span>
  const color = score >= 90 ? 'bg-green-500' : score >= 70 ? 'bg-yellow-500' : score >= 50 ? 'bg-orange-500' : 'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <span className="text-sm font-bold text-white w-8">{score.toFixed(0)}</span>
      <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden max-w-16">
        <div className={clsx('h-full rounded-full', color)} style={{ width: `${score}%` }} />
      </div>
    </div>
  )
}

interface CreateClientForm {
  name: string
  contact_name: string
  contact_email: string
  contact_phone: string
  industry: string
  notes: string
}

function CreateClientModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState<CreateClientForm>({
    name: '', contact_name: '', contact_email: '', contact_phone: '', industry: 'Healthcare', notes: ''
  })
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: (data: CreateClientForm) => api.post('/clients/', data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['clients'] })
      onClose()
    },
    onError: (err: any) => setError(err?.response?.data?.detail ?? 'Failed to create client'),
  })

  const set = (k: keyof CreateClientForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))

  const inputCls = 'w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70">
      <div className="w-full max-w-lg bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-white">Add New Client</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white"><X className="w-4 h-4" /></button>
        </div>
        <form onSubmit={(e) => { e.preventDefault(); mutation.mutate(form) }} className="p-5 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-400 mb-1.5">Company Name *</label>
              <input required value={form.name} onChange={set('name')} placeholder="Acme Medical Group" className={inputCls} />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">Contact Name</label>
              <input value={form.contact_name} onChange={set('contact_name')} placeholder="Jane Smith" className={inputCls} />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">Contact Email</label>
              <input type="email" value={form.contact_email} onChange={set('contact_email')} placeholder="jane@acme.com" className={inputCls} />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">Phone</label>
              <input value={form.contact_phone} onChange={set('contact_phone')} placeholder="(832) 555-0100" className={inputCls} />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">Industry</label>
              <select value={form.industry} onChange={set('industry')} className={inputCls}>
                <option>Healthcare</option>
                <option>Dental</option>
                <option>Mental Health</option>
                <option>Physical Therapy</option>
                <option>Pharmacy</option>
                <option>Laboratory</option>
                <option>Other</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-400 mb-1.5">Notes</label>
              <textarea value={form.notes} onChange={set('notes')} rows={2} placeholder="Internal notes…" className={inputCls + ' resize-none'} />
            </div>
          </div>
          {error && <p className="text-xs text-red-400 bg-red-900/20 border border-red-800 rounded px-3 py-2">{error}</p>}
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="flex-1 px-4 py-2 text-sm text-gray-400 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">Cancel</button>
            <button type="submit" disabled={mutation.isPending} className="flex-1 px-4 py-2 text-sm text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-60 rounded-lg transition-colors">
              {mutation.isPending ? 'Creating…' : 'Create Client'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Clients() {
  const [search, setSearch] = useState('')
  const [showCreate, setShowCreate] = useState(false)

  const { data: clients, isLoading } = useQuery<Client[]>({
    queryKey: ['clients'],
    queryFn: async () => (await api.get('/clients/')).data,
    refetchInterval: 30_000,
  })

  const filtered = clients?.filter(c =>
    c.name.toLowerCase().includes(search.toLowerCase()) ||
    (c.contact_name ?? '').toLowerCase().includes(search.toLowerCase())
  ) ?? []

  return (
    <>
      {showCreate && <CreateClientModal onClose={() => setShowCreate(false)} />}
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold text-white">Clients</h1>
            <p className="text-sm text-gray-500 mt-0.5">{clients?.length ?? 0} total clients</p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add Client
          </button>
        </div>

        {/* Search */}
        <div className="relative max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search clients…"
            className="w-full bg-gray-900 border border-gray-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Table */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-medium">Client</th>
                <th className="text-left px-4 py-3 font-medium">Industry</th>
                <th className="text-left px-4 py-3 font-medium">Score</th>
                <th className="text-left px-4 py-3 font-medium">Risk</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {isLoading && (
                [...Array(5)].map((_, i) => (
                  <tr key={i}>
                    <td className="px-4 py-3" colSpan={5}>
                      <div className="h-5 bg-gray-800 rounded animate-pulse w-3/4" />
                    </td>
                  </tr>
                ))
              )}
              {!isLoading && filtered.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-600">
                    {search ? 'No clients match your search.' : 'No clients yet. Add your first client.'}
                  </td>
                </tr>
              )}
              {filtered.map((c) => (
                <tr key={c.id} className="hover:bg-gray-800/40 transition-colors group cursor-pointer" onClick={() => window.location.hash = `/clients/${c.id}`}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-7 h-7 rounded-lg bg-gray-800 flex items-center justify-center flex-shrink-0">
                        <Building2 className="w-3.5 h-3.5 text-gray-500" />
                      </div>
                      <div>
                        <p className="font-medium text-white">{c.name}</p>
                        {c.contact_name && <p className="text-xs text-gray-500 mt-0.5">{c.contact_name}</p>}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{c.industry ?? '—'}</td>
                  <td className="px-4 py-3"><ScoreBar score={c.latest_score} /></td>
                  <td className="px-4 py-3"><RiskBadge level={c.latest_risk_level} /></td>
                  <td className="px-4 py-3 text-right">
                    <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-gray-400 ml-auto transition-colors" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
