import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Shield, AlertTriangle, CheckCircle, Users } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import clsx from 'clsx'

interface Client {
  id: string
  name: string
  latest_score: number | null
  latest_risk_level: string | null
}

function RiskBadge({ level }: { level: string | null }) {
  if (!level) return <span className="text-gray-500 text-xs">No scan</span>
  const colors: Record<string, string> = {
    MINIMAL: 'bg-green-900/30 text-green-400 border border-green-800',
    LOW: 'bg-green-900/20 text-green-500 border border-green-900',
    MODERATE: 'bg-yellow-900/30 text-yellow-400 border border-yellow-800',
    ELEVATED: 'bg-orange-900/30 text-orange-400 border border-orange-800',
    HIGH: 'bg-red-900/30 text-red-400 border border-red-800',
  }
  return (
    <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', colors[level] ?? 'bg-gray-800 text-gray-400')}>
      {level}
    </span>
  )
}

function ScoreGauge({ score }: { score: number | null }) {
  if (score === null) return <span className="text-gray-500 text-sm">—</span>
  const color = score >= 90 ? 'text-green-400' : score >= 70 ? 'text-yellow-400' : score >= 50 ? 'text-orange-400' : 'text-red-400'
  return <span className={clsx('text-xl font-bold', color)}>{score.toFixed(0)}</span>
}

export default function Dashboard() {
  const { data: clients, isLoading } = useQuery<Client[]>({
    queryKey: ['clients'],
    queryFn: async () => (await api.get('/clients/')).data,
    refetchInterval: 60_000,
  })

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-8 w-48 bg-gray-800 rounded animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-32 bg-gray-900 rounded-2xl animate-pulse" />
          ))}
        </div>
      </div>
    )
  }

  const totalClients = clients?.length ?? 0
  const atRisk = clients?.filter(c => c.latest_risk_level === 'HIGH' || c.latest_risk_level === 'ELEVATED').length ?? 0
  const avgScore = clients && clients.length > 0
    ? clients.filter(c => c.latest_score !== null).reduce((sum, c) => sum + (c.latest_score ?? 0), 0) /
      clients.filter(c => c.latest_score !== null).length
    : 0

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">MSP Dashboard</h1>
        <p className="text-gray-400 text-sm mt-0.5">HIPAA compliance status across all clients</p>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm mb-1">Total Clients</p>
              <p className="text-3xl font-bold text-white">{totalClients}</p>
            </div>
            <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center">
              <Users className="w-5 h-5 text-white" />
            </div>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm mb-1">At Risk</p>
              <p className="text-3xl font-bold text-red-400">{atRisk}</p>
            </div>
            <div className="w-10 h-10 bg-red-600 rounded-xl flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-white" />
            </div>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm mb-1">Avg Compliance Score</p>
              <p className="text-3xl font-bold text-white">{avgScore.toFixed(0)}</p>
            </div>
            <div className="w-10 h-10 bg-green-600 rounded-xl flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
          </div>
        </div>
      </div>

      {/* Client Grid */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4">All Clients</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {(clients ?? []).map(client => (
            <a
              key={client.id}
              href={`/clients/${client.id}`}
              className="bg-gray-900 border border-gray-800 hover:border-indigo-600 rounded-2xl p-5 transition-colors block"
            >
              <div className="flex items-start justify-between mb-3">
                <h3 className="text-white font-semibold text-sm">{client.name}</h3>
                <RiskBadge level={client.latest_risk_level} />
              </div>
              <div className="flex items-center gap-2">
                <span className="text-gray-400 text-xs">Score:</span>
                <ScoreGauge score={client.latest_score} />
                <span className="text-gray-600 text-xs">/100</span>
              </div>
            </a>
          ))}
        </div>

        {(!clients || clients.length === 0) && (
          <div className="text-center py-12 text-gray-500">
            <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p>No clients yet. Add your first client to begin scanning.</p>
          </div>
        )}
      </div>
    </div>
  )
}
