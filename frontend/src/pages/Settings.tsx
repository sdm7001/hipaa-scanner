import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Key, Users, Plus, Trash2, Edit2, RefreshCw, Eye, EyeOff, Check } from 'lucide-react'
import { api } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

interface User {
  id: string
  email: string
  first_name: string
  last_name: string
  role: string
  is_active: boolean
  client_id: string | null
}

interface ApiKeyData {
  api_key: string
  msp_name: string
  note: string
}

function RoleBadge({ role }: { role: string }) {
  const colors: Record<string, string> = {
    msp_admin: 'bg-blue-900/40 text-blue-300',
    msp_tech: 'bg-purple-900/40 text-purple-300',
    client_admin: 'bg-green-900/40 text-green-300',
  }
  return (
    <span className={`text-[11px] px-2 py-0.5 rounded font-medium ${colors[role] ?? 'bg-gray-800 text-gray-400'}`}>
      {role.replace(/_/g, ' ')}
    </span>
  )
}

function ApiKeySection() {
  const [visible, setVisible] = useState(false)
  const [copied, setCopied] = useState(false)
  const [rotating, setRotating] = useState(false)
  const qc = useQueryClient()

  const { data: keyData, isLoading } = useQuery<ApiKeyData>({
    queryKey: ['api-key'],
    queryFn: async () => (await api.get('/api-keys/')).data,
  })

  const rotateMutation = useMutation({
    mutationFn: () => api.post('/api-keys/rotate').then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-key'] })
      setVisible(true)
    },
  })

  const copy = () => {
    if (!keyData) return
    navigator.clipboard.writeText(keyData.api_key).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <Key className="w-4 h-4 text-blue-400" />
        <h2 className="font-semibold text-white">Scanner API Key</h2>
      </div>
      <p className="text-xs text-gray-500 mb-4">
        Used by the HIPAA Scanner CLI to upload scan results. Keep it secret.
      </p>

      {isLoading ? (
        <div className="h-10 bg-gray-800 rounded-lg animate-pulse" />
      ) : keyData ? (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <div className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 font-mono text-sm text-gray-300 overflow-hidden">
              {visible ? keyData.api_key : '•'.repeat(32)}
            </div>
            <button onClick={() => setVisible(v => !v)} className="p-2 text-gray-500 hover:text-gray-300 transition-colors">
              {visible ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
            <button onClick={copy} className="p-2 text-gray-500 hover:text-gray-300 transition-colors">
              {copied ? <Check className="w-4 h-4 text-green-400" /> : <span className="text-xs">Copy</span>}
            </button>
          </div>
          <button
            onClick={() => {
              if (!window.confirm('Rotate the API key? The old key will stop working immediately — update your scanner config before rotating.')) return
              rotateMutation.mutate()
            }}
            disabled={rotateMutation.isPending}
            className="flex items-center gap-2 text-xs text-orange-400 hover:text-orange-300 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${rotateMutation.isPending ? 'animate-spin' : ''}`} />
            {rotateMutation.isPending ? 'Rotating…' : 'Rotate API Key'}
          </button>
        </div>
      ) : (
        <p className="text-sm text-red-400">Failed to load API key</p>
      )}
    </div>
  )
}

function CreateUserModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    email: '', password: '', first_name: '', last_name: '',
    role: 'msp_tech' as string,
  })
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: () => api.post('/users/', form).then(r => r.data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['users'] }); onClose() },
    onError: (err: { response?: { data?: { detail?: string } } }) => setError(err.response?.data?.detail ?? 'Failed to create user'),
  })

  const inputClass = "w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors"

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 w-full max-w-md">
        <h3 className="font-semibold text-white mb-4">Add User</h3>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-gray-500 mb-1">First Name</label>
              <input className={inputClass} value={form.first_name} onChange={e => setForm(f => ({ ...f, first_name: e.target.value }))} required />
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">Last Name</label>
              <input className={inputClass} value={form.last_name} onChange={e => setForm(f => ({ ...f, last_name: e.target.value }))} required />
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Email</label>
            <input type="email" className={inputClass} value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} required />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Password</label>
            <input type="password" className={inputClass} value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Role</label>
            <select className={inputClass} value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
              <option value="msp_tech">MSP Technician</option>
              <option value="msp_admin">MSP Admin</option>
              <option value="client_admin">Client Admin</option>
            </select>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <div className="flex justify-end gap-3 mt-5">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors">Cancel</button>
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || !form.email || !form.password || !form.first_name || !form.last_name}
            className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            {mutation.isPending ? 'Creating…' : 'Create User'}
          </button>
        </div>
      </div>
    </div>
  )
}

function UsersSection() {
  const { user: currentUser } = useAuthStore()
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)

  const { data: users = [], isLoading } = useQuery<User[]>({
    queryKey: ['users'],
    queryFn: async () => (await api.get('/users/')).data,
  })

  const toggleActive = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      api.patch(`/users/${id}`, { is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  if (currentUser?.role !== 'msp_admin') {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <p className="text-sm text-gray-500">User management is available to MSP admins only.</p>
      </div>
    )
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Users className="w-4 h-4 text-blue-400" />
          <h2 className="font-semibold text-white">Users</h2>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" /> Add User
        </button>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => <div key={i} className="h-12 bg-gray-800 rounded-lg animate-pulse" />)}
        </div>
      ) : (
        <div className="space-y-2">
          {users.map(u => (
            <div key={u.id} className={`flex items-center justify-between px-3 py-2.5 rounded-lg border ${u.is_active ? 'border-gray-800' : 'border-gray-800/50 opacity-50'}`}>
              <div className="min-w-0">
                <p className="text-sm text-white truncate">{u.first_name} {u.last_name}</p>
                <p className="text-xs text-gray-500 truncate">{u.email}</p>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0 ml-3">
                <RoleBadge role={u.role} />
                {u.id !== currentUser?.id && (
                  <button
                    onClick={() => toggleActive.mutate({ id: u.id, is_active: !u.is_active })}
                    className={`text-xs px-2 py-1 rounded transition-colors ${
                      u.is_active
                        ? 'text-gray-500 hover:text-red-400 hover:bg-red-900/20'
                        : 'text-gray-600 hover:text-green-400 hover:bg-green-900/20'
                    }`}
                  >
                    {u.is_active ? 'Deactivate' : 'Reactivate'}
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} />}
    </div>
  )
}

export default function Settings() {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'msp_admin'

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-xl font-bold text-white">Settings</h1>
        <p className="text-sm text-gray-400 mt-1">Manage your MSP organization, users, and scanner credentials</p>
      </div>

      {isAdmin && <ApiKeySection />}
      <UsersSection />
    </div>
  )
}
