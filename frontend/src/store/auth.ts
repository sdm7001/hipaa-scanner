import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface User {
  id: string
  email: string
  first_name: string
  last_name: string
  role: string
  msp_id: string
}

interface AuthState {
  token: string | null
  user: User | null
  setToken: (token: string) => void
  setUser: (user: User) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      user: null,
      setToken: (token) => {
        localStorage.setItem('access_token', token)
        set({ token })
      },
      setUser: (user) => set({ user }),
      logout: () => {
        localStorage.removeItem('access_token')
        set({ token: null, user: null })
      },
    }),
    {
      name: 'hipaa-auth',
      partialize: (s) => ({ token: s.token, user: s.user }),
    }
  )
)
