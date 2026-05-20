import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from 'react'
import { useQuery } from '@tanstack/react-query'
import { authApi } from '@/api/auth'
import { paymentsApi } from '@/api/payments'
import {
  clearTokens,
  getAccessToken,
  setTokens,
} from '@/api/client'
import type { LoginRequest, RegisterRequest, User } from '@/types'

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (data: LoginRequest) => Promise<void>
  register: (data: RegisterRequest) => Promise<void>
  logout: () => void
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | null>(null)

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const refreshUser = useCallback(async () => {
    try {
      const me = await authApi.me()
      setUser(me)
    } catch {
      setUser(null)
      clearTokens()
    }
  }, [])

  useEffect(() => {
    const token = getAccessToken()
    if (token) {
      refreshUser().finally(() => setIsLoading(false))
    } else {
      setIsLoading(false)
    }
  }, [refreshUser])

  const login = async (data: LoginRequest) => {
    const result = await authApi.login(data)
    setTokens(result.access_token, result.refresh_token)
    setUser(result.user)
  }

  const register = async (data: RegisterRequest) => {
    const result = await authApi.register(data)
    setTokens(result.access_token, result.refresh_token)
    setUser(result.user)
  }

  const { data: publicConfig } = useQuery({
    queryKey: ['publicConfig'],
    queryFn: paymentsApi.publicConfig,
    staleTime: Infinity,
  })

  const logout = useCallback(() => {
    clearTokens()
    setUser(null)
    if (publicConfig?.auth_mode === 'oidc') {
      // Full-page navigation so Authentik's end-session endpoint can also
      // clear the upstream session cookie before bouncing back.
      window.location.href = '/api/v1/auth/logout'
    }
  }, [publicConfig?.auth_mode])

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
