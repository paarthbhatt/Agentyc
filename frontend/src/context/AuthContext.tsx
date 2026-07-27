import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { API_BASE, refreshSession } from '../lib/api';

interface User {
  id: string;
  email: string;
  is_active: boolean;
  created_at: string;
}

interface Organization {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}

interface AuthContextType {
  user: User | null;
  org: Organization | null;
  isLoading: boolean;
  error: string | null;
  register: (email: string, password: string, orgName: string) => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: () => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [org, setOrg] = useState<Organization | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const restore = async () => {
      try {
        let response = await fetch(`${API_BASE}/auth/session`, { credentials: 'include' });
        if (response.status === 401 && await refreshSession()) {
          response = await fetch(`${API_BASE}/auth/session`, { credentials: 'include' });
        }
        if (response.ok) {
          const data = await response.json();
          setUser(data.user);
          setOrg(data.organization);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unable to restore session');
      } finally {
        setIsLoading(false);
      }
    };
    void restore();
  }, []);

  const authenticate = async (path: string, body: Record<string, string>) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}${path}`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Authentication failed');
      setUser(data.user);
      setOrg(data.organization);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const register = (email: string, password: string, orgName: string) =>
    authenticate('/auth/register', { email, password, org_name: orgName });

  const login = (email: string, password: string) =>
    authenticate('/auth/login', { email, password });

  const logout = () => {
    void fetch(`${API_BASE}/auth/logout`, { method: 'POST', credentials: 'include' });
    setUser(null);
    setOrg(null);
    setError(null);
  };

  const isAuthenticated = () => !!user && !!org;

  return (
    <AuthContext.Provider value={{ user, org, isLoading, error, register, login, logout, isAuthenticated }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}
