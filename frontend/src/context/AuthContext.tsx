import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

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
  tokens: { access_token: string; refresh_token: string } | null;
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
  const [tokens, setTokens] = useState<{ access_token: string; refresh_token: string } | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stored = localStorage.getItem('auth');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        setUser(parsed.user);
        setOrg(parsed.org);
        setTokens(parsed.tokens);
      } catch {
        localStorage.removeItem('auth');
      }
    }
  }, []);

  const register = async (email: string, password: string, orgName: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/v1/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, org_name: orgName }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Registration failed');
      }
      const data = await response.json();
      setUser(data.user);
      setOrg(data.organization);
      setTokens({ access_token: data.access_token, refresh_token: data.refresh_token });
      localStorage.setItem('auth', JSON.stringify({
        user: data.user,
        org: data.organization,
        tokens: { access_token: data.access_token, refresh_token: data.refresh_token },
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Login failed');
      }
      const data = await response.json();
      setUser(data.user);
      setOrg(data.organization);
      setTokens({ access_token: data.access_token, refresh_token: data.refresh_token });
      localStorage.setItem('auth', JSON.stringify({
        user: data.user,
        org: data.organization,
        tokens: { access_token: data.access_token, refresh_token: data.refresh_token },
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    setOrg(null);
    setTokens(null);
    setError(null);
    localStorage.removeItem('auth');
  };

  const isAuthenticated = () => !!tokens && !!user;

  return (
    <AuthContext.Provider value={{ user, org, tokens, isLoading, error, register, login, logout, isAuthenticated }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
