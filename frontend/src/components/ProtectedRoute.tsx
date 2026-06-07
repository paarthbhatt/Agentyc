import { useAuth } from '../context/AuthContext';
import { Login } from '../pages/Auth';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated()) {
    return <Login onSuccess={() => window.location.reload()} />;
  }

  return <>{children}</>;
}
