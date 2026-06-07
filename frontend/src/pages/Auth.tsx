import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import styles from './Auth.module.css';

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const { login, isLoading, error } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [localError, setLocalError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError('');
    try {
      await login(email, password);
      onSuccess();
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Login failed');
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.box}>
        <div className={styles.header}>
          <h1 className={styles.title}>Agent Sentinel</h1>
          <p className={styles.tagline}>Trust Nothing. Verify Every Thought.</p>
        </div>

        <form onSubmit={handleSubmit} className={styles.form}>
          <div className={styles.formGroup}>
            <label htmlFor="email" className={styles.label}>Email Address</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              className={styles.input}
              required
              disabled={isLoading}
            />
          </div>

          <div className={styles.formGroup}>
            <label htmlFor="password" className={styles.label}>Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className={styles.input}
              required
              minLength={8}
              disabled={isLoading}
            />
          </div>

          {(error || localError) && (
            <div className={styles.error}>
              <span className={styles.errorIcon}>⚠</span>
              {error || localError}
            </div>
          )}

          <button 
            type="submit" 
            className={styles.button}
            disabled={isLoading}
          >
            {isLoading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div className={styles.footer}>
          <p>No account? <a href="#register" className={styles.link}>Create one</a></p>
        </div>
      </div>

      <div className={styles.background}></div>
    </div>
  );
}

export function Register({ onSuccess }: { onSuccess: () => void }) {
  const { register, isLoading, error } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  const [localError, setLocalError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError('');
    if (password.length < 8) {
      setLocalError('Password must be at least 8 characters');
      return;
    }
    try {
      await register(email, password, orgName);
      onSuccess();
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Registration failed');
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.box}>
        <div className={styles.header}>
          <h1 className={styles.title}>Agent Sentinel</h1>
          <p className={styles.tagline}>Trust Nothing. Verify Every Thought.</p>
        </div>

        <form onSubmit={handleSubmit} className={styles.form}>
          <div className={styles.formGroup}>
            <label htmlFor="email" className={styles.label}>Email Address</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              className={styles.input}
              required
              disabled={isLoading}
            />
          </div>

          <div className={styles.formGroup}>
            <label htmlFor="orgName" className={styles.label}>Organization Name</label>
            <input
              id="orgName"
              type="text"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              placeholder="Your Company"
              className={styles.input}
              required
              disabled={isLoading}
            />
          </div>

          <div className={styles.formGroup}>
            <label htmlFor="password" className={styles.label}>Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className={styles.input}
              required
              minLength={8}
              disabled={isLoading}
            />
            <small className={styles.hint}>At least 8 characters</small>
          </div>

          {(error || localError) && (
            <div className={styles.error}>
              <span className={styles.errorIcon}>⚠</span>
              {error || localError}
            </div>
          )}

          <button 
            type="submit" 
            className={styles.button}
            disabled={isLoading}
          >
            {isLoading ? 'Creating account...' : 'Create Account'}
          </button>
        </form>

        <div className={styles.footer}>
          <p>Already have an account? <a href="#login" className={styles.link}>Sign in</a></p>
        </div>
      </div>

      <div className={styles.background}></div>
    </div>
  );
}
