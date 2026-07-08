import { useState } from 'react';
import type { FormEvent } from 'react';
import { ArrowRight, KeyRound, LoaderCircle, Shield } from 'lucide-react';

import { useAuth } from '../auth/AuthProvider';
import { messageFromError } from '../lib/api';

export function LoginScreen({ initialError }: { initialError: string | null }) {
  const { login } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(initialError);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setFormError(null);

    try {
      await login(username.trim(), password);
    } catch (error) {
      setFormError(messageFromError(error));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-kicker">
          <Shield size={14} />
          React Workspace
        </div>
        <h1>Operator sign-in</h1>
        <p>
          This standalone UI workspace reuses the same Safe Zone authentication flow as the current
          server-rendered dashboard.
        </p>

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="auth-field">
            <label htmlFor="auth-username">Username</label>
            <input
              id="auth-username"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="admin or guest"
            />
          </div>

          <div className="auth-field">
            <label htmlFor="auth-password">Password</label>
            <input
              id="auth-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter your access secret"
            />
          </div>

          <button className="button-primary" type="submit" disabled={submitting}>
            {submitting ? <LoaderCircle size={16} className="spin" /> : <KeyRound size={16} />}
            Authenticate
            <ArrowRight size={16} />
          </button>
        </form>

        {formError ? <div className="auth-error">{formError}</div> : null}

        <div className="auth-meta">
          <span>API target: proxied through Vite</span>
          <span>Session mode: cookie-based</span>
        </div>
      </div>
    </div>
  );
}
