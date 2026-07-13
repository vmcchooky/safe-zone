import { useState } from 'react';
import type { FormEvent } from 'react';
import { ArrowRight, KeyRound, LoaderCircle, Shield } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

import { useAuth } from '../auth/AuthProvider';
import { messageFromError } from '../lib/api';
import { ScreenLoader } from '../App';

export function LoginScreen({ initialError }: { initialError: string | null }) {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(initialError);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    
    const trimmedUsername = username.trim();
    if (!trimmedUsername) {
      setFormError('Username is required.');
      return;
    }
    
    // Validate username to prevent injection (only allow alphanumeric, dash, underscore)
    const usernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!usernameRegex.test(trimmedUsername)) {
      setFormError('Invalid username: only alphanumeric characters, dashes, and underscores are allowed.');
      return;
    }
    
    if (!password) {
      setFormError('Password is required.');
      return;
    }

    setSubmitting(true);
    setFormError(null);

    try {
      await login(trimmedUsername, password);
    } catch (error) {
      setFormError(messageFromError(error));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden bg-slate-50/50">
      {/* Background decorations */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden -z-10">
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 1 }}
          className="absolute top-[-20%] left-[-10%] w-[60%] h-[60%] rounded-full bg-sky-100/50 blur-[120px]" 
        />
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 1, delay: 0.2 }}
          className="absolute bottom-[-20%] right-[-10%] w-[60%] h-[60%] rounded-full bg-pink-100/50 blur-[120px]" 
        />
      </div>

      <motion.div 
        initial={{ opacity: 0, y: 30, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ type: "spring", stiffness: 200, damping: 20 }}
        className="w-full max-w-md bg-transparent border border-white/60 rounded-[32px] p-8 sm:p-10 shadow-[0_30px_60px_-15px_rgba(0,0,0,0.05)]"
      >
        <div className="inline-flex items-center gap-1.5 px-3 py-1.5 mb-6 rounded-full bg-[#e0f2fe] text-sky-600 text-xs font-bold tracking-widest uppercase shadow-[inset_0_0_0_1px_rgba(14,165,233,0.1)]">
          <Shield size={14} />
          Safe Zone DNS
        </div>
        
        <h1 className="text-4xl font-semibold text-slate-900 mb-8 tracking-tight">Operator sign-in</h1>

        <form className="space-y-5" onSubmit={handleSubmit}>
          <div className="space-y-2">
            <label htmlFor="auth-username" className="text-sm font-medium text-slate-600 pl-1">Username</label>
            <input
              id="auth-username"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="Enter your username"
              className="w-full bg-white border border-slate-200 rounded-2xl px-4 py-3.5 text-slate-900 placeholder:text-slate-500 focus:outline-none focus:ring-4 focus:ring-sky-500/15 focus:border-sky-500/50 transition-all shadow-sm hover:border-slate-300"
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="auth-password" className="text-sm font-medium text-slate-600 pl-1">Password</label>
            <input
              id="auth-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter your access secret"
              className="w-full bg-white border border-slate-200 rounded-2xl px-4 py-3.5 text-slate-900 placeholder:text-slate-500 focus:outline-none focus:ring-4 focus:ring-sky-500/15 focus:border-sky-500/50 transition-all shadow-sm hover:border-slate-300"
            />
          </div>

          <button 
            type="submit" 
            disabled={submitting}
            className="w-full mt-2 bg-[#fdb533] hover:bg-[#ffbe47] text-slate-900 py-3.5 px-6 rounded-2xl font-medium flex items-center justify-center gap-2 transition-all duration-200 ease-out hover:-translate-y-0.5 active:translate-y-0.5 active:scale-[0.98] shadow-[0_8px_20px_-6px_rgba(253,181,51,0.5)] hover:shadow-[0_12px_24px_-6px_rgba(253,181,51,0.6)] disabled:opacity-60 disabled:pointer-events-none"
          >
            {submitting ? <LoaderCircle size={18} className="animate-spin" /> : <KeyRound size={18} className="opacity-80" />}
            Authenticate
            <ArrowRight size={18} className="opacity-80" />
          </button>
        </form>

        <AnimatePresence>
          {formError && (
            <motion.div 
              initial={{ opacity: 0, y: -10, height: 0 }}
              animate={{ opacity: 1, y: 0, height: 'auto' }}
              exit={{ opacity: 0, y: -10, height: 0 }}
              className="mt-6 text-rose-700 text-sm font-medium bg-rose-50/80 p-4 rounded-xl border border-rose-200/60 flex items-start gap-2.5 shadow-sm"
            >
              <div className="mt-0.5 shrink-0"><Shield size={16} className="text-rose-500" /></div>
              {formError}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Show full screen Lottie when authenticating */}
      <AnimatePresence>
        {submitting && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[1000]"
          >
            <ScreenLoader />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
