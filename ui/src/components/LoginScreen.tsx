import { useState } from 'react';
import { ArrowRight, KeyRound, LoaderCircle, Shield } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';

import { useAuth } from '../auth/AuthProvider';
import { messageFromError } from '../lib/api';

const loginSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters.').regex(/^[a-zA-Z0-9_-]+$/, 'Invalid username: only alphanumeric characters, dashes, and underscores are allowed.'),
  password: z.string().min(6, 'Password must be at least 6 characters.')
});

type LoginFormValues = z.infer<typeof loginSchema>;

export function LoginScreen({ initialError }: { initialError: string | null }) {
  const { login } = useAuth();
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(initialError);

  const { register, handleSubmit, formState: { errors } } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { username: '', password: '' }
  });

  const onSubmit = async (data: LoginFormValues) => {
    setSubmitting(true);
    setFormError(null);

    try {
      await login(data.username, data.password);
    } catch (error) {
      setFormError(messageFromError(error));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-slate-50" data-testid="login-screen">
      <div className="relative w-full max-w-md">
        <motion.div 
          initial={{ opacity: 0, y: 30, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ type: "spring", stiffness: 200, damping: 20 }}
          className="bg-white/90 border border-slate-200 rounded-[32px] p-8 shadow-[0_30px_60px_-15px_rgba(0,0,0,0.12)]"
          data-testid="login-card"
        >
        <div className="inline-flex items-center gap-1.5 px-3 py-1.5 mb-5 rounded-full bg-[#e0f2fe] text-sky-600 text-xs font-bold tracking-widest uppercase shadow-[inset_0_0_0_1px_rgba(14,165,233,0.1)]">
          <Shield size={14} />
          Safe Zone DNS
        </div>
        
        <h1 className="text-4xl font-semibold text-slate-900 mb-6 tracking-tight">Operator sign-in</h1>

        <form className="space-y-4" onSubmit={handleSubmit(onSubmit)}>
          <div className="space-y-2">
            <label htmlFor="auth-username" className="text-sm font-medium text-slate-600 pl-1">Username</label>
            <input
              id="auth-username"
              autoComplete="username"
              placeholder="Enter your username"
              {...register('username')}
              className={`w-full bg-white border rounded-2xl px-4 py-3.5 text-slate-900 placeholder:text-slate-500 focus:outline-none focus:ring-4 transition-all shadow-sm ${errors.username ? 'border-rose-400 focus:ring-rose-500/15 focus:border-rose-500/50' : 'border-slate-200 focus:ring-sky-500/15 focus:border-sky-500/50 hover:border-slate-300'}`}
            />
            {errors.username && <p className="text-rose-500 text-sm pl-1">{errors.username.message}</p>}
          </div>

          <div className="space-y-2">
            <label htmlFor="auth-password" className="text-sm font-medium text-slate-600 pl-1">Password</label>
            <input
              id="auth-password"
              type="password"
              autoComplete="current-password"
              placeholder="Enter your access secret"
              {...register('password')}
              className={`w-full bg-white border rounded-2xl px-4 py-3.5 text-slate-900 placeholder:text-slate-500 focus:outline-none focus:ring-4 transition-all shadow-sm ${errors.password ? 'border-rose-400 focus:ring-rose-500/15 focus:border-rose-500/50' : 'border-slate-200 focus:ring-sky-500/15 focus:border-sky-500/50 hover:border-slate-300'}`}
            />
            {errors.password && <p className="text-rose-500 text-sm pl-1">{errors.password.message}</p>}
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
      </div>
    </div>
  );
}
