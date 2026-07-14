import React, { createContext, useContext, useState } from 'react';
import type { ReactNode } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertCircle, Info, CheckCircle2 } from 'lucide-react';

interface DialogOptions {
  title?: string;
  message: string;
  type?: 'info' | 'error' | 'success' | 'warning';
  confirmText?: string;
  cancelText?: string;
}

interface DialogContextType {
  alert: (options: string | DialogOptions) => Promise<void>;
  confirm: (options: string | DialogOptions) => Promise<boolean>;
}

const DialogContext = createContext<DialogContextType | null>(null);

export function useDialog() {
  const context = useContext(DialogContext);
  if (!context) {
    throw new Error('useDialog must be used within a DialogProvider');
  }
  return context;
}

export function DialogProvider({ children }: { children: ReactNode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [config, setConfig] = useState<DialogOptions & { isConfirm: boolean, resolve: (value: any) => void }>({
    message: '',
    isConfirm: false,
    resolve: () => {},
  });

  const showDialog = (options: string | DialogOptions, isConfirm: boolean) => {
    return new Promise<any>((resolve) => {
      const opts = typeof options === 'string' ? { message: options } : options;
      setConfig({
        title: isConfirm ? 'Confirm' : 'Alert',
        type: isConfirm ? 'warning' : 'info',
        confirmText: 'OK',
        cancelText: 'Cancel',
        ...opts,
        isConfirm,
        resolve,
      });
      setIsOpen(true);
    });
  };

  const alert = (options: string | DialogOptions) => showDialog(options, false);
  const confirm = (options: string | DialogOptions) => showDialog(options, true);

  const handleConfirm = () => {
    setIsOpen(false);
    config.resolve(true);
  };

  const handleCancel = () => {
    setIsOpen(false);
    config.resolve(false);
  };

  const getIcon = () => {
    switch (config.type) {
      case 'error': return <AlertCircle className="text-rose-500 w-7 h-7 drop-shadow-sm" />;
      case 'success': return <CheckCircle2 className="text-emerald-500 w-7 h-7 drop-shadow-sm" />;
      case 'warning': return <AlertCircle className="text-amber-500 w-7 h-7 drop-shadow-sm" />;
      case 'info':
      default: return <Info className="text-sky-500 w-7 h-7 drop-shadow-sm" />;
    }
  };

  const getIconBg = () => {
    switch (config.type) {
      case 'error': return 'bg-rose-100/80 border-rose-200/60 shadow-rose-500/20';
      case 'success': return 'bg-emerald-100/80 border-emerald-200/60 shadow-emerald-500/20';
      case 'warning': return 'bg-amber-100/80 border-amber-200/60 shadow-amber-500/20';
      case 'info':
      default: return 'bg-sky-100/80 border-sky-200/60 shadow-sky-500/20';
    }
  };

  return (
    <DialogContext.Provider value={{ alert, confirm }}>
      {children}
      <AnimatePresence>
        {isOpen && (
          <div className="fixed inset-0 z-[999] flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
              animate={{ opacity: 1, backdropFilter: "blur(8px)" }}
              exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
              transition={{ duration: 0.3 }}
              className="absolute inset-0 bg-slate-900/20"
              onClick={handleCancel}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              transition={{ type: "spring", stiffness: 400, damping: 30 }}
              className="relative w-full max-w-md bg-white/70 backdrop-blur-2xl border border-white/80 rounded-[32px] shadow-[0_20px_40px_-15px_rgba(0,0,0,0.1)] overflow-hidden flex flex-col"
            >
              {/* Decorative top gradient */}
              <div className="absolute top-0 inset-x-0 h-32 bg-gradient-to-b from-white/60 to-transparent pointer-events-none" />

              <div className="p-8 pb-6 relative z-10">
                <div className="flex flex-col items-center text-center gap-4">
                  <motion.div 
                    initial={{ scale: 0.8, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ delay: 0.1, type: "spring", stiffness: 300, damping: 20 }}
                    className={`p-4 rounded-2xl border shadow-lg ${getIconBg()} flex items-center justify-center`}
                  >
                    {getIcon()}
                  </motion.div>
                  <div className="space-y-2">
                    <h3 className="text-xl font-bold text-slate-900 tracking-tight">
                      {config.title}
                    </h3>
                    <p className="text-[15px] text-slate-600 leading-relaxed font-medium">
                      {config.message}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="px-8 py-6 bg-slate-50/50 border-t border-slate-100/50 flex justify-center gap-3 relative z-10">
                {config.isConfirm && (
                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.97 }}
                    onClick={handleCancel}
                    className="px-6 py-2.5 text-sm font-semibold text-slate-700 bg-white/80 border border-slate-200/80 rounded-2xl hover:bg-slate-100 hover:text-slate-900 transition-all shadow-sm"
                  >
                    {config.cancelText}
                  </motion.button>
                )}
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.97 }}
                  onClick={handleConfirm}
                  className={`px-6 py-2.5 text-sm font-semibold text-white rounded-2xl transition-all shadow-md ${
                    config.type === 'error' ? 'bg-rose-600 hover:bg-rose-700 shadow-rose-600/20' : 
                    config.type === 'warning' ? 'bg-amber-500 hover:bg-amber-600 shadow-amber-500/20' : 
                    'bg-slate-900 hover:bg-slate-800 shadow-slate-900/20'
                  }`}
                >
                  {config.confirmText}
                </motion.button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </DialogContext.Provider>
  );
}
