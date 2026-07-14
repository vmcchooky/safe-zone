import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { X, Shield, ShieldAlert, Globe, Gamepad2, Dices, MessageSquare, Megaphone } from 'lucide-react';
import type { PolicyGroup } from '../lib/types';
import { apiJSON } from '../lib/api';

interface GroupModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: () => void;
  group: PolicyGroup | null;
}

const CATEGORIES = [
  { id: 'adult', name: 'Adult Content', desc: 'Restrict mature destination categories.', icon: Globe },
  { id: 'gambling', name: 'Gambling', desc: 'Block wagering, betting, and casino domains.', icon: Dices },
  { id: 'social_media', name: 'Social Media', desc: 'Limit social platforms and high-distraction feeds.', icon: MessageSquare },
  { id: 'gaming', name: 'Gaming', desc: 'Restrict game portals and related services.', icon: Gamepad2 },
  { id: 'advertising', name: 'Advertising', desc: 'Reduce ad networks and tracking endpoints.', icon: Megaphone },
];

const groupSchema = z.object({
  name: z.string().min(1, 'Group name is required.').max(50, 'Group name cannot exceed 50 characters.'),
  description: z.string().max(200, 'Description cannot exceed 200 characters.').optional(),
  blockCategories: z.array(z.string()),
  strictPhishing: z.boolean(),
  strictMalware: z.boolean(),
});

type GroupFormValues = z.infer<typeof groupSchema>;

export function GroupModal({ isOpen, onClose, onSave, group }: GroupModalProps) {
  const [saving, setSaving] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const { register, handleSubmit, control, reset, formState: { errors } } = useForm<GroupFormValues>({
    resolver: zodResolver(groupSchema),
    defaultValues: {
      name: '',
      description: '',
      blockCategories: [],
      strictPhishing: false,
      strictMalware: false,
    }
  });

  useEffect(() => {
    if (isOpen) {
      if (group) {
        reset({
          name: group.name,
          description: group.description,
          blockCategories: group.block_categories || [],
          strictPhishing: group.strict_phishing,
          strictMalware: group.strict_malware,
        });
      } else {
        reset({
          name: '',
          description: '',
          blockCategories: [],
          strictPhishing: false,
          strictMalware: false,
        });
      }
      setApiError(null);
    }
  }, [isOpen, group, reset]);

  const onSubmit = async (data: GroupFormValues) => {
    setSaving(true);
    setApiError(null);

    try {
      const payload = {
        name: data.name.trim(),
        description: (data.description || '').trim(),
        block_categories: data.blockCategories,
        strict_phishing: data.strictPhishing,
        strict_malware: data.strictMalware,
      };

      if (group) {
        await apiJSON(`/v1/groups?id=${group.id}`, payload, { method: 'PUT' });
      } else {
        await apiJSON('/v1/groups', payload, { method: 'POST' });
      }

      onSave();
      onClose();
    } catch (err: any) {
      setApiError(err.message || 'Failed to save group');
    } finally {
      setSaving(false);
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-slate-900/20 backdrop-blur-sm z-[100]"
            onClick={onClose}
          />
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-2xl bg-white/80 backdrop-blur-xl border border-white rounded-3xl shadow-2xl z-[101] overflow-hidden flex flex-col max-h-[90vh]"
          >
            <div className="flex items-center justify-between p-6 border-b border-black/5 bg-white/50">
              <h2 className="text-xl font-semibold text-slate-900">
                {group ? 'Edit Policy Group' : 'New Policy Group'}
              </h2>
              <button
                onClick={onClose}
                className="p-2 hover:bg-slate-100 rounded-full text-slate-500 transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            <div className="p-6 overflow-y-auto flex-1 custom-scrollbar">
              <form id="group-form" onSubmit={handleSubmit(onSubmit)} className="space-y-8">
                
                {apiError && (
                  <div className="p-4 bg-red-50 text-red-600 rounded-2xl text-sm font-medium border border-red-100">
                    {apiError}
                  </div>
                )}

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1">Group Name</label>
                    <input
                      type="text"
                      {...register('name')}
                      placeholder="e.g., Office WiFi, Guest Network"
                      className={`w-full bg-white border rounded-xl px-4 py-2.5 text-sm outline-none focus:ring-2 transition-all ${errors.name ? 'border-rose-400 focus:ring-rose-500/20 focus:border-rose-500' : 'border-slate-200 focus:ring-sky-500/20 focus:border-sky-500'}`}
                    />
                    {errors.name && <p className="text-rose-500 text-xs mt-1">{errors.name.message}</p>}
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1">Description</label>
                    <input
                      type="text"
                      {...register('description')}
                      placeholder="Optional details about this group"
                      className={`w-full bg-white border rounded-xl px-4 py-2.5 text-sm outline-none focus:ring-2 transition-all ${errors.description ? 'border-rose-400 focus:ring-rose-500/20 focus:border-rose-500' : 'border-slate-200 focus:ring-sky-500/20 focus:border-sky-500'}`}
                    />
                    {errors.description && <p className="text-rose-500 text-xs mt-1">{errors.description.message}</p>}
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-bold tracking-wider uppercase text-slate-500 mb-4">Block Categories</h3>
                  <Controller
                    name="blockCategories"
                    control={control}
                    render={({ field }) => (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {CATEGORIES.map(cat => {
                          const active = field.value.includes(cat.id);
                          const Icon = cat.icon;
                          return (
                            <button
                              type="button"
                              key={cat.id}
                              onClick={() => {
                                const newValue = active
                                  ? field.value.filter((c: string) => c !== cat.id)
                                  : [...field.value, cat.id];
                                field.onChange(newValue);
                              }}
                              className={`flex items-center justify-between w-full p-4 rounded-2xl border transition-all ${
                                active 
                                  ? 'bg-sky-50/50 border-sky-200' 
                                  : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50'
                              }`}
                            >
                              <div className="flex items-center gap-3 text-left">
                                <div className={`p-2 rounded-xl shrink-0 ${active ? 'bg-sky-100 text-sky-600' : 'bg-slate-100 text-slate-500'}`}>
                                  <Icon size={18} />
                                </div>
                                <div>
                                  <div className={`font-semibold text-sm ${active ? 'text-sky-900' : 'text-slate-700'}`}>
                                    {cat.name}
                                  </div>
                                  <div className="text-xs text-slate-500 mt-0.5 line-clamp-2">
                                    {cat.desc}
                                  </div>
                                </div>
                              </div>
                              <div className={`w-11 h-6 rounded-full transition-colors flex items-center px-1 shrink-0 ml-3 ${active ? 'bg-sky-500' : 'bg-slate-200'}`}>
                                <div className={`w-4 h-4 bg-white rounded-full shadow-sm transition-transform ${active ? 'translate-x-5' : 'translate-x-0'}`} />
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    )}
                  />
                </div>

                <div>
                  <h3 className="text-sm font-bold tracking-wider uppercase text-slate-500 mb-4">Security Features</h3>
                  <div className="space-y-3">
                    <Controller
                      name="strictPhishing"
                      control={control}
                      render={({ field }) => (
                        <button
                          type="button"
                          onClick={() => field.onChange(!field.value)}
                          className={`flex items-center justify-between w-full p-4 rounded-2xl border transition-all ${
                            field.value ? 'bg-emerald-50/50 border-emerald-200' : 'bg-white border-slate-200 hover:border-slate-300'
                          }`}
                        >
                          <div className="flex items-center gap-3 text-left">
                            <div className={`p-2 rounded-xl shrink-0 ${field.value ? 'bg-emerald-100 text-emerald-600' : 'bg-slate-100 text-slate-500'}`}>
                              <Shield size={18} />
                            </div>
                            <div>
                              <div className={`font-semibold text-sm ${field.value ? 'text-emerald-900' : 'text-slate-700'}`}>
                                Strict Phishing Protection
                              </div>
                              <div className="text-xs text-slate-500 mt-0.5">
                                Aggressively block domains resembling popular brands.
                              </div>
                            </div>
                          </div>
                          <div className={`w-11 h-6 rounded-full transition-colors flex items-center px-1 shrink-0 ml-3 ${field.value ? 'bg-emerald-500' : 'bg-slate-200'}`}>
                            <div className={`w-4 h-4 bg-white rounded-full shadow-sm transition-transform ${field.value ? 'translate-x-5' : 'translate-x-0'}`} />
                          </div>
                        </button>
                      )}
                    />

                    <Controller
                      name="strictMalware"
                      control={control}
                      render={({ field }) => (
                        <button
                          type="button"
                          onClick={() => field.onChange(!field.value)}
                          className={`flex items-center justify-between w-full p-4 rounded-2xl border transition-all ${
                            field.value ? 'bg-rose-50/50 border-rose-200' : 'bg-white border-slate-200 hover:border-slate-300'
                          }`}
                        >
                          <div className="flex items-center gap-3 text-left">
                            <div className={`p-2 rounded-xl shrink-0 ${field.value ? 'bg-rose-100 text-rose-600' : 'bg-slate-100 text-slate-500'}`}>
                              <ShieldAlert size={18} />
                            </div>
                            <div>
                              <div className={`font-semibold text-sm ${field.value ? 'text-rose-900' : 'text-slate-700'}`}>
                                Strict Malware Filtering
                              </div>
                              <div className="text-xs text-slate-500 mt-0.5">
                                Block newly registered domains and low-reputation IPs.
                              </div>
                            </div>
                          </div>
                          <div className={`w-11 h-6 rounded-full transition-colors flex items-center px-1 shrink-0 ml-3 ${field.value ? 'bg-rose-500' : 'bg-slate-200'}`}>
                            <div className={`w-4 h-4 bg-white rounded-full shadow-sm transition-transform ${field.value ? 'translate-x-5' : 'translate-x-0'}`} />
                          </div>
                        </button>
                      )}
                    />
                  </div>
                </div>
              </form>
            </div>

            <div className="p-6 border-t border-black/5 bg-white/50 flex justify-end gap-3">
              <button
                type="button"
                onClick={onClose}
                className="px-5 py-2.5 rounded-xl text-sm font-medium text-slate-600 hover:bg-slate-100 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                form="group-form"
                disabled={saving}
                className="px-5 py-2.5 rounded-xl text-sm font-medium text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-50 transition-colors flex items-center gap-2"
              >
                {saving && (
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                )}
                {group ? 'Save Changes' : 'Create Group'}
              </button>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
