import { useCallback, useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useForm, Controller, type FieldErrors } from 'react-hook-form';
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
  const panelRef = useRef<HTMLDivElement | null>(null);
  const openerRef = useRef<HTMLElement | null>(null);
  // Mirrored synchronously during render: the autoFocus focusin fires inside
  // the commit phase, before any effect has a chance to detach listeners, so
  // the tracker must consult the render-time open state, not effect timing.
  const isOpenRef = useRef(isOpen);
  isOpenRef.current = isOpen;

  // Focus lifecycle: remember the last element focused OUTSIDE the dialog
  // while it is closed, so focus can be handed back to it (the opener) when
  // the dialog closes (WCAG 2.4.3 — focus must not drop to <body> behind a
  // now-closed overlay). Sampling activeElement on open alone would capture
  // the autoFocus target inside the panel instead of the real opener.
  useEffect(() => {
    const trackFocus = (e: FocusEvent) => {
      if (isOpenRef.current) return; // dialog open: never record
      const target = e.target as HTMLElement | null;
      if (!target || target === document.body) return;
      openerRef.current = target;
    };
    document.addEventListener('focusin', trackFocus);
    return () => document.removeEventListener('focusin', trackFocus);
  }, []);

  // While open, freeze the opener snapshot; on close (or unmount) restore.
  useEffect(() => {
    if (!isOpen) return;
    const opener = openerRef.current;
    return () => {
      openerRef.current = null;
      if (opener && document.contains(opener)) opener.focus();
    };
  }, [isOpen]);

  // Single close entry point: hands focus back to the opener on a microtask
  // right after React's synchronous flush for the discrete close event. The
  // effect cleanup above stays as a fallback, but it alone proved flaky when
  // React's commit timing interleaved with the exiting panel's unmount.
  const closeAndRestoreFocus = useCallback(() => {
    const opener = openerRef.current;
    onClose();
    if (opener && document.contains(opener)) {
      queueMicrotask(() => opener.focus());
    }
  }, [onClose]);

  const { register, handleSubmit, control, reset, formState: { errors } } = useForm<GroupFormValues>({
    resolver: zodResolver(groupSchema),
    // RHF's built-in focus-on-error resolves ASYNC (after the zod resolver's
    // promise) and races the modal close: it refocuses the invalid field even
    // after the user has dismissed the dialog, stealing focus back from the
    // restored opener. We focus the first error field ourselves, only while
    // the dialog is still open.
    shouldFocusError: false,
    defaultValues: {
      name: '',
      description: '',
      blockCategories: [],
      strictPhishing: false,
      strictMalware: false,
    }
  });

  const handleInvalid = (errs: FieldErrors<GroupFormValues>) => {
    if (!isOpenRef.current) return;
    if (errs.name) document.getElementById('group-name-input')?.focus();
    else if (errs.description) document.getElementById('group-description-input')?.focus();
  };

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

  // Modal keyboard contract: Escape dismisses, and Tab cycles inside the
  // dialog instead of reaching the inert background page.
  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        closeAndRestoreFocus();
        return;
      }
      if (e.key !== 'Tab' || !panelRef.current) return;
      // Only truly focusable children may receive the wrapped Tab: disabled
      // controls and display/visibility-hidden (or zero-size) elements would
      // otherwise capture focus invisibly and break the cycle.
      const focusables = Array.from(
        panelRef.current.querySelectorAll<HTMLElement>(
          'button, a[href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((el) => {
        if (el.hasAttribute('disabled') || el.getAttribute('aria-disabled') === 'true') return false;
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden') return false;
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      });
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [isOpen, closeAndRestoreFocus]);

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
      // Same close path as Cancel/Escape/backdrop: hands focus back to the
      // opener instead of dropping it at <body> when the panel unmounts.
      closeAndRestoreFocus();
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
            aria-hidden="true"
            className="fixed inset-0 bg-slate-900/20 backdrop-blur-sm z-[100]"
            onClick={closeAndRestoreFocus}
          />
          <motion.div
            ref={panelRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="group-modal-title"
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-2xl bg-white/80 backdrop-blur-xl border border-white rounded-3xl shadow-2xl z-[101] overflow-hidden flex flex-col max-h-[90vh]"
          >
            <div className="flex items-center justify-between p-6 border-b border-black/5 bg-white/50">
              <h2 id="group-modal-title" className="text-xl font-semibold text-slate-900">
                {group ? 'Edit Policy Group' : 'New Policy Group'}
              </h2>
              <button
                onClick={closeAndRestoreFocus}
                aria-label="Close"
                className="p-2 hover:bg-slate-100 rounded-full text-slate-500 transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            <div className="p-6 overflow-y-auto flex-1 custom-scrollbar">
              <form id="group-form" onSubmit={handleSubmit(onSubmit, handleInvalid)} className="space-y-8">
                
                {apiError && (
                  <div role="alert" className="p-4 bg-red-50 text-red-600 rounded-2xl text-sm font-medium border border-red-100">
                    {apiError}
                  </div>
                )}

                <div className="space-y-4">
                  <div>
                    <label htmlFor="group-name-input" className="block text-sm font-semibold text-slate-700 mb-1">Group Name</label>
                    <input
                      id="group-name-input"
                      type="text"
                      autoFocus
                      aria-invalid={errors.name ? true : undefined}
                      aria-describedby={errors.name ? 'group-name-error' : undefined}
                      {...register('name')}
                      placeholder="e.g., Office WiFi, Guest Network"
                      className={`w-full bg-white border rounded-xl px-4 py-2.5 text-sm outline-none focus:ring-2 transition-all ${errors.name ? 'border-rose-400 focus:ring-rose-500/20 focus:border-rose-500' : 'border-slate-200 focus:ring-sky-500/20 focus:border-sky-500'}`}
                    />
                    {errors.name && <p id="group-name-error" className="text-rose-500 text-xs mt-1">{errors.name.message}</p>}
                  </div>
                  <div>
                    <label htmlFor="group-description-input" className="block text-sm font-semibold text-slate-700 mb-1">Description</label>
                    <input
                      id="group-description-input"
                      type="text"
                      aria-invalid={errors.description ? true : undefined}
                      aria-describedby={errors.description ? 'group-description-error' : undefined}
                      {...register('description')}
                      placeholder="Optional details about this group"
                      className={`w-full bg-white border rounded-xl px-4 py-2.5 text-sm outline-none focus:ring-2 transition-all ${errors.description ? 'border-rose-400 focus:ring-rose-500/20 focus:border-rose-500' : 'border-slate-200 focus:ring-sky-500/20 focus:border-sky-500'}`}
                    />
                    {errors.description && <p id="group-description-error" className="text-rose-500 text-xs mt-1">{errors.description.message}</p>}
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
                              aria-pressed={active}
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
                          aria-pressed={field.value}
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
                          aria-pressed={field.value}
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
                onClick={closeAndRestoreFocus}
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
