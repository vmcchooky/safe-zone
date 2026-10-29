/**
 * Trusted Brands card (OZ-12).
 *
 * Brand rules power the typosquat/spoofing heuristics: each rule pairs a
 * brand name with its official domain (plus alternates), and a domain that
 * imitates one is scored as brand spoofing. Full CRUD against
 * /v1/brands (GET list, POST create, PUT?id= update, DELETE?id=), following
 * the overrides page conventions: inline form, shared confirm dialog for
 * destructive actions, read-only sessions get disabled controls.
 */
import { useEffect, useState } from 'react';
import useSWR from 'swr';
import { motion } from 'framer-motion';
import { Building2, Pencil, Plus, ShieldCheck, X } from 'lucide-react';
import { apiFetch, apiJSON, messageFromError } from '../lib/api';
import { READ_ONLY_HINT, useCanMutate } from '../auth/AuthProvider';
import { useDialog } from './DialogContext';
import type { Brand } from '../lib/types';

const emptyForm = { name: '', official_domain: '', alt_domains: '' };

export function BrandsCard() {
  const canMutate = useCanMutate();
  const { alert, confirm } = useDialog();
  const [form, setForm] = useState(emptyForm);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [submitError, setSubmitError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { data, error, mutate } = useSWR<{ items: Brand[] }>('/v1/brands', apiFetch, {
    keepPreviousData: true,
  });

  useEffect(() => {
    if (!canMutate) {
      setSubmitError('');
    }
  }, [canMutate]);

  const brands = data?.items ?? [];

  const resetForm = () => {
    setForm(emptyForm);
    setEditingId(null);
    setSubmitError('');
  };

  const startEdit = (brand: Brand) => {
    setEditingId(brand.id ?? null);
    setForm({
      name: brand.name,
      official_domain: brand.official_domain,
      alt_domains: (brand.alt_domains ?? []).join(', '),
    });
    setSubmitError('');
  };

  const parseAltDomains = (raw: string) =>
    raw
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry !== '');

  const validate = (): string | null => {
    if (form.name.trim() === '') return 'Brand name is required';
    if (form.official_domain.trim() === '') return 'Official domain is required';
    if (
      !/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(
        form.official_domain.trim(),
      )
    ) {
      return 'Official domain must be a valid domain like brand.com';
    }
    return null;
  };

  const handleSubmit = async () => {
    if (!canMutate) {
      setSubmitError(READ_ONLY_HINT);
      return;
    }
    const validationError = validate();
    if (validationError) {
      setSubmitError(validationError);
      return;
    }
    setIsSubmitting(true);
    setSubmitError('');
    const payload = {
      name: form.name.trim(),
      official_domain: form.official_domain.trim(),
      alt_domains: parseAltDomains(form.alt_domains),
    };
    try {
      if (editingId !== null) {
        await apiJSON(`/v1/brands?id=${encodeURIComponent(String(editingId))}`, payload, { method: 'PUT' });
        await alert({ message: `Brand "${payload.name}" updated.`, type: 'success' });
      } else {
        await apiJSON('/v1/brands', payload, { method: 'POST' });
        await alert({ message: `Brand "${payload.name}" created.`, type: 'success' });
      }
      resetForm();
      await mutate();
    } catch (err) {
      setSubmitError(messageFromError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (brand: Brand) => {
    if (
      !(await confirm({
        message: `Delete the brand rule for ${brand.name}? Typosquat detection for it stops immediately.`,
        type: 'warning',
      }))
    ) {
      return;
    }
    try {
      await apiFetch(`/v1/brands?id=${encodeURIComponent(String(brand.id))}`, { method: 'DELETE' });
      if (editingId === brand.id) {
        resetForm();
      }
      await mutate();
      await alert({ message: `Brand "${brand.name}" deleted.`, type: 'success' });
    } catch (err) {
      await alert({
        message: `Failed to delete brand ${brand.name}: ${messageFromError(err)}`,
        type: 'error',
      });
    }
  };

  return (
    <section
      className="bg-white border border-black/5 rounded-3xl shadow-sm overflow-hidden"
      data-testid="brands-card"
    >
      <div className="p-6 pb-4">
        <div className="flex items-center gap-3 mb-1">
          <div className="p-2.5 bg-indigo-100/80 text-indigo-600 rounded-xl">
            <Building2 size={20} />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900">Trusted Brands</h2>
            <p className="text-sm text-slate-500">Rules that power typosquat and spoofing detection</p>
          </div>
        </div>
      </div>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          void handleSubmit();
        }}
        className="px-6 pb-4 flex flex-wrap items-start gap-3"
      >
        <div className="flex-1 min-w-[180px] space-y-1">
          <input
            type="text"
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
            placeholder="Brand name (e.g., vietcombank)"
            disabled={isSubmitting || !canMutate}
            className="w-full h-11 px-4 bg-white/80 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 shadow-sm disabled:opacity-50"
          />
        </div>
        <div className="flex-1 min-w-[220px] space-y-1">
          <input
            type="text"
            value={form.official_domain}
            onChange={(event) => setForm({ ...form, official_domain: event.target.value })}
            placeholder="Official domain (e.g., vietcombank.com.vn)"
            disabled={isSubmitting || !canMutate}
            className="w-full h-11 px-4 bg-white/80 border border-slate-200 rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 shadow-sm disabled:opacity-50"
          />
        </div>
        <div className="flex-1 min-w-[220px] space-y-1">
          <input
            type="text"
            value={form.alt_domains}
            onChange={(event) => setForm({ ...form, alt_domains: event.target.value })}
            placeholder="Alternate domains, comma-separated (optional)"
            disabled={isSubmitting || !canMutate}
            className="w-full h-11 px-4 bg-white/80 border border-slate-200 rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 shadow-sm disabled:opacity-50"
          />
        </div>
        {editingId !== null ? (
          <>
            <motion.button
              type="submit"
              disabled={isSubmitting || !canMutate}
              title={canMutate ? 'Save the brand rule' : READ_ONLY_HINT}
              className="w-24 h-11 bg-slate-900 text-white text-sm font-medium rounded-xl hover:bg-slate-800 disabled:opacity-50 disabled:pointer-events-none shadow-sm flex items-center justify-center gap-2"
            >
              {isSubmitting ? '...' : 'Save'}
            </motion.button>
            <button
              type="button"
              onClick={resetForm}
              title="Cancel editing"
              className="w-11 h-11 flex items-center justify-center rounded-xl border border-slate-200 text-slate-500 hover:bg-slate-50"
            >
              <X size={16} />
            </button>
          </>
        ) : (
          <motion.button
            type="submit"
            disabled={isSubmitting || !canMutate}
            title={canMutate ? 'Add the brand rule' : READ_ONLY_HINT}
            className="w-24 h-11 bg-slate-900 text-white text-sm font-medium rounded-xl hover:bg-slate-800 disabled:opacity-50 disabled:pointer-events-none shadow-sm flex items-center justify-center gap-2"
          >
            <Plus size={16} />
            {isSubmitting ? '...' : 'Add'}
          </motion.button>
        )}
      </form>
      {submitError && (
        <p
          className="mx-6 mb-4 text-sm text-rose-600 bg-rose-50 p-3 rounded-lg border border-rose-100"
          data-testid="brands-form-error"
        >
          {submitError}
        </p>
      )}

      <div className="pb-6">
        {error ? (
          <div className="px-6 py-8 text-center" data-testid="brands-error">
            <ShieldCheck className="w-10 h-10 text-rose-400 mx-auto mb-2 opacity-60" />
            <h3 className="text-base font-semibold text-slate-800">Failed to load brands</h3>
            <p className="text-sm text-slate-500 mt-1">{messageFromError(error)}</p>
          </div>
        ) : !data ? (
          <div className="px-6 py-8 flex justify-center" data-testid="brands-loading">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : brands.length === 0 ? (
          <div className="px-6 py-8 text-center" data-testid="brands-empty">
            <h3 className="text-base font-semibold text-slate-800">No Brand Rules</h3>
            <p className="text-sm text-slate-500 mt-1">
              Add the brands your users need protected; imitating domains will be scored as spoofing.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-50/50 text-slate-500 border-y border-slate-200/50">
                <tr>
                  <th className="px-6 py-3 font-medium">Brand</th>
                  <th className="px-6 py-3 font-medium">Official Domain</th>
                  <th className="px-6 py-3 font-medium">Alternates</th>
                  <th className="px-6 py-3 font-medium text-right w-32">Manage</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100/80">
                {brands.map((brand) => (
                  <tr key={brand.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-6 py-3 font-medium text-slate-700">{brand.name}</td>
                    <td className="px-6 py-3 font-mono text-slate-600">{brand.official_domain}</td>
                    <td
                      className="px-6 py-3 font-mono text-slate-500 max-w-[18rem] truncate"
                      title={(brand.alt_domains ?? []).join(', ')}
                    >
                      {(brand.alt_domains ?? []).join(', ') || '—'}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <div className="inline-flex gap-2">
                        <button
                          type="button"
                          onClick={() => startEdit(brand)}
                          disabled={!canMutate}
                          title={canMutate ? `Edit the brand rule for ${brand.name}` : READ_ONLY_HINT}
                          aria-label={`Edit the brand rule for ${brand.name}`}
                          className="p-2 rounded-lg border border-slate-200 text-slate-500 hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <Pencil size={14} />
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDelete(brand)}
                          disabled={!canMutate}
                          title={canMutate ? `Delete the brand rule for ${brand.name}` : READ_ONLY_HINT}
                          aria-label={`Delete the brand rule for ${brand.name}`}
                          className="p-2 rounded-lg border border-rose-200 text-rose-600 hover:bg-rose-50 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <X size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
