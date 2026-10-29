/**
 * Whitelist Snapshots & Rollback card.
 *
 * The whitelist is replaced wholesale by imports, and every import stores a
 * rollback snapshot (internal/store/whitelist_snapshot.go). This card is the
 * operator surface for those snapshots: list them, see the last rollback,
 * and roll back with a mandatory reason (the API refuses reasons shorter
 * than 8 characters, and the client validates the same rule before asking
 * for confirmation). Reads and writes are admin-only on the backend; the
 * card follows the system-page convention of disabling mutation controls for
 * read-only sessions.
 */
import { useState } from 'react';
import useSWR from 'swr';
import { motion } from 'framer-motion';
import { History, RotateCcw } from 'lucide-react';
import { apiFetch, apiJSON, messageFromError } from '../lib/api';
import { READ_ONLY_HINT, useCanMutate } from '../auth/AuthProvider';
import { useDialog } from './DialogContext';
import { globalLoader } from '../App';
import type { WhitelistSnapshotsResponse } from '../lib/types';

const MIN_REASON_LENGTH = 8;

export function WhitelistSnapshotsCard() {
  const canMutate = useCanMutate();
  const { alert, confirm } = useDialog();
  const [reason, setReason] = useState('');
  const [rollingBackId, setRollingBackId] = useState<number | null>(null);

  const { data, error, mutate } = useSWR<WhitelistSnapshotsResponse>('/v1/whitelist/snapshots', apiFetch, {
    refreshInterval: 30000,
    keepPreviousData: true,
  });

  const snapshots = data?.snapshots ?? [];
  const lastRollback = data?.last_rollback ?? null;
  const reasonReady = reason.trim().length >= MIN_REASON_LENGTH;

  const handleRollback = async (snapshotId: number, entryCount: number) => {
    if (!canMutate) {
      await alert({ message: READ_ONLY_HINT, type: 'error' });
      return;
    }
    if (!reasonReady) {
      await alert({
        message: `A reason of at least ${MIN_REASON_LENGTH} characters is required before rolling back.`,
        type: 'warning',
      });
      return;
    }
    const trimmed = reason.trim();
    if (
      !(await confirm({
        message: `Restore the whitelist from snapshot ${snapshotId} (${entryCount.toLocaleString()} entries)? The current allow list is replaced and the rollback is audited.`,
        type: 'warning',
        confirmText: 'Roll Back',
      }))
    ) {
      return;
    }

    setRollingBackId(snapshotId);
    globalLoader.show();
    try {
      const result = await apiJSON<{ status: string; snapshot: number; entries: number }>(
        `/v1/whitelist/rollback?id=${encodeURIComponent(String(snapshotId))}`,
        { reason: trimmed },
        { method: 'POST' },
      );
      setReason('');
      await mutate();
      await alert({
        message: `Whitelist restored to snapshot ${result.snapshot} (${result.entries.toLocaleString()} entries). The change is published to the resolvers within one poll interval.`,
        type: 'success',
      });
    } catch (err) {
      await alert({ message: `Rollback failed: ${messageFromError(err)}`, type: 'error' });
    } finally {
      setRollingBackId(null);
      globalLoader.hide();
    }
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: 0.2, ease: 'easeOut' }}
      className="bg-transparent border border-black/5 rounded-3xl p-6 shadow-sm relative overflow-hidden flex flex-col h-full lg:col-span-3"
      data-testid="whitelist-snapshots-card"
    >
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2.5 bg-teal-100/80 text-teal-600 rounded-xl">
          <History size={20} />
        </div>
        <div>
          <h2 className="text-lg font-bold text-slate-900">Whitelist Snapshots</h2>
          <p className="text-sm text-slate-500">Roll the allow list back to a verified import</p>
        </div>
      </div>

      {error ? (
        <div
          className="flex-1 flex flex-col items-center justify-center p-8 text-center"
          data-testid="whitelist-snapshots-error"
        >
          <h3 className="text-base font-semibold text-slate-800">Failed to load whitelist snapshots</h3>
          <p className="text-sm text-slate-500 mt-1">{messageFromError(error)}</p>
          <button
            type="button"
            onClick={() => void mutate()}
            className="mt-4 px-4 py-2 text-sm font-medium rounded-xl bg-slate-900 text-white hover:bg-slate-800"
          >
            Retry
          </button>
        </div>
      ) : !data ? (
        <div
          className="flex-1 flex items-center justify-center p-8"
          data-testid="whitelist-snapshots-loading"
        >
          <div className="w-8 h-8 border-2 border-teal-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : snapshots.length === 0 ? (
        <div
          className="flex-1 flex flex-col items-center justify-center p-8 text-center"
          data-testid="whitelist-snapshots-empty"
        >
          <h3 className="text-base font-semibold text-slate-800">No Whitelist Snapshots</h3>
          <p className="text-sm text-slate-500 mt-1">
            Snapshots are stored automatically each time the allow list is replaced by an import.
          </p>
        </div>
      ) : (
        <>
          {lastRollback && (
            <div className="mb-4 p-4 rounded-2xl bg-amber-50/60 border border-amber-100 text-sm text-slate-600">
              <span className="font-medium text-slate-800">Last rollback:</span> snapshot{' '}
              {lastRollback.snapshot_id} restored by {lastRollback.actor || 'admin'} at{' '}
              {lastRollback.created_at} ({lastRollback.entries.toLocaleString()} entries, revision{' '}
              {lastRollback.revision}).
            </div>
          )}
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-50/50 text-slate-500 border-b border-slate-200/50">
                <tr>
                  <th className="px-4 py-3 font-medium">Snapshot</th>
                  <th className="px-4 py-3 font-medium">Created</th>
                  <th className="px-4 py-3 font-medium">Source</th>
                  <th className="px-4 py-3 font-medium text-right">Entries</th>
                  <th className="px-4 py-3 font-medium text-right w-32">Manage</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100/80">
                {snapshots.map((snapshot) => (
                  <tr key={snapshot.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-4 py-3 font-mono text-slate-700">#{snapshot.id}</td>
                    <td className="px-4 py-3 text-slate-600">{snapshot.created_at}</td>
                    <td className="px-4 py-3 text-slate-600 max-w-[16rem] truncate" title={snapshot.source}>
                      {snapshot.source}
                    </td>
                    <td className="px-4 py-3 text-right text-slate-600">
                      {snapshot.entry_count.toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => void handleRollback(snapshot.id, snapshot.entry_count)}
                        disabled={rollingBackId !== null || !canMutate}
                        title={
                          canMutate ? `Roll back the whitelist to snapshot ${snapshot.id}` : READ_ONLY_HINT
                        }
                        aria-label={`Roll back the whitelist to snapshot ${snapshot.id}`}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-900 text-white hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        <RotateCcw
                          size={13}
                          className={rollingBackId === snapshot.id ? 'animate-spin' : ''}
                        />
                        {rollingBackId === snapshot.id ? 'Rolling Back...' : 'Roll Back'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4">
            <label htmlFor="rollback-reason" className="block text-xs font-medium text-slate-500 mb-1">
              Rollback reason (required, at least {MIN_REASON_LENGTH} characters) — recorded in the audit log
            </label>
            <input
              id="rollback-reason"
              type="text"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="e.g., reverting the bad Tranco import"
              disabled={!canMutate || rollingBackId !== null}
              className="w-full h-11 px-4 bg-white/80 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-teal-500/20 focus:border-teal-500 shadow-sm disabled:opacity-50"
            />
          </div>
        </>
      )}
    </motion.section>
  );
}
