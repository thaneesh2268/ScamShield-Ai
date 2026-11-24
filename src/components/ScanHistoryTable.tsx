import { useMemo, useState } from 'react';
import { Search, Trash2 } from 'lucide-react';
import type { RiskLevel, ScamAnalysisResult } from '../types/scam';

interface ScanHistoryTableProps {
  history: ScamAnalysisResult[];
  activeId: string | null;
  onSelectScan: (scan: ScamAnalysisResult) => void;
  onClearHistory: () => void;
}

const RISK_TEXT_STYLE: Record<RiskLevel, string> = {
  Safe: 'text-emerald-700 dark:text-emerald-400 font-semibold',
  Suspicious: 'text-amber-700 dark:text-amber-400 font-semibold',
  'High Risk': 'text-red-700 dark:text-red-400 font-semibold',
};

export function ScanHistoryTable({
  history,
  activeId,
  onSelectScan,
  onClearHistory,
}: ScanHistoryTableProps) {
  const [riskFilter, setRiskFilter] = useState<'All' | RiskLevel>('All');
  const [searchQuery, setSearchQuery] = useState('');

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return history.filter((item) => {
      if (riskFilter !== 'All' && item.riskLevel !== riskFilter) return false;
      if (!q) return true;
      return (
        item.input.toLowerCase().includes(q) ||
        item.summary.toLowerCase().includes(q) ||
        item.detectedChannel.toLowerCase().includes(q)
      );
    });
  }, [history, riskFilter, searchQuery]);

  return (
    <section
      id="history"
      className="rounded-xl border border-slate-200 bg-white p-5 sm:p-6 dark:border-slate-800 dark:bg-slate-900"
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Recent Scans
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Saved locally in your browser session. Click any scan to inspect its full report.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 rounded-lg bg-slate-100 p-1 dark:bg-slate-800">
            {(['All', 'High Risk', 'Suspicious', 'Safe'] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                onClick={() => setRiskFilter(tab)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  riskFilter === tab
                    ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-slate-100'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>

          {history.length > 0 && (
            <button
              type="button"
              onClick={onClearHistory}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50 hover:text-slate-900 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100 cursor-pointer whitespace-nowrap shrink-0"
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
              Clear
            </button>
          )}
        </div>
      </div>

      {history.length > 0 && (
        <div className="relative mt-4 max-w-sm">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500"
            aria-hidden="true"
          />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter scan history..."
            aria-label="Filter scan history"
            className="w-full rounded-lg border border-slate-200 bg-slate-50 py-1.5 pl-8 pr-3 text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-950/60 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-blue-500 dark:focus:bg-slate-950"
          />
        </div>
      )}

      {history.length === 0 ? (
        <div className="mt-5 border-t border-slate-100 py-8 text-center dark:border-slate-800">
          <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
            No scans recorded yet
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Run any sample message or paste a link above to build your local audit log.
          </p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="mt-5 border-t border-slate-100 py-8 text-center dark:border-slate-800">
          <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
            No matching scans
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Adjust your filter or search query to view prior results.
          </p>
        </div>
      ) : (
        <div className="mt-4 overflow-x-auto border-t border-slate-100 dark:border-slate-800">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500 dark:border-slate-800 dark:text-slate-400">
                <th className="py-2.5 pr-4 font-medium">Verdict</th>
                <th className="py-2.5 pr-4 font-medium">Message Snippet</th>
                <th className="py-2.5 pr-4 font-medium">Channel</th>
                <th className="py-2.5 pr-4 font-medium">AI Engine</th>
                <th className="py-2.5 pr-4 text-right font-medium">Confidence</th>
                <th className="py-2.5 text-right font-medium">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
              {filtered.map((item) => {
                const isActive = item.id === activeId;
                return (
                  <tr
                    key={item.id}
                    onClick={() => onSelectScan(item)}
                    className={`cursor-pointer transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/50 ${
                      isActive ? 'bg-blue-50/50 dark:bg-blue-950/30' : ''
                    }`}
                  >
                    <td className={`py-2.5 pr-4 whitespace-nowrap ${RISK_TEXT_STYLE[item.riskLevel]}`}>
                      {item.riskLevel}
                    </td>
                    <td className="max-w-[340px] truncate py-2.5 pr-4 text-slate-800 dark:text-slate-200">
                      {item.input}
                    </td>
                    <td className="py-2.5 pr-4 whitespace-nowrap text-slate-600 dark:text-slate-400">
                      {item.detectedChannel}
                    </td>
                    <td className="py-2.5 pr-4 whitespace-nowrap text-slate-600 dark:text-slate-400">
                      {item.engine === 'on-device' ? 'On-Device' : 'Firebase AI Logic'}
                    </td>
                    <td className="py-2.5 pr-4 text-right font-mono tabular-nums text-slate-900 dark:text-slate-100">
                      {item.confidenceScore}%
                    </td>
                    <td className="py-2.5 text-right font-mono tabular-nums text-slate-500 dark:text-slate-400">
                      {item.latencyMs} ms
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
