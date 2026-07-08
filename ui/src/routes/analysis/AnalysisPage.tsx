import { ExternalLink, Search, ShieldAlert } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

export function AnalysisPage() {
  const [searchParams] = useSearchParams();
  const domain = searchParams.get('domain') || '';

  return (
    <section className="analysis-placeholder">
      <div className="eyebrow">React migration in progress</div>
      <h1 className="page-title">Analysis workspace is next in line</h1>
      <p className="page-copy">
        The telemetry and settings panels are now backed by the standalone React workspace. The
        detailed analysis flow has not been migrated yet, so this route acts as a jump point while
        we keep the API contract stable.
      </p>

      {domain ? (
        <div className="surface-card" style={{ padding: '18px 20px' }}>
          <div className="eyebrow">Selected domain</div>
          <h2 style={{ margin: '8px 0 4px' }}>
            <Search size={18} style={{ marginRight: 8, verticalAlign: 'text-bottom' }} />
            {domain}
          </h2>
          <p className="page-copy" style={{ marginTop: 0 }}>
            Use the existing dashboard while the React analysis route is being rebuilt around the
            same `/v1/analyze` and OSINT evidence APIs.
          </p>
        </div>
      ) : null}

      <div className="analysis-actions">
        <a className="button-primary" href={domain ? `/dashboard?domain=${encodeURIComponent(domain)}` : '/dashboard'}>
          <ExternalLink size={16} />
          Open legacy analysis flow
        </a>
        <a className="button-secondary" href="/dashboard">
          <ShieldAlert size={16} />
          Open full dashboard
        </a>
      </div>
    </section>
  );
}
