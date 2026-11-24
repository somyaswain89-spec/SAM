import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../auth/AuthContext';
import { api } from '../api/client';
import { ApiTable, LoadError, Loading, PageHeader, Panel } from '../components/Panel';
import './ThreatsPage.css';

type ThreatIntelItem = {
  findingId: string;
  cve: string;
  title: string;
  severity: string;
  assetId: string;
  assetName: string;
  assetType: 'Website' | 'Server';
  classification: string;
  criticality: string;
  kevListed: boolean | null;
  kevDateAdded: string | null;
  kevDueDate: string | null;
  kevVendor: string | null;
  kevProduct: string | null;
  kevRequiredAction: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  epssDate: string | null;
};
type ThreatIntelResponse = {
  summary: {
    openFindingsWithCve: number;
    kevImpactedFindings: number;
    epssAtLeast50PercentFindings: number;
    feedStatus: string;
    lastSyncAt: string | null;
    lastSyncError: string | null;
    recordsRead: number;
    recordsWritten: number;
  };
  items: ThreatIntelItem[];
  total: number;
  interpretation: string;
};
type ZeroDayResponse = {
  signals: Array<{ id: string; title: string; severity: string; confidence: string; status: string; source: string; impactedAssets: unknown[] }>;
  candidateFindings: Array<Record<string, unknown>>;
  warning: string;
};
type SyncRun = { id: string; status: string; task_id: string };

export function ThreatsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [entity, setEntity] = useState('');
  const [cve, setCve] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [minimumEpss, setMinimumEpss] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 100;
  const queryParameters = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (entity) queryParameters.set('entity', entity);
  if (cve.trim()) queryParameters.set('cve', cve.trim());
  if (kevOnly) queryParameters.set('kev_only', 'true');
  if (minimumEpss) queryParameters.set('min_epss', minimumEpss);
  const intelligence = useQuery({
    queryKey: ['threat-intelligence', entity, cve, kevOnly, minimumEpss, offset],
    queryFn: () => api.get<ThreatIntelResponse>(`/threats/intelligence?${queryParameters.toString()}`),
    refetchInterval: (query) => ['queued', 'running'].includes(query.state.data?.summary.feedStatus ?? '') ? 3000 : false,
  });
  const zeroDay = useQuery({ queryKey: ['zero-day-signals'], queryFn: () => api.get<ZeroDayResponse>('/threats/zero-day-signals') });
  const sync = useMutation({
    mutationFn: () => api.post<SyncRun>('/integrations/threat_intel/sync'),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['threat-intelligence'] }); },
  });
  const canSync = user?.role === 'admin' || user?.role === 'security_admin';
  const rows = (intelligence.data?.items ?? []).map((item) => ({
    ...item,
    kevListed: item.kevListed === null ? 'Not enriched' : item.kevListed ? 'Yes' : 'No',
    epssScore: item.epssScore === null ? 'Not enriched' : item.epssScore.toFixed(3),
    epssPercentile: item.epssPercentile === null ? 'Not enriched' : item.epssPercentile.toFixed(3),
  }));
  const signalRows = (zeroDay.data?.signals ?? []).map(({ impactedAssets, ...signal }) => ({ ...signal, impactedAssetCount: impactedAssets.length }));

  return <>
    <PageHeader
      title="Threat intelligence"
      description="Match persisted findings to CISA Known Exploited Vulnerabilities and FIRST EPSS data, with each impacted asset visible."
      actions={canSync ? <button className="primary" onClick={() => sync.mutate()} disabled={sync.isPending || ['queued', 'running'].includes(intelligence.data?.summary.feedStatus ?? '')}>{sync.isPending ? 'Queueing feed sync…' : 'Sync threat feeds'}</button> : undefined}
    />
    {sync.error && <div className="notice error" role="alert">{sync.error.message}</div>}
    {sync.data && <div className="notice success" role="status">Threat-feed sync queued: {sync.data.id}.</div>}
    {intelligence.isPending ? <Loading /> : intelligence.error ? <LoadError message={intelligence.error.message} retry={() => void intelligence.refetch()} /> : <>
      <div className="notice">{intelligence.data.interpretation}</div>
      {intelligence.data.summary.feedStatus === 'never_synced' && <div className="notice">Threat-feed data has not been synchronized yet. Current CVE exposure cannot be confirmed from these feeds.</div>}
      {intelligence.data.summary.lastSyncError && <div className="notice error" role="status">Latest sync failed: {intelligence.data.summary.lastSyncError}</div>}
      <Panel title="Feed coverage">
        <div className="metric-grid">
          <div className="metric"><span>Open findings with CVE</span><strong>{intelligence.data.summary.openFindingsWithCve}</strong></div>
          <div className="metric"><span>Impacted findings in CISA KEV</span><strong>{intelligence.data.summary.kevImpactedFindings}</strong></div>
          <div className="metric"><span>Impacted findings with EPSS ≥ 0.50</span><strong>{intelligence.data.summary.epssAtLeast50PercentFindings}</strong></div>
          <div className="metric"><span>Feed sync</span><strong>{intelligence.data.summary.feedStatus}</strong><small>{intelligence.data.summary.lastSyncAt ?? 'No completed sync'}</small></div>
        </div>
      </Panel>
      <Panel title="Prioritized impacted findings">
        <div className="filters">
          <input aria-label="Search CVE" placeholder="Search CVE" maxLength={40} value={cve} onChange={(event) => { setCve(event.target.value); setOffset(0); }} />
          <select aria-label="Asset type filter" value={entity} onChange={(event) => { setEntity(event.target.value); setOffset(0); }}><option value="">All assets</option><option value="Website">Websites</option><option value="Server">Servers</option></select>
          <label className="inline-check"><input type="checkbox" checked={kevOnly} onChange={(event) => { setKevOnly(event.target.checked); setOffset(0); }} /> CISA KEV only</label>
          <select aria-label="Minimum EPSS" value={minimumEpss} onChange={(event) => { setMinimumEpss(event.target.value); setOffset(0); }}><option value="">Any EPSS score</option><option value="0.1">EPSS ≥ 0.10</option><option value="0.5">EPSS ≥ 0.50</option><option value="0.9">EPSS ≥ 0.90</option></select>
          <span className="pill">{intelligence.data.total} findings</span>
        </div>
        <ApiTable rows={rows} columns={[
          { key: 'cve', label: 'CVE' }, { key: 'findingId', label: 'Finding' }, { key: 'severity', label: 'Severity' },
          { key: 'assetId', label: 'Impacted asset' }, { key: 'assetName', label: 'Asset name' }, { key: 'assetType', label: 'Type' },
          { key: 'classification', label: 'Exposure' }, { key: 'criticality', label: 'Criticality' }, { key: 'kevListed', label: 'CISA KEV' },
          { key: 'kevDateAdded', label: 'KEV added' }, { key: 'kevDueDate', label: 'KEV due' },
          { key: 'epssScore', label: 'EPSS probability' }, { key: 'epssPercentile', label: 'EPSS percentile' }, { key: 'epssDate', label: 'EPSS date' },
        ]} />
        <div className="pagination"><button className="secondary" disabled={offset === 0 || intelligence.isFetching} onClick={() => setOffset(Math.max(0, offset - limit))}>Previous</button><span>{intelligence.data.total === 0 ? 0 : offset + 1}–{Math.min(offset + limit, intelligence.data.total)} of {intelligence.data.total}</span><button className="secondary" disabled={offset + limit >= intelligence.data.total || intelligence.isFetching} onClick={() => setOffset(offset + limit)}>Next</button></div>
        <small>{intelligence.data.summary.recordsRead} feed records read · {intelligence.data.summary.recordsWritten} CVE records updated · source: CISA KEV and FIRST EPSS</small>
      </Panel>
    </>}
    <Panel title="Zero-day investigation signals">
      {zeroDay.isPending ? <Loading /> : zeroDay.error ? <LoadError message={zeroDay.error.message} retry={() => void zeroDay.refetch()} /> : <>
        <div className="notice">{zeroDay.data.warning}</div>
        <ApiTable rows={signalRows} columns={[
          { key: 'id', label: 'Signal' }, { key: 'title', label: 'Title' }, { key: 'severity', label: 'Severity' },
          { key: 'confidence', label: 'Confidence' }, { key: 'status', label: 'Status' }, { key: 'source', label: 'Source' },
          { key: 'impactedAssetCount', label: 'Impacted assets' },
        ]} />
        <h3>Unlinked open findings</h3>
        <ApiTable rows={zeroDay.data.candidateFindings} columns={[
          { key: 'finding_id', label: 'Finding' }, { key: 'title', label: 'Title' }, { key: 'severity', label: 'Severity' },
          { key: 'asset_id', label: 'Impacted asset' }, { key: 'name', label: 'Asset name' },
        ]} />
      </>}
    </Panel>
  </>;
}
