import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { api, type Asset, type Page } from '../api/client';
import { ApiTable, LoadError, Loading, Metric, PageHeader, Panel } from '../components/Panel';

type Dashboard = { assets: number; websites: number; servers: number; openFindings: number; bySeverity: Record<string, number>; compliancePercent: number; nonCompliantAssets: number; websitesWafProtected: number; websitesTotal: number; generatedAt: string };

export function DashboardPage() {
  const [entity, setEntity] = useState('');
  const query = useQuery({ queryKey: ['dashboard', entity], queryFn: async () => {
    const query = entity ? `?entity=${entity}` : '';
    const [dashboard, assets] = await Promise.all([api.get<Dashboard>(`/dashboard${query}`), api.get<Page<Asset>>(`/assets?limit=500${entity ? `&entity=${entity}` : ''}`)]);
    return { dashboard, assets: assets.items };
  } });
  return <>
    <PageHeader title="Security overview" description="Current inventory, vulnerability exposure, and compliance from SAM’s persisted records." actions={<select aria-label="Asset scope" value={entity} onChange={(event) => setEntity(event.target.value)}><option value="">All assets</option><option value="Website">Websites</option><option value="Server">Servers</option></select>} />
    {query.isPending ? <Loading /> : query.error ? <LoadError message={query.error.message} retry={() => void query.refetch()} /> : <>
      <div className="metric-grid">
        <Metric label="Assets monitored" value={query.data.dashboard.assets} footnote={`${query.data.dashboard.websites} websites · ${query.data.dashboard.servers} servers`} />
        <Metric label="Open findings" value={query.data.dashboard.openFindings} footnote={`${query.data.dashboard.bySeverity.Critical ?? 0} critical · ${query.data.dashboard.bySeverity.High ?? 0} high`} />
        <Metric label="Below 80% compliance" value={query.data.dashboard.nonCompliantAssets} />
        <Metric label="Recorded compliance" value={`${query.data.dashboard.compliancePercent}%`} />
        <Metric label="Websites with recorded WAF protection" value={`${query.data.dashboard.websitesWafProtected}/${query.data.dashboard.websitesTotal}`} footnote="Provider evidence still needs verification." />
      </div>
      <Panel title="Asset posture"><ApiTable rows={query.data.assets} columns={[{ key: 'name', label: 'Asset' }, { key: 'kind', label: 'Type' }, { key: 'classification', label: 'Classification' }, { key: 'owner', label: 'Owner' }, { key: 'criticality', label: 'Criticality' }, { key: 'compliance', label: 'Compliance %' }, { key: 'status', label: 'Status' }]} /></Panel>
      <p className="data-caption">Updated {new Date(query.data.dashboard.generatedAt).toLocaleString()}</p>
    </>}
  </>;
}
