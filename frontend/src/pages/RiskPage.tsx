import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { ApiTable, LoadError, Loading, PageHeader, Panel } from '../components/Panel';

export function RiskPage() {
  const query = useQuery({ queryKey: ['risk-page'], queryFn: async () => {
    const [priorities, forecast] = await Promise.all([api.get<{ items: Array<Record<string, unknown>>; scoreModel: string }>('/risk/priorities?limit=500'), api.get<{ breached: Array<Record<string, unknown>>; atRiskNext7Days: Array<Record<string, unknown>>; forecastMethod: string }>('/risk/sla-forecast')]);
    return { priorities, forecast };
  } });
  return <>
    <PageHeader title="Risk & SLA" description="Risk scores are a transparent prioritization heuristic. SLA forecasts use only explicit due dates." />
    {query.isPending ? <Loading /> : query.error ? <LoadError message={query.error.message} retry={() => void query.refetch()} /> : <>
      <div className="metric-grid"><div className="metric"><span>Breached due dates</span><strong>{query.data.forecast.breached.length}</strong></div><div className="metric"><span>Due in seven days</span><strong>{query.data.forecast.atRiskNext7Days.length}</strong></div></div>
      <Panel title="Prioritized findings"><ApiTable rows={query.data.priorities.items} columns={[{ key: 'id', label: 'Finding' }, { key: 'title', label: 'Title' }, { key: 'severity', label: 'Severity' }, { key: 'riskScore', label: 'Risk score' }, { key: 'kev', label: 'CISA KEV' }, { key: 'epss', label: 'EPSS score' }, { key: 'threatIntelSource', label: 'Threat source' }, { key: 'asset_id', label: 'Asset' }, { key: 'classification', label: 'Exposure' }, { key: 'due_at', label: 'Due date' }]} /></Panel>
      <Panel title="SLA forecast"><h3>Breached</h3><ApiTable rows={query.data.forecast.breached} columns={[{ key: 'findingId', label: 'Finding' }, { key: 'title', label: 'Title' }, { key: 'assetId', label: 'Asset' }, { key: 'daysRemaining', label: 'Days overdue' }]} /><h3>Due in next seven days</h3><ApiTable rows={query.data.forecast.atRiskNext7Days} columns={[{ key: 'findingId', label: 'Finding' }, { key: 'title', label: 'Title' }, { key: 'assetId', label: 'Asset' }, { key: 'daysRemaining', label: 'Days remaining' }]} /><small>{query.data.forecast.forecastMethod} {query.data.priorities.scoreModel}</small></Panel>
    </>}
  </>;
}
