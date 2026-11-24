import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { ApiTable, LoadError, Loading, Metric, PageHeader, Panel } from '../components/Panel';

function RecordView({ value }: { value: unknown }) {
  if (Array.isArray(value)) {
    const rows = value.filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null);
    const keys = rows.length ? Object.keys(rows[0]).filter((key) => !['evidence', 'attributes', 'payload'].includes(key)).slice(0, 8) : [];
    return keys.length ? <ApiTable rows={rows} columns={keys.map((key) => ({ key, label: key.replaceAll('_', ' ') }))} /> : <div className="empty">No records in this result.</div>;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    const arrays = entries.filter(([, child]) => Array.isArray(child));
    return <div className="stack">{entries.filter(([, child]) => !Array.isArray(child) && (typeof child !== 'object' || child === null)).length > 0 && <div className="metric-grid">{entries.filter(([, child]) => !Array.isArray(child) && (typeof child !== 'object' || child === null)).map(([key, child]) => <Metric key={key} label={key.replaceAll('_', ' ')} value={typeof child === 'string' || typeof child === 'number' || typeof child === 'boolean' ? String(child) : '—'} />)}</div>}{arrays.map(([key, rows]) => <Panel key={key} title={key.replaceAll(/([A-Z])/g, ' $1').replaceAll('_', ' ')}><RecordView value={rows} /></Panel>)}{entries.filter(([, child]) => child && typeof child === 'object' && !Array.isArray(child)).map(([key, child]) => <Panel key={key} title={key.replaceAll('_', ' ')}><pre className="data-json">{JSON.stringify(child, null, 2)}</pre></Panel>)}</div>;
  }
  return <pre className="data-json">{String(value ?? 'No data returned.')}</pre>;
}

export function DataFeaturePage({ title, description, endpoint }: { title: string; description: string; endpoint: string }) {
  const query = useQuery({ queryKey: ['feature', endpoint], queryFn: () => api.get<unknown>(endpoint) });
  const auditCheck = useQuery({ queryKey: ['audit-integrity'], queryFn: () => api.get<{ valid: boolean; checked: number }>('/audit/verify'), enabled: false });
  return <>
    <PageHeader title={title} description={description} actions={<>{endpoint === '/audit' && <button className="secondary" onClick={() => void auditCheck.refetch()} disabled={auditCheck.isFetching}>{auditCheck.isFetching ? 'Verifying…' : 'Verify audit chain'}</button>}<button className="secondary" onClick={() => void query.refetch()} disabled={query.isFetching}>{query.isFetching ? 'Refreshing…' : 'Refresh'}</button></>} />
    {auditCheck.data && <div className={`notice ${auditCheck.data.valid ? 'success' : 'error'}`} role="status">Chain valid: {String(auditCheck.data.valid)} · {auditCheck.data.checked} events checked.</div>}
    {auditCheck.error && <div className="notice error">{auditCheck.error.message}</div>}
    {query.isPending ? <Loading /> : query.error ? <LoadError message={query.error.message} retry={() => void query.refetch()} /> : <RecordView value={query.data} />}
  </>;
}
