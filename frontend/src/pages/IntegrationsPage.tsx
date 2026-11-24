import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../auth/AuthContext';
import { api } from '../api/client';
import { ApiTable, LoadError, Loading, PageHeader, Panel } from '../components/Panel';

type Connector = { id: 'qualys' | 'servicenow' | 'threat_intel'; name: string; status: string; configured: boolean; tables?: string[]; capabilities: string[] };
type SyncRun = { id: string; source: string; status: string; started_at: string; finished_at?: string | null; records_read: number; records_written: number; error?: string | null };
type StatusResponse = { connectors: Connector[]; recentRuns: SyncRun[]; note: string; ticketWriteConfigured: boolean; aiAnalystConfigured: boolean };

export function IntegrationsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ['integration-status'],
    queryFn: () => api.get<StatusResponse>('/integrations/status'),
    refetchInterval: (query) => query.state.data?.recentRuns.some((run) => ['queued', 'running'].includes(run.status)) ? 3000 : false,
  });
  const test = useMutation({
    mutationFn: (source: string) => api.post<{ ok: boolean; provider: string }>(`/integrations/${source}/test`),
  });
  const sync = useMutation({
    mutationFn: (source: string) => api.post<SyncRun>(`/integrations/${source}/sync`),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['integration-status'] }); },
  });
  const canManage = user?.role === 'admin' || user?.role === 'security_admin';
  return <>
    <PageHeader title="Integrations" description="Validate provider access and synchronize scanner and CMDB records into SAM." actions={<button className="secondary" onClick={() => void status.refetch()} disabled={status.isFetching}>{status.isFetching ? 'Refreshing…' : 'Refresh status'}</button>} />
    {status.isPending ? <Loading /> : status.error ? <LoadError message={status.error.message} retry={() => void status.refetch()} /> : <>
      <div className="notice">{status.data.note}</div>
      <Panel title="ServiceNow ticketing">
        <div className="metric-grid"><div className="metric"><span>Incident write access</span><strong>{status.data.ticketWriteConfigured ? 'enabled' : 'not configured'}</strong></div></div>
        <p className="muted">Ticket creation uses a separate, explicitly enabled ServiceNow writer account. SAM stores the external reference and idempotency state; it never claims success until ServiceNow confirms the incident.</p>
      </Panel>
      <Panel title="AI security analyst">
        <div className="metric-grid"><div className="metric"><span>Provider status</span><strong>{status.data.aiAnalystConfigured ? 'enabled' : 'not configured'}</strong></div></div>
        <p className="muted">AI answers require an API key, model, explicit enablement, and approval to send bounded SAM asset and vulnerability data to the configured provider. The provider key stays on the API server.</p>
      </Panel>
      <div className="stack">
        {status.data.connectors.map((connector) => <Panel key={connector.id} title={connector.name}>
          <div className="metric-grid">
            <div className="metric"><span>Configuration</span><strong>{connector.status}</strong></div>
            <div className="metric"><span>Available operations</span><strong>{connector.capabilities.filter((item) => item !== 'connection_test').join(', ')}</strong></div>
            {connector.tables && <div className="metric"><span>CMDB tables</span><strong>{connector.tables.join(', ')}</strong></div>}
          </div>
          {canManage && <div className="actions">
            <button className="secondary" disabled={!connector.configured || test.isPending} onClick={() => test.mutate(connector.id)}>{test.isPending && test.variables === connector.id ? 'Checking…' : 'Test connection'}</button>
            <button className="primary" disabled={!connector.configured || sync.isPending} onClick={() => sync.mutate(connector.id)}>{sync.isPending && sync.variables === connector.id ? 'Queueing…' : 'Start sync'}</button>
          </div>}
        </Panel>)}
      </div>
      {test.data && <div className="notice success" role="status">Connection confirmed by {test.data.provider}.</div>}
      {test.error && <div className="notice error" role="alert">{test.error.message}</div>}
      {sync.data && <div className="notice success" role="status">Sync request queued: {sync.data.id}.</div>}
      {sync.error && <div className="notice error" role="alert">{sync.error.message}</div>}
      <Panel title="Recent synchronization runs">
        <ApiTable rows={status.data.recentRuns} columns={[
          { key: 'source', label: 'Source' }, { key: 'status', label: 'Status' },
          { key: 'started_at', label: 'Started' }, { key: 'finished_at', label: 'Finished' },
          { key: 'records_read', label: 'Records read' }, { key: 'records_written', label: 'Records written' },
          { key: 'error', label: 'Error' },
        ]} />
      </Panel>
    </>}
  </>;
}
