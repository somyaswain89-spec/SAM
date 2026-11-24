import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../auth/AuthContext';
import { api, type Finding, type Page } from '../api/client';
import { ApiTable, LoadError, Loading, PageHeader, Panel } from '../components/Panel';

export function FindingsPage() {
  const [state, setState] = useState('Open');
  const [businessImpact, setBusinessImpact] = useState('');
  const ticketKeys = useRef(new Map<string, string>());
  const client = useQueryClient();
  const { user } = useAuth();
  const query = useQuery({ queryKey: ['findings', state], queryFn: () => api.get<Page<Finding>>(`/findings?limit=200&state=${encodeURIComponent(state)}`) });
  const integrationStatus = useQuery({ queryKey: ['integration-status'], queryFn: () => api.get<{ ticketWriteConfigured: boolean }>('/integrations/status') });
  const resolve = useMutation({ mutationFn: ({ id, next }: { id: string; next: string }) => api.patch<Finding>(`/findings/${encodeURIComponent(id)}/state`, { state: next }), onSuccess: () => client.invalidateQueries({ queryKey: ['findings'] }) });
  const ticket = useMutation({
    mutationFn: ({ findingId, impact }: { findingId: string; impact: string }) => {
      const key = ticketKeys.current.get(findingId) ?? crypto.randomUUID();
      ticketKeys.current.set(findingId, key);
      return api.post<{ external_number: string | null; status: string }>('/integrations/servicenow/tickets', { finding_id: findingId, business_impact: impact }, { 'Idempotency-Key': key });
    },
    onSuccess: (_result, variables) => { ticketKeys.current.delete(variables.findingId); },
  });
  const canCreateTickets = ['admin', 'security_admin', 'analyst'].includes(user?.role ?? '');
  return <>
    <PageHeader title="Vulnerability queue" description="Persisted findings ordered by severity and updated time. State changes are recorded server-side." actions={<select aria-label="Finding state" value={state} onChange={(event) => setState(event.target.value)}><option>Open</option><option>In Progress</option><option>Resolved</option><option>Accepted Risk</option></select>} />
    <Panel>
      {query.isPending ? <Loading /> : query.error ? <LoadError message={query.error.message} retry={() => void query.refetch()} /> : <>
        <ApiTable rows={query.data.items} columns={[{ key: 'id', label: 'Finding' }, { key: 'title', label: 'Vulnerability' }, { key: 'cve', label: 'CVE' }, { key: 'severity', label: 'Severity' }, { key: 'asset_id', label: 'Asset' }, { key: 'asset_name', label: 'Asset name' }, { key: 'state', label: 'State' }, { key: 'due_at', label: 'Due date' }]} />
        {query.data.items.some((item) => item.state !== 'Resolved') && <div className="actions-row">{query.data.items.filter((item) => item.state !== 'Resolved').slice(0, 12).map((item) => <button key={item.id} className="secondary" disabled={resolve.isPending} onClick={() => resolve.mutate({ id: item.id, next: item.state === 'In Progress' ? 'Resolved' : 'In Progress' })}>{item.id}: {item.state === 'In Progress' ? 'Resolve' : 'Start work'}</button>)}</div>}
        {resolve.error && <div className="notice error">{resolve.error.message}</div>}
      </>}
    </Panel>
    <Panel title="ServiceNow remediation tickets">
      {integrationStatus.isPending ? <Loading /> : integrationStatus.error ? <LoadError message={integrationStatus.error.message} retry={() => void integrationStatus.refetch()} /> : !integrationStatus.data.ticketWriteConfigured ? <div className="empty">ServiceNow incident write access is not configured. Configure the dedicated writer credentials and explicitly enable ticket creation in the deployment environment.</div> : <>
        <label>Business impact<textarea value={businessImpact} onChange={(event) => setBusinessImpact(event.target.value)} maxLength={2000} minLength={10} placeholder="Describe the affected service or customer impact. This text will be sent to the ServiceNow incident." /></label>
        <div className="actions-row">{(query.data?.items ?? []).filter((item) => item.state !== 'Resolved').slice(0, 12).map((item) => <button key={item.id} className="secondary" disabled={!canCreateTickets || businessImpact.trim().length < 10 || ticket.isPending} onClick={() => ticket.mutate({ findingId: item.id, impact: businessImpact.trim() })}>{ticket.isPending && ticket.variables?.findingId === item.id ? 'Creating…' : `Create incident for ${item.id}`}</button>)}</div>
        {ticket.data && <div className="notice success" role="status">ServiceNow incident confirmed: {ticket.data.external_number ?? ticket.data.status}.</div>}
        {ticket.error && <div className="notice error" role="alert">{ticket.error.message}. If ServiceNow may have accepted the request, retry with the same key to reconcile safely.</div>}
        {!canCreateTickets && <div className="muted">Your account does not have permission to create incidents.</div>}
      </>}
    </Panel>
  </>;
}
