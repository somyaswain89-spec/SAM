import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../auth/AuthContext';
import { api } from '../api/client';
import { ApiTable, Empty, LoadError, Loading, Metric, PageHeader, Panel } from '../components/Panel';
import './ExposurePage.css';

type DiscoveryStatus = { provider: string; configured: boolean; method: string; behavior: string };
type Target = {
  id: string; domain: string; active: boolean; authorization_note: string;
  authorized_by: number | null; created_at: string; last_run_at: string | null;
};
type Run = {
  id: string; target_id: string; domain: string; status: string; started_at: string;
  finished_at: string | null; pages_read: number; records_read: number;
  candidates_created: number; candidates_updated: number; error: string | null; task_id?: string;
};
type Candidate = {
  id: string; target_id: string; domain: string; hostname: string; status: string;
  first_seen_at: string; last_seen_at: string; evidence: Record<string, unknown>;
  asset_id: string | null; review_note: string | null;
};
type Page<T> = { items: T[]; total: number };

export function ExposurePage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const canManage = user?.role === 'admin' || user?.role === 'security_admin';
  const [domain, setDomain] = useState('');
  const [authorizationNote, setAuthorizationNote] = useState('');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [reviewNotes, setReviewNotes] = useState<Record<string, string>>({});
  const [reactivating, setReactivating] = useState<string | null>(null);
  const [reactivationConfirmed, setReactivationConfirmed] = useState(false);
  const [reactivationNotes, setReactivationNotes] = useState<Record<string, string>>({});
  const status = useQuery({ queryKey: ['external-discovery-status'], queryFn: () => api.get<DiscoveryStatus>('/exposure/discovery/status') });
  const targets = useQuery({ queryKey: ['external-discovery-targets'], queryFn: () => api.get<Page<Target>>('/exposure/discovery/targets?limit=100') });
  const runs = useQuery({
    queryKey: ['external-discovery-runs'], queryFn: () => api.get<Page<Run>>('/exposure/discovery/runs?limit=100'),
    refetchInterval: (query) => query.state.data?.items.some((run) => ['queued', 'running'].includes(run.status)) ? 3000 : false,
  });
  const candidates = useQuery({ queryKey: ['external-discovery-candidates'], queryFn: () => api.get<Page<Candidate>>('/exposure/discovery/candidates?status=pending_review&limit=100') });
  const summary = useQuery({ queryKey: ['exposure-summary'], queryFn: () => api.get<{ classificationCounts: Array<{ classification: string; kind: string; n: number }>; wafCounts: Array<{ waf: string | null; n: number }>; verificationNote: string }>('/exposure/summary') });
  const knownExternal = useQuery({ queryKey: ['known-external-assets'], queryFn: () => api.get<{ items: Array<{ id: string; name: string; kind: string; owner: string; criticality: string; open_findings: number }>; source: string }>('/exposure/external-assets') });

  const invalidateDiscovery = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['external-discovery-targets'] }),
      queryClient.invalidateQueries({ queryKey: ['external-discovery-runs'] }),
      queryClient.invalidateQueries({ queryKey: ['external-discovery-candidates'] }),
      queryClient.invalidateQueries({ queryKey: ['known-external-assets'] }),
      queryClient.invalidateQueries({ queryKey: ['assets'] }),
      queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
    ]);
  };
  const addTarget = useMutation({
    mutationFn: () => api.post<Target>('/exposure/discovery/targets', {
      domain, authorization_note: authorizationNote, authorization_confirmed: authorizationConfirmed,
    }),
    onSuccess: async () => { setDomain(''); setAuthorizationNote(''); setAuthorizationConfirmed(false); await invalidateDiscovery(); },
  });
  const startRun = useMutation({
    mutationFn: (targetId: string) => api.post<Run>(`/exposure/discovery/targets/${encodeURIComponent(targetId)}/runs`),
    onSuccess: invalidateDiscovery,
  });
  const updateTarget = useMutation({
    mutationFn: ({ target, active }: { target: Target; active: boolean }) => api.patch<Target>(`/exposure/discovery/targets/${encodeURIComponent(target.id)}`, {
      active,
      ...(active ? { authorization_confirmed: true, authorization_note: reactivationNotes[target.id] ?? '' } : {}),
    }),
    onSuccess: async (_data, variables) => {
      setReactivating(null);
      setReactivationConfirmed(false);
      setReactivationNotes((value) => ({ ...value, [variables.target.id]: '' }));
      await invalidateDiscovery();
    },
  });
  const review = useMutation({
    mutationFn: ({ candidate, decision }: { candidate: Candidate; decision: 'accept' | 'dismiss' }) => api.post<Candidate>(
      `/exposure/discovery/candidates/${encodeURIComponent(candidate.id)}/review`,
      { decision, note: reviewNotes[candidate.id] ?? '' },
    ),
    onSuccess: async (_data, variables) => {
      setReviewNotes((value) => ({ ...value, [variables.candidate.id]: '' }));
      await invalidateDiscovery();
    },
  });

  const openRuns = useMemo(() => runs.data?.items.filter((run) => ['queued', 'running'].includes(run.status)).length ?? 0, [runs.data]);
  const classifications = summary.data?.classificationCounts ?? [];
  const countFor = (kind: string, classification: string) => classifications.find((row) => row.kind === kind && row.classification === classification)?.n ?? 0;

  return <>
    <PageHeader title="Attack surface" description="Review SAM inventory and discover public hostnames from certificate transparency for domains your organization is authorized to monitor." actions={<button className="secondary" onClick={() => void Promise.all([status.refetch(), targets.refetch(), runs.refetch(), candidates.refetch(), summary.refetch(), knownExternal.refetch()])}>Refresh</button>} />

    {status.isPending ? <Loading /> : status.error ? <LoadError message={status.error.message} retry={() => void status.refetch()} /> : <div className={`notice ${status.data.configured ? '' : 'warning'}`}>
      <strong>{status.data.provider}: {status.data.configured ? 'configured' : 'not configured'}</strong>
      <span>{status.data.behavior} {status.data.configured ? '' : 'Set CERTSPOTTER_API_TOKEN on the API and worker to enable discovery.'}</span>
    </div>}

    <div className="metric-grid">
      <Metric label="Internal websites" value={countFor('Website', 'Internal facing')} />
      <Metric label="External websites" value={countFor('Website', 'External facing')} />
      <Metric label="Internal servers" value={countFor('Server', 'Internal facing')} />
      <Metric label="External servers" value={countFor('Server', 'External facing')} />
      <Metric label="Pending hostname review" value={candidates.data?.total ?? '—'} footnote="Certificate transparency candidates" />
      <Metric label="Discovery runs active" value={openRuns} />
    </div>

    {summary.isError && <LoadError message={summary.error.message} retry={() => void summary.refetch()} />}
    {summary.data && <Panel title="WAF posture recorded in SAM"><div className="exposure-waf-grid">{summary.data.wafCounts.map((row) => <Metric key={row.waf ?? 'unknown'} label={`Website WAF: ${row.waf ?? 'Unverified'}`} value={row.n} />)}</div><p className="muted">{summary.data.verificationNote}</p></Panel>}

    <Panel title="Authorized discovery domains">
      <p className="muted">Discovery is passive: SAM queries SSLMate Cert Spotter certificate-transparency records. SAM does not probe, crawl, or scan the returned hostnames. Register only domains your organization owns or has written authorization to monitor.</p>
      {canManage && <form className="form-grid exposure-target-form" onSubmit={(event) => { event.preventDefault(); addTarget.mutate(); }}>
        <label>Registered root domain<input value={domain} onChange={(event) => setDomain(event.target.value)} maxLength={253} minLength={3} placeholder="example.com" required /></label>
        <label className="wide">Authorization basis<textarea value={authorizationNote} onChange={(event) => setAuthorizationNote(event.target.value)} minLength={20} maxLength={1000} required placeholder="Describe the ownership or written authorization for monitoring this domain." /></label>
        <label className="checkbox-label wide"><input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} required />I confirm SAM may perform passive certificate-transparency discovery for this domain.</label>
        <div className="form-actions wide"><button className="primary" disabled={addTarget.isPending || !authorizationConfirmed}>{addTarget.isPending ? 'Registering…' : 'Register authorized domain'}</button></div>
        {addTarget.error && <div className="notice error wide" role="alert">{addTarget.error.message}</div>}
      </form>}
      {!canManage && <div className="notice">Only security administrators can register or run discovery for domains.</div>}
      {targets.isPending ? <Loading /> : targets.error ? <LoadError message={targets.error.message} retry={() => void targets.refetch()} /> : targets.data.items.length === 0 ? <Empty>No authorized domains have been registered.</Empty> : <div className="table-scroll"><table><thead><tr><th>Domain</th><th>Status</th><th>Authorization basis</th><th>Last discovery</th><th>Action</th></tr></thead><tbody>{targets.data.items.map((target) => <tr key={target.id}><td><strong>{target.domain}</strong><small className="exposure-block">{target.id}</small></td><td>{target.active ? 'Active' : 'Paused'}</td><td>{target.authorization_note}</td><td>{target.last_run_at ?? 'Never'}</td><td><div className="actions-row exposure-actions">{target.active && canManage && <button className="primary" disabled={!status.data?.configured || startRun.isPending || openRuns > 0} onClick={() => startRun.mutate(target.id)}>Discover</button>}{target.active && canManage && <button className="secondary" onClick={() => updateTarget.mutate({ target, active: false })} disabled={updateTarget.isPending}>Pause</button>}{!target.active && canManage && reactivating === target.id && <button className="secondary" onClick={() => updateTarget.mutate({ target, active: true })} disabled={updateTarget.isPending || !reactivationConfirmed || (reactivationNotes[target.id] ?? '').trim().length < 20}>Reactivate</button>}</div>{!target.active && reactivating === target.id && <div className="reactivation-box"><textarea aria-label={`Authorization basis for ${target.domain}`} value={reactivationNotes[target.id] ?? ''} onChange={(event) => setReactivationNotes((value) => ({ ...value, [target.id]: event.target.value }))} minLength={20} maxLength={1000} placeholder="Renew the authorization basis (at least 20 characters)." /><label className="checkbox-label"><input type="checkbox" checked={reactivationConfirmed} onChange={(event) => setReactivationConfirmed(event.target.checked)} />I reconfirm current authorization</label></div>}{!target.active && canManage && reactivating !== target.id && <button className="link-button" onClick={() => { setReactivating(target.id); setReactivationConfirmed(false); }}>Review reactivation</button>}</td></tr>)}</tbody></table></div>}
      {startRun.error && <div className="notice error" role="alert">{startRun.error.message}</div>}
      {updateTarget.error && <div className="notice error" role="alert">{updateTarget.error.message}</div>}
    </Panel>

    <Panel title="Discovered hostname candidates">
      <p className="muted">A CT record proves that a certificate was publicly logged, not that a hostname is currently live, owned by your organization, behind a WAF, or vulnerable. Verify the asset owner before adding it to inventory.</p>
      {candidates.isPending ? <Loading /> : candidates.error ? <LoadError message={candidates.error.message} retry={() => void candidates.refetch()} /> : candidates.data.items.length === 0 ? <Empty>No hostnames are awaiting review.</Empty> : <div className="exposure-candidates">{candidates.data.items.map((candidate) => <article className="answer-card" key={candidate.id}>
        <div className="request-head"><div><strong>{candidate.hostname}</strong><span>Domain {candidate.domain} · first observed {new Date(candidate.first_seen_at).toLocaleString()} · last observed {new Date(candidate.last_seen_at).toLocaleString()}</span></div><span className="pill">Pending review</span></div>
        <div className="exposure-evidence"><span>Issuer: {String(candidate.evidence.issuer ?? 'unknown')}</span><span>Certificate expires: {String(candidate.evidence.not_after ?? 'unknown')}</span><span>Revoked: {String(candidate.evidence.revoked ?? 'unknown')}</span><span>Certificate fingerprint: {String(candidate.evidence.certificate_sha256 ?? 'not provided')}</span></div>
        {canManage && <><label className="exposure-review-note">Review note<input value={reviewNotes[candidate.id] ?? ''} onChange={(event) => setReviewNotes((value) => ({ ...value, [candidate.id]: event.target.value }))} minLength={3} maxLength={1000} placeholder="Owner validation or reason to dismiss" /></label><div className="actions-row"><button className="primary" disabled={review.isPending || (reviewNotes[candidate.id] ?? '').trim().length < 3} onClick={() => review.mutate({ candidate, decision: 'accept' })}>Add verified hostname to inventory</button><button className="secondary" disabled={review.isPending || (reviewNotes[candidate.id] ?? '').trim().length < 3} onClick={() => review.mutate({ candidate, decision: 'dismiss' })}>Dismiss candidate</button></div></>}
      </article>)}</div>}
      {review.error && <div className="notice error" role="alert">{review.error.message}</div>}
    </Panel>

    <Panel title="Latest discovery runs">
      {runs.isPending ? <Loading /> : runs.error ? <LoadError message={runs.error.message} retry={() => void runs.refetch()} /> : <ApiTable rows={runs.data.items} columns={[
        { key: 'domain', label: 'Domain' }, { key: 'status', label: 'Status' }, { key: 'started_at', label: 'Started' },
        { key: 'pages_read', label: 'Pages' }, { key: 'records_read', label: 'Issuances' },
        { key: 'candidates_created', label: 'New candidates' }, { key: 'candidates_updated', label: 'Updated candidates' }, { key: 'error', label: 'Error' },
      ]} />}
    </Panel>

    <Panel title="External assets already in inventory">
      <p className="muted">This list is from the existing SAM asset inventory; it is not a discovery result.</p>
      {knownExternal.isPending ? <Loading /> : knownExternal.error ? <LoadError message={knownExternal.error.message} retry={() => void knownExternal.refetch()} /> : <ApiTable rows={knownExternal.data.items} columns={[
        { key: 'id', label: 'Asset ID' }, { key: 'name', label: 'Name' }, { key: 'kind', label: 'Type' },
        { key: 'owner', label: 'Owner' }, { key: 'criticality', label: 'Criticality' }, { key: 'open_findings', label: 'Open findings' },
      ]} />}
    </Panel>
  </>;
}
