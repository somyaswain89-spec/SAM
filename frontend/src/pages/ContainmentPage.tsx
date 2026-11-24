import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../auth/AuthContext';
import { api, type Asset, type Page } from '../api/client';
import { LoadError, Loading, PageHeader, Panel } from '../components/Panel';

type Action = { id: string; asset_id: string; action: string; status: string; impact: string; requested_by: number; created_at: string };
type ImpactPreview = { assetId: string; action: string; expectedEffect: string; impact: string; dependentAssets: string[]; impactBasis: string };

export function ContainmentPage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const [assetId, setAssetId] = useState('');
  const [action, setAction] = useState('Quarantine');
  const [acknowledged, setAcknowledged] = useState(false);
  const [decisionNote, setDecisionNote] = useState<Record<string, string>>({});
  const assets = useQuery({ queryKey: ['containment-assets'], queryFn: () => api.get<Page<Asset>>('/compliance/assets') });
  const impact = useQuery({ queryKey: ['containment-impact', assetId, action], queryFn: () => api.get<ImpactPreview>(`/containment/impact/${encodeURIComponent(assetId)}?action=${encodeURIComponent(action)}`), enabled: Boolean(assetId) });
  const requests = useQuery({ queryKey: ['containment'], queryFn: () => api.get<{ items: Action[] }>('/containment/requests') });
  const request = useMutation({ mutationFn: () => api.post<Action>('/containment/requests', { asset_id: assetId, action, acknowledge_impact: acknowledged }), onSuccess: async () => { setAcknowledged(false); await client.invalidateQueries({ queryKey: ['containment'] }); } });
  const review = useMutation({ mutationFn: ({ id, decision }: { id: string; decision: 'Approve' | 'Reject' }) => api.post(`/containment/requests/${encodeURIComponent(id)}/decision`, { decision, note: decisionNote[id] || 'Reviewed by authorized approver' }), onSuccess: () => client.invalidateQueries({ queryKey: ['containment'] }) });
  const canReview = user?.role === 'admin' || user?.role === 'security_admin';
  return <>
    <PageHeader title="Containment approvals" description="Review the recorded service impact before requesting quarantine or release." />
    <div className="notice warning"><strong>External action depends on connector configuration.</strong><span>Approval is stored in SAM. The application will not claim a server, endpoint, network, DNS, or WAF change until an approved adapter is configured and confirms it.</span></div>
    <Panel title="Request containment review">
      {assets.isPending ? <Loading /> : assets.error ? <LoadError message={assets.error.message} retry={() => void assets.refetch()} /> : <form className="form-grid" onSubmit={(event) => { event.preventDefault(); request.mutate(); }}>
        <label>Asset<select required value={assetId} onChange={(event) => { setAssetId(event.target.value); setAcknowledged(false); }}><option value="">Select asset</option>{assets.data.items.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.kind} · {item.compliance ?? 'unknown'}% recorded</option>)}</select></label>
        <label>Action<select value={action} onChange={(event) => { setAction(event.target.value); setAcknowledged(false); }}><option>Quarantine</option><option>Release</option></select></label>
        {assetId && <div className="notice impact-preview" aria-live="polite">
          <strong>Business impact preview · {action}</strong>
          {impact.isPending ? <span>Loading current asset and dependency records…</span> : impact.error ? <LoadError message={impact.error.message} retry={() => void impact.refetch()} /> : impact.data && <>
            <b>{impact.data.expectedEffect}</b>
            <span>{impact.data.impact}</span>
            <small>Basis: {impact.data.impactBasis}. This reflects SAM records only; unrecorded service dependencies and customer or financial impact are not included.</small>
          </>}
        </div>}
        <label className="wide"><span className="checkbox-label"><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />I reviewed the impact preview, asset owner, and recovery requirements.</span></label>
        <div className="form-actions"><button className="primary" disabled={!assetId || !impact.data || !acknowledged || request.isPending}>{request.isPending ? 'Submitting…' : 'Submit for independent approval'}</button></div>
        {request.error && <div className="notice error">{request.error.message}</div>}
      </form>}
    </Panel>
    <Panel title="Persisted containment requests">
      {requests.isPending ? <Loading /> : requests.error ? <LoadError message={requests.error.message} retry={() => void requests.refetch()} /> : requests.data.items.length === 0 ? <div className="empty">No containment requests have been recorded.</div> : <div className="stack">{requests.data.items.map((item) => <article className="request-card" key={item.id}><div className="request-head"><div><b>{item.action} · {item.asset_id}</b><span>{item.status} · {new Date(item.created_at).toLocaleString()}</span></div><span className="pill">{item.id}</span></div><p>{item.impact}</p>{item.status === 'Approval required' && canReview && <div className="review-controls"><input value={decisionNote[item.id] || ''} onChange={(event) => setDecisionNote((state) => ({ ...state, [item.id]: event.target.value }))} placeholder="Review note" /><button className="primary" disabled={review.isPending} onClick={() => review.mutate({ id: item.id, decision: 'Approve' })}>Approve record</button><button className="secondary" disabled={review.isPending} onClick={() => review.mutate({ id: item.id, decision: 'Reject' })}>Reject</button></div>}</article>)}</div>}
      {review.error && <div className="notice error">{review.error.message}</div>}
    </Panel>
  </>;
}
