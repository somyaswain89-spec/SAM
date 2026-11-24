import { useState } from 'react';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm, useWatch } from 'react-hook-form';
import { useAuth } from '../auth/AuthContext';
import { api, type Asset, type Finding, type Page } from '../api/client';
import { LoadError, Loading, PageHeader, Panel } from '../components/Panel';

type ExceptionRecord = {
  id: string;
  asset_id: string;
  asset_name?: string | null;
  finding_id?: string | null;
  requested_by: number;
  reason: string;
  expires_at: string;
  status: string;
  reviewed_by?: number | null;
  review_note?: string | null;
  created_at: string;
  updated_at: string;
};

const exceptionSchema = z.object({
  asset_id: z.string().min(1, 'Choose an asset'),
  finding_id: z.string().optional(),
  reason: z.string().trim().min(10).max(3000),
  expires_at: z.string().min(1, 'Choose an expiry date').refine((value) => {
    const timestamp = new Date(value).getTime();
    return Number.isFinite(timestamp) && timestamp > Date.now();
  }, 'Expiry must be in the future'),
});

type ExceptionInput = z.infer<typeof exceptionSchema>;
type ExceptionState = '' | 'Pending' | 'Approved' | 'Rejected';

function defaultExpiry() {
  const date = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  return date.toISOString().slice(0, 16);
}

export function GovernancePage() {
  const { user } = useAuth();
  const client = useQueryClient();
  const [state, setState] = useState<ExceptionState>('');
  const [offset, setOffset] = useState(0);
  const [reviewNotes, setReviewNotes] = useState<Record<string, string>>({});
  const canRequest = ['admin', 'security_admin', 'analyst'].includes(user?.role ?? '');
  const canReview = ['admin', 'security_admin'].includes(user?.role ?? '');
  const assets = useQuery({
    queryKey: ['governance-assets'],
    queryFn: () => api.get<Page<Asset>>('/assets?limit=500'),
    enabled: canRequest,
  });
  const { control, register, handleSubmit, reset, setValue, formState: { errors } } = useForm<ExceptionInput>({
    resolver: zodResolver(exceptionSchema),
    defaultValues: { asset_id: '', finding_id: '', reason: '', expires_at: defaultExpiry() },
  });
  const assetId = useWatch({ control, name: 'asset_id' });
  const findings = useQuery({
    queryKey: ['governance-findings', assetId],
    queryFn: () => api.get<Page<Finding>>(`/findings?limit=500&asset_id=${encodeURIComponent(assetId)}`),
    enabled: Boolean(assetId),
  });
  const exceptions = useQuery({
    queryKey: ['exceptions', state, offset],
    queryFn: () => api.get<Page<ExceptionRecord>>(`/exceptions?limit=50&offset=${offset}${state ? `&state=${encodeURIComponent(state)}` : ''}`),
  });
  const create = useMutation({
    mutationFn: (values: ExceptionInput) => api.post<ExceptionRecord>('/exceptions', {
      ...values,
      finding_id: values.finding_id || null,
      expires_at: new Date(values.expires_at).toISOString(),
    }),
    onSuccess: async () => {
      reset({ asset_id: '', finding_id: '', reason: '', expires_at: defaultExpiry() });
      setOffset(0);
      await client.invalidateQueries({ queryKey: ['exceptions'] });
    },
  });
  const review = useMutation({
    mutationFn: ({ id, decision, note }: { id: string; decision: 'Approve' | 'Reject'; note: string }) =>
      api.post<ExceptionRecord>(`/exceptions/${encodeURIComponent(id)}/review`, { decision, note }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['exceptions'] });
    },
  });

  return <>
    <PageHeader title="Governance" description="Request time-bounded vulnerability exceptions and record independent approval decisions." actions={<select aria-label="Exception status" value={state} onChange={(event) => { setState(event.target.value as ExceptionState); setOffset(0); }}><option value="">All statuses</option><option>Pending</option><option>Approved</option><option>Rejected</option></select>} />
    {canRequest && <Panel title="Request a risk exception">
      {assets.isPending ? <Loading /> : assets.error ? <LoadError message={assets.error.message} retry={() => void assets.refetch()} /> : assets.data.items.length === 0 ? <div className="empty">Add an asset before requesting an exception.</div> : <form className="form-grid" onSubmit={handleSubmit((values) => create.mutate(values))}>
        <label>Asset<select {...register('asset_id', { onChange: () => setValue('finding_id', '') })}><option value="">Select asset</option>{assets.data.items.map((asset) => <option key={asset.id} value={asset.id}>{asset.name} · {asset.kind} · {asset.id}</option>)}</select>{errors.asset_id && <small className="field-error">{errors.asset_id.message}</small>}</label>
        <label>Finding (optional)<select {...register('finding_id')} disabled={!assetId || findings.isPending}><option value="">No specific finding</option>{findings.data?.items.map((finding) => <option key={finding.id} value={finding.id}>{finding.id} · {finding.severity} · {finding.title}</option>)}</select>{findings.error && <small className="field-error">{findings.error.message}</small>}</label>
        <label className="wide">Business justification<textarea {...register('reason')} maxLength={3000} />{errors.reason && <small className="field-error">{errors.reason.message}</small>}</label>
        <label>Exception expires<input type="datetime-local" {...register('expires_at')} aria-invalid={!!errors.expires_at} />{errors.expires_at && <small className="field-error">{errors.expires_at.message}</small>}</label>
        <div className="form-actions"><button className="primary" disabled={create.isPending}>{create.isPending ? 'Submitting…' : 'Submit for approval'}</button></div>
        {create.error && <div className="notice error" role="alert">{create.error.message}</div>}
      </form>}
    </Panel>}

    <Panel title="Exception requests">
      {exceptions.isPending ? <Loading /> : exceptions.error ? <LoadError message={exceptions.error.message} retry={() => void exceptions.refetch()} /> : exceptions.data.items.length === 0 ? <div className="empty">No exception requests match this view.</div> : <div className="stack">
        {exceptions.data.items.map((item) => <article className="request-card" key={item.id}>
          <div className="request-head"><div><b>{item.asset_name || item.asset_id}{item.finding_id ? ` · ${item.finding_id}` : ''}</b><span>{item.id} · {item.status} · expires {new Date(item.expires_at).toLocaleString()}</span></div><span className="pill">{item.status}</span></div>
          <p>{item.reason}</p>
          {item.review_note && <small>Review note: {item.review_note}</small>}
          {item.status === 'Pending' && canReview && item.requested_by === user?.id && <small className="muted">The requester cannot review their own exception; an independent approver is required.</small>}
          {item.status === 'Pending' && canReview && item.requested_by !== user?.id && <div className="review-controls">
            <input aria-label={`Review note for ${item.id}`} value={reviewNotes[item.id] || ''} maxLength={1000} minLength={3} placeholder="Decision note (at least 3 characters)" onChange={(event) => setReviewNotes((notes) => ({ ...notes, [item.id]: event.target.value }))} />
            <button className="primary" disabled={(review.isPending && review.variables?.id === item.id) || (reviewNotes[item.id] || '').trim().length < 3} onClick={() => review.mutate({ id: item.id, decision: 'Approve', note: reviewNotes[item.id].trim() })}>Approve</button>
            <button className="secondary" disabled={(review.isPending && review.variables?.id === item.id) || (reviewNotes[item.id] || '').trim().length < 3} onClick={() => review.mutate({ id: item.id, decision: 'Reject', note: reviewNotes[item.id].trim() })}>Reject</button>
          </div>}
        </article>)}
        <div className="pagination"><button className="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous</button><span>{offset + 1}–{Math.min(offset + 50, exceptions.data.total)} of {exceptions.data.total}</span><button className="secondary" disabled={offset + 50 >= exceptions.data.total} onClick={() => setOffset(offset + 50)}>Next</button></div>
      </div>}
      {review.error && <div className="notice error" role="alert">{review.error.message}</div>}
    </Panel>
  </>;
}
