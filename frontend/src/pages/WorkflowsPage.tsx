import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { api, type Asset, type Page } from '../api/client';
import { ApiTable, LoadError, Loading, PageHeader, Panel } from '../components/Panel';

const workflowSchema = z.object({ kind: z.enum(['Rescan', 'FalsePositive', 'Remediation', 'SLAReview']), asset_id: z.string().optional(), finding_id: z.string().optional(), reason: z.string().min(3).max(1000) });
type WorkflowInput = z.infer<typeof workflowSchema>;

export function WorkflowsPage() {
  const client = useQueryClient();
  const assets = useQuery({ queryKey: ['workflow-assets'], queryFn: () => api.get<Page<Asset>>('/assets?limit=500') });
  const workflows = useQuery({ queryKey: ['workflows'], queryFn: () => api.get<Page<Record<string, unknown>>>('/workflows') });
  const { register, handleSubmit, reset, formState: { errors } } = useForm<WorkflowInput>({ resolver: zodResolver(workflowSchema), defaultValues: { kind: 'Rescan' } });
  const create = useMutation({ mutationFn: (values: WorkflowInput) => api.post('/workflows', { kind: values.kind, asset_id: values.asset_id || null, finding_id: values.finding_id || null, payload: { reason: values.reason } }), onSuccess: async () => { reset(); await client.invalidateQueries({ queryKey: ['workflows'] }); } });
  return <>
    <PageHeader title="Operational workflows" description="Create durable review requests for rescans, false-positive validation, remediation, and SLA review." />
    <Panel title="Create a workflow request"><form className="form-grid" onSubmit={handleSubmit((values) => create.mutate(values))}>
      <label>Workflow type<select {...register('kind')}><option>Rescan</option><option>FalsePositive</option><option>Remediation</option><option>SLAReview</option></select></label>
      <label>Asset<select {...register('asset_id')}><option value="">No specific asset</option>{assets.data?.items.map((asset) => <option value={asset.id} key={asset.id}>{asset.name} · {asset.id}</option>)}</select></label>
      <label>Finding ID (optional)<input {...register('finding_id')} placeholder="FND-1234" /></label>
      <label className="wide">Reason and context<textarea {...register('reason')} /></label>
      {errors.reason && <small className="field-error">{errors.reason.message}</small>}
      <div className="form-actions"><button className="primary" disabled={create.isPending}>{create.isPending ? 'Submitting…' : 'Submit request'}</button></div>
      {create.error && <div className="notice error">{create.error.message}</div>}
    </form></Panel>
    <Panel title="Workflow requests">{workflows.isPending ? <Loading /> : workflows.error ? <LoadError message={workflows.error.message} retry={() => void workflows.refetch()} /> : <ApiTable rows={workflows.data.items} columns={[{ key: 'id', label: 'Request' }, { key: 'kind', label: 'Type' }, { key: 'asset_id', label: 'Asset' }, { key: 'finding_id', label: 'Finding' }, { key: 'status', label: 'Status' }, { key: 'payload', label: 'Details' }, { key: 'created_at', label: 'Created' }]} />}</Panel>
  </>;
}
