import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { api, type Asset, type Page } from '../api/client';
import { ApiTable, LoadError, Loading, PageHeader, Panel } from '../components/Panel';

const assetSchema = z.object({ id: z.string().min(2), name: z.string().min(1), kind: z.enum(['Website', 'Server']), classification: z.enum(['Internal facing', 'External facing', 'Unknown']), owner: z.string().max(255), environment: z.string().max(80), criticality: z.enum(['Critical', 'High', 'Medium', 'Low']) });
type AssetInput = z.infer<typeof assetSchema>;

export function AssetsPage() {
  const [entity, setEntity] = useState('');
  const [classification, setClassification] = useState('');
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const [showForm, setShowForm] = useState(false);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [columnMapping, setColumnMapping] = useState('{"id":"id","name":"name","kind":"kind","classification":"classification","owner":"owner","environment":"environment","criticality":"criticality","compliance":"compliance","waf":"waf"}');
  const [importJobId, setImportJobId] = useState('');
  const [exportJobId, setExportJobId] = useState('');
  const [downloadError, setDownloadError] = useState('');
  const queryClient = useQueryClient();
  const params = new URLSearchParams({ limit: '50', offset: String(offset) });
  if (entity) params.set('entity', entity);
  if (classification) params.set('classification', classification);
  if (search) params.set('q', search);
  const query = useQuery({ queryKey: ['assets', entity, classification, search, offset], queryFn: () => api.get<Page<Asset>>(`/assets?${params.toString()}`) });
  const { register, handleSubmit, reset, formState: { errors } } = useForm<AssetInput>({ resolver: zodResolver(assetSchema), defaultValues: { classification: 'Unknown', kind: 'Website', criticality: 'Medium', owner: '', environment: 'Production' } });
  const create = useMutation({ mutationFn: (values: AssetInput) => api.post<Asset>('/assets', values), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['assets'] }); reset(); setShowForm(false); } });
  const upload = useMutation({ mutationFn: async () => {
    if (!uploadFile) throw new Error('Choose a CSV or XLSX file first');
    const form = new FormData(); form.set('file', uploadFile); form.set('column_mapping', columnMapping);
    return api.upload<{ job: { id: string } }>('/imports/assets', form);
  }, onSuccess: async (result) => { setImportJobId(result.job.id); await queryClient.invalidateQueries({ queryKey: ['import-jobs'] }); } });
  const exportAssets = useMutation({ mutationFn: () => api.post<{ job: { id: string } }>('/exports/assets'), onSuccess: (result) => setExportJobId(result.job.id) });
  const importStatus = useQuery({ queryKey: ['import-job', importJobId], queryFn: () => api.get<{ status: string; processedRows: number; rejectedRows: number; totalRows: number; downloadAvailable: boolean; errors: Array<{ row?: number; error: string }> }>(`/imports/jobs/${importJobId}`), enabled: !!importJobId, refetchInterval: (current) => ['queued', 'running'].includes(current.state.data?.status ?? '') ? 1500 : false });
  const exportStatus = useQuery({ queryKey: ['export-job', exportJobId], queryFn: () => api.get<{ status: string; processedRows: number; totalRows: number; downloadAvailable: boolean }>(`/imports/jobs/${exportJobId}`), enabled: !!exportJobId, refetchInterval: (current) => ['queued', 'running'].includes(current.state.data?.status ?? '') ? 1500 : false });
  async function downloadFile(path: string, name: string) { setDownloadError(''); try { await api.download(path, name); } catch (error) { setDownloadError(error instanceof Error ? error.message : 'Download could not be completed'); } }
  return <>
    <PageHeader title="Asset inventory" description="Search and classify websites and servers using records stored by SAM." actions={<button className="primary" onClick={() => { setShowForm((value) => !value); create.reset(); }}>{showForm ? 'Close form' : 'Add asset'}</button>} />
    {showForm && <Panel title="Register an asset"><form className="form-grid" onSubmit={handleSubmit((values) => create.mutate(values))}>
      <label>Asset ID<input {...register('id')} placeholder="WEB-1200" />{errors.id && <small className="field-error">{errors.id.message}</small>}</label>
      <label>Name or hostname<input {...register('name')} placeholder="portal.example.com" />{errors.name && <small className="field-error">{errors.name.message}</small>}</label>
      <label>Type<select {...register('kind')}><option>Website</option><option>Server</option></select></label>
      <label>Classification<select {...register('classification')}><option>Unknown</option><option>Internal facing</option><option>External facing</option></select></label>
      <label>Owner<input {...register('owner')} /></label><label>Environment<input {...register('environment')} /></label>
      <label>Criticality<select {...register('criticality')}><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></label>
      <div className="form-actions"><button className="primary" disabled={create.isPending}>{create.isPending ? 'Saving…' : 'Save asset'}</button></div>
      {create.error && <div className="notice error" role="alert">{create.error.message}</div>}
    </form></Panel>}
    <Panel>
      <div className="filters"><input aria-label="Search inventory" placeholder="Search name, ID, or owner" value={search} onChange={(event) => { setSearch(event.target.value); setOffset(0); }} /><select aria-label="Asset type" value={entity} onChange={(event) => { setEntity(event.target.value); setOffset(0); }}><option value="">All types</option><option value="Website">Websites</option><option value="Server">Servers</option></select><select aria-label="Asset classification" value={classification} onChange={(event) => { setClassification(event.target.value); setOffset(0); }}><option value="">All classifications</option><option>Internal facing</option><option>External facing</option><option>Unknown</option></select><span className="pill">{query.data?.total ?? '—'} records</span></div>
      {query.isPending ? <Loading /> : query.error ? <LoadError message={query.error.message} retry={() => void query.refetch()} /> : <ApiTable rows={query.data.items} columns={[{ key: 'id', label: 'Asset ID' }, { key: 'name', label: 'Name' }, { key: 'kind', label: 'Type' }, { key: 'classification', label: 'Classification' }, { key: 'owner', label: 'Owner' }, { key: 'criticality', label: 'Criticality' }, { key: 'compliance', label: 'Compliance %' }, { key: 'waf', label: 'WAF evidence' }, { key: 'status', label: 'State' }]} />}
      <div className="pagination"><button className="secondary" disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous</button><span>{offset + 1}–{Math.min(offset + 50, query.data?.total ?? 0)} of {query.data?.total ?? 0}</span><button className="secondary" disabled={!query.data || offset + 50 >= query.data.total} onClick={() => setOffset(offset + 50)}>Next</button></div>
    </Panel>
    <Panel title="File imports and exports"><div className="form-grid">
      <label>Import CSV or XLSX<input type="file" accept=".csv,.xlsx" onChange={(event) => setUploadFile(event.target.files?.[0] ?? null)} /></label>
      <label>Column mapping (target field → file header)<textarea value={columnMapping} onChange={(event) => setColumnMapping(event.target.value)} spellCheck={false} /></label>
      <div className="form-actions"><button className="primary" disabled={!uploadFile || upload.isPending} onClick={() => upload.mutate()}>{upload.isPending ? 'Uploading…' : 'Upload and validate'}</button><button className="secondary" disabled={exportAssets.isPending} onClick={() => exportAssets.mutate()}>{exportAssets.isPending ? 'Queueing…' : 'Generate asset CSV export'}</button></div>
      {(upload.error || exportAssets.error) && <div className="notice error">{upload.error?.message ?? exportAssets.error?.message}</div>}
      {importStatus.data && <div className="notice"><strong>Import {importStatus.data.status}</strong><span>{importStatus.data.processedRows} processed of {importStatus.data.totalRows} · {importStatus.data.rejectedRows} rejected</span>{importStatus.data.downloadAvailable && <button className="secondary" onClick={() => void downloadFile(`/imports/jobs/${importJobId}/download`, 'asset-import-errors.csv')}>Download row error report</button>}{importStatus.data.errors.slice(0, 5).map((item, index) => <small key={`${item.row}-${index}`}>Row {item.row ?? '—'}: {item.error}</small>)}</div>}
      {importStatus.error && <div className="notice error">{importStatus.error.message}</div>}
      {exportStatus.data && <div className="notice"><strong>Export {exportStatus.data.status}</strong><span>{exportStatus.data.processedRows} of {exportStatus.data.totalRows} rows</span>{exportStatus.data.downloadAvailable && <button className="secondary" onClick={() => void downloadFile(`/imports/jobs/${exportJobId}/download`, 'sam-assets.csv')}>Download CSV</button>}</div>}
      {downloadError && <div className="notice error">{downloadError}</div>}
      {exportStatus.error && <div className="notice error">{exportStatus.error.message}</div>}
    </div></Panel>
  </>;
}
