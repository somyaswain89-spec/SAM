import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { api } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { LoadError, Loading, PageHeader, Panel } from '../components/Panel';

type Role = 'admin' | 'security_admin' | 'analyst' | 'auditor' | 'viewer';
type UserRecord = { id: number; email: string; role: Role; active: boolean };
type UserPageResult = { items: UserRecord[]; total: number; limit: number; offset: number };

const createSchema = z.object({
  email: z.string().email('Enter a valid work email'),
  password: z.string().min(12, 'Use at least 12 characters').max(256),
  role: z.enum(['admin', 'security_admin', 'analyst', 'auditor', 'viewer']),
});
type CreateValues = z.infer<typeof createSchema>;

export function UsersPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState('');
  const [operationError, setOperationError] = useState('');
  const [roleDrafts, setRoleDrafts] = useState<Record<number, Role>>({});
  const users = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => api.get<UserPageResult>('/auth/users?limit=200&offset=0'),
    enabled: user?.role === 'admin',
  });
  const { register, handleSubmit, reset, formState: { errors } } = useForm<CreateValues>({
    resolver: zodResolver(createSchema),
    defaultValues: { role: 'analyst' },
  });
  const create = useMutation({
    mutationFn: (values: CreateValues) => api.post<{ email: string; role: Role }>('/auth/users', values),
    onSuccess: async (created) => {
      reset({ email: '', password: '', role: 'analyst' });
      await queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      setNotice(`Created ${created.email} with the ${created.role} role.`);
    },
  });
  const setActive = useMutation({
    mutationFn: ({ id, active }: { id: number; active: boolean }) => api.patch<UserRecord>(`/auth/users/${id}/active`, { active }),
    onSuccess: async (updated) => {
      setOperationError('');
      setNotice(`${updated.email} is now ${updated.active ? 'active' : 'inactive'}.`);
      await queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (error) => { setNotice(''); setOperationError(error instanceof Error ? error.message : 'Account update failed'); },
  });
  const setRole = useMutation({
    mutationFn: ({ id, role }: { id: number; role: Role }) => api.patch<UserRecord>(`/auth/users/${id}/role`, { role }),
    onSuccess: async (updated) => {
      setOperationError('');
      setRoleDrafts((drafts) => ({ ...drafts, [updated.id]: updated.role }));
      setNotice(`${updated.email} now has the ${updated.role.replace('_', ' ')} role. Existing sessions were revoked.`);
      await queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (error) => { setNotice(''); setOperationError(error instanceof Error ? error.message : 'Role update failed'); },
  });

  if (user?.role !== 'admin') return <>
    <PageHeader title="User administration" description="Manage SAM user access." />
    <div className="notice error" role="alert">Administrator access is required to manage users.</div>
  </>;

  return <>
    <PageHeader title="User administration" description="Create accounts and suspend or restore access. Every status change is audited and revokes existing sessions." />
    {notice && <div className="notice success" role="status">{notice}</div>}
    {operationError && <div className="notice error" role="alert">{operationError}</div>}
    <Panel title="Create account">
      <form className="form-grid" onSubmit={handleSubmit((values) => { setNotice(''); create.mutate(values); })} noValidate>
        <label>Work email<input type="email" autoComplete="email" {...register('email')} aria-invalid={!!errors.email} />{errors.email && <small className="field-error">{errors.email.message}</small>}</label>
        <label>Temporary password<input type="password" autoComplete="new-password" {...register('password')} aria-invalid={!!errors.password} />{errors.password && <small className="field-error">{errors.password.message}</small>}</label>
        <label>Role<select {...register('role')}><option value="analyst">Analyst</option><option value="viewer">Viewer</option><option value="auditor">Auditor</option><option value="security_admin">Security administrator</option><option value="admin">Administrator</option></select></label>
        <div className="form-actions"><button className="primary" disabled={create.isPending}>{create.isPending ? 'Creating…' : 'Create account'}</button></div>
        {create.error && <div className="notice error" role="alert">{create.error.message}</div>}
      </form>
      <p className="muted">Passwords require at least 12 characters. Users can request a password reset after email delivery is configured.</p>
    </Panel>
    <Panel title="Accounts">
      {users.isPending ? <Loading /> : users.error ? <LoadError message={users.error.message} retry={() => void users.refetch()} /> : <>
        <div className="filters"><span className="pill">{users.data.total} accounts</span><button className="secondary" onClick={() => void users.refetch()} disabled={users.isFetching}>{users.isFetching ? 'Refreshing…' : 'Refresh'}</button></div>
        <div className="table-scroll"><table><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead><tbody>
          {users.data.items.map((account) => {
            const selectedRole = roleDrafts[account.id] ?? account.role;
            return <tr key={account.id}>
            <td>{account.email}{account.id === user.id && <span className="pill">You</span>}</td>
            <td><select aria-label={`Role for ${account.email}`} value={selectedRole} disabled={account.id === user.id || setRole.isPending} onChange={(event) => setRoleDrafts((drafts) => ({ ...drafts, [account.id]: event.target.value as Role }))}><option value="analyst">Analyst</option><option value="viewer">Viewer</option><option value="auditor">Auditor</option><option value="security_admin">Security administrator</option><option value="admin">Administrator</option></select>{selectedRole !== account.role && <button className="secondary" disabled={setRole.isPending} onClick={() => { setNotice(''); setOperationError(''); setRole.mutate({ id: account.id, role: selectedRole }); }}>Save role</button>}</td>
            <td><span className={`pill ${account.active ? '' : 'status-inactive'}`}>{account.active ? 'Active' : 'Inactive'}</span></td>
            <td><button className={account.active ? 'secondary' : 'primary'} disabled={setActive.isPending || (account.id === user.id && account.active)} onClick={() => { setNotice(''); setOperationError(''); setActive.mutate({ id: account.id, active: !account.active }); }}>{account.active ? 'Deactivate' : 'Reactivate'}</button></td>
          </tr>;
          })}
        </tbody></table></div>
      </>}
    </Panel>
  </>;
}
