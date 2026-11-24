import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { api } from '../api/client';

const requestSchema = z.object({ email: z.string().email('Enter a valid work email') });
const confirmSchema = z.object({
  password: z.string().min(12, 'Use at least 12 characters').max(256),
  confirmPassword: z.string(),
}).refine((values) => values.password === values.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});
type RequestValues = z.infer<typeof requestSchema>;
type ConfirmValues = z.infer<typeof confirmSchema>;

export function PasswordResetPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') ?? '';
  const [success, setSuccess] = useState('');
  const requestForm = useForm<RequestValues>({ resolver: zodResolver(requestSchema) });
  const confirmForm = useForm<ConfirmValues>({ resolver: zodResolver(confirmSchema) });
  const requestReset = useMutation({
    mutationFn: (values: RequestValues) => api.post<{ status: string }>('/auth/password-reset/request', values),
    onSuccess: (result) => setSuccess(result.status),
  });
  const confirmReset = useMutation({
    mutationFn: (values: ConfirmValues) => api.post<{ status: string }>('/auth/password-reset/confirm', {
      token,
      new_password: values.password,
    }),
    onSuccess: (result) => setSuccess(result.status),
  });

  return <main className="login-page"><section className="login-card">
    <div className="brand"><span className="brand-mark">S</span><span>SAM <small>SECURITY PLATFORM</small></span></div>
    <p className="eyebrow">ACCOUNT RECOVERY</p>
    <h1>{token ? 'Set a new password' : 'Reset your password'}</h1>
    <p className="muted">{token
      ? 'Choose a new password for your SAM account. Reset links expire after 30 minutes and can only be used once.'
      : 'Enter your work email. If the account exists, SAM sends a one-time reset link.'}</p>

    {success ? <div className="notice success" role="status">{success}</div> : token ? <form onSubmit={confirmForm.handleSubmit((values) => confirmReset.mutate(values))} noValidate>
      <label>New password<input type="password" autoComplete="new-password" {...confirmForm.register('password')} aria-invalid={!!confirmForm.formState.errors.password} /></label>
      {confirmForm.formState.errors.password && <small className="field-error">{confirmForm.formState.errors.password.message}</small>}
      <label>Confirm new password<input type="password" autoComplete="new-password" {...confirmForm.register('confirmPassword')} aria-invalid={!!confirmForm.formState.errors.confirmPassword} /></label>
      {confirmForm.formState.errors.confirmPassword && <small className="field-error">{confirmForm.formState.errors.confirmPassword.message}</small>}
      {confirmReset.error && <div className="notice error" role="alert">{confirmReset.error.message}</div>}
      <button className="primary full" disabled={confirmReset.isPending}>{confirmReset.isPending ? 'Updating password…' : 'Update password'}</button>
    </form> : <form onSubmit={requestForm.handleSubmit((values) => requestReset.mutate(values))} noValidate>
      <label>Email address<input type="email" autoComplete="username" {...requestForm.register('email')} aria-invalid={!!requestForm.formState.errors.email} /></label>
      {requestForm.formState.errors.email && <small className="field-error">{requestForm.formState.errors.email.message}</small>}
      {requestReset.error && <div className="notice error" role="alert">{requestReset.error.message}</div>}
      <button className="primary full" disabled={requestReset.isPending}>{requestReset.isPending ? 'Requesting link…' : 'Send reset link'}</button>
    </form>}
    <p className="muted"><Link to="/login">Back to sign in</Link></p>
  </section></main>;
}
