import { useState } from 'react';
import { Link, Navigate, NavLink, Outlet, Route, Routes, useNavigate } from 'react-router-dom';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useAuth } from './auth/AuthContext';
import { PageHeader } from './components/Panel';
import { DashboardPage } from './pages/DashboardPage';
import { AssetsPage } from './pages/AssetsPage';
import { FindingsPage } from './pages/FindingsPage';
import { AnalystPage } from './pages/AnalystPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { DataFeaturePage } from './pages/DataFeaturePage';
import { RiskPage } from './pages/RiskPage';
import { ContainmentPage } from './pages/ContainmentPage';
import { WorkflowsPage } from './pages/WorkflowsPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { GovernancePage } from './pages/GovernancePage';
import { PasswordResetPage } from './pages/PasswordResetPage';
import { UsersPage } from './pages/UsersPage';
import { ExposurePage } from './pages/ExposurePage';

const nav = [
  { to: '/', label: 'Overview', icon: '◫' },
  { to: '/inventory', label: 'Asset inventory', icon: '▦' },
  { to: '/findings', label: 'Vulnerabilities', icon: '⌁' },
  { to: '/risk', label: 'Risk & SLA', icon: '◷' },
  { to: '/compliance', label: 'Compliance', icon: '✓' },
  { to: '/exposure', label: 'Attack surface', icon: '◎' },
  { to: '/attack-paths', label: 'Attack paths', icon: '⌘' },
  { to: '/threats', label: 'Threat intelligence', icon: '⚑' },
  { to: '/analyst', label: 'AI security analyst', icon: '✳' },
  { to: '/governance', label: 'Governance', icon: '▤' },
  { to: '/workflows', label: 'Workflows', icon: '↗' },
  { to: '/containment', label: 'Containment', icon: '⛨' },
  { to: '/integrations', label: 'Integrations', icon: '⤴' },
  { to: '/reports', label: 'Reports', icon: '▧' },
  { to: '/audit', label: 'Audit log', icon: '≡' },
];

const loginSchema = z.object({ email: z.string().email('Enter a valid work email'), password: z.string().min(1, 'Enter your password') });
type LoginValues = z.infer<typeof loginSchema>;

function LoginPage() {
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const { register, handleSubmit, formState: { errors } } = useForm<LoginValues>({ resolver: zodResolver(loginSchema) });
  const submit = handleSubmit(async ({ email, password }) => {
    setBusy(true); setError('');
    try { await signIn(email, password); navigate('/', { replace: true }); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Sign in could not be completed'); }
    finally { setBusy(false); }
  });
  return <main className="login-page"><section className="login-card">
    <Brand /><p className="eyebrow">SECURITY EXPOSURE MANAGEMENT</p><h1>Sign in to SAM</h1><p className="muted">Use your organization account to open the security workspace.</p>
    <form onSubmit={submit} noValidate>
      <label>Email address<input type="email" autoComplete="username" {...register('email')} aria-invalid={!!errors.email} /></label>
      {errors.email && <small className="field-error">{errors.email.message}</small>}
      <label>Password<input type="password" autoComplete="current-password" {...register('password')} aria-invalid={!!errors.password} /></label>
      {errors.password && <small className="field-error">{errors.password.message}</small>}
      {error && <div className="notice error" role="alert">{error}</div>}
      <button className="primary full" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}<span>→</span></button>
      <Link className="link-button" to="/reset-password">Forgot your password?</Link>
    </form>
  </section></main>;
}

function Brand() { return <div className="brand"><span className="brand-mark">S</span><span>SAM <small>SECURITY PLATFORM</small></span></div>; }

function Layout() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  return <div className="app-shell">
    <aside className="sidebar"><Brand /><div className="nav-label">WORKSPACE</div><nav>{nav.slice(0, 8).map((item) => <NavLink key={item.to} to={item.to} end={item.to === '/'}><span>{item.icon}</span>{item.label}</NavLink>)}</nav><div className="nav-label">OPERATIONS</div><nav>{nav.slice(8).map((item) => <NavLink key={item.to} to={item.to}><span>{item.icon}</span>{item.label}</NavLink>)}{user?.role === 'admin' && <NavLink to="/users"><span>♙</span>User administration</NavLink>}</nav><div className="side-bottom"><span className="status-dot" />API-connected view<br /><small>{user?.role} account</small></div></aside>
    <main className="main"><header className="topbar"><span>Security workspace <b>/</b> SAM</span><div className="user-menu"><span className="avatar">{user?.email.slice(0, 1).toUpperCase()}</span><span>{user?.email}</span><button className="link-button" onClick={async () => { try { await signOut(); } finally { navigate('/login', { replace: true }); } }}>Sign out</button></div></header><div className="content"><Outlet /></div></main>
  </div>;
}

function Protected() {
  const { user, loading } = useAuth();
  if (loading) return <div className="boot-loading">Connecting to SAM…</div>;
  return user ? <Layout /> : <Navigate to="/login" replace />;
}

function PageNotFound() { return <><PageHeader title="Page not found" description="This SAM route is not available." /><NavLink to="/">Return to overview</NavLink></>; }

export function App() {
  const { user, loading } = useAuth();
  return <Routes>
    <Route path="/login" element={loading ? <div className="boot-loading">Connecting to SAM…</div> : user ? <Navigate to="/" replace /> : <LoginPage />} />
    <Route path="/reset-password" element={<PasswordResetPage />} />
    <Route element={<Protected />}>
      <Route path="/" element={<DashboardPage />} />
      <Route path="/inventory" element={<AssetsPage />} />
      <Route path="/findings" element={<FindingsPage />} />
      <Route path="/risk" element={<RiskPage />} />
      <Route path="/compliance" element={<DataFeaturePage title="Compliance" description="Recorded compliance posture and known gaps." endpoint="/compliance/summary" />} />
      <Route path="/exposure" element={<ExposurePage />} />
      <Route path="/attack-paths" element={<DataFeaturePage title="Attack path analysis" description="Asset relationships and exposed findings recorded in SAM." endpoint="/attack-paths" />} />
      <Route path="/threats" element={<ThreatsPage />} />
      <Route path="/analyst" element={<AnalystPage />} />
      <Route path="/governance" element={<GovernancePage />} />
      <Route path="/workflows" element={<WorkflowsPage />} />
      <Route path="/containment" element={<ContainmentPage />} />
      <Route path="/integrations" element={<IntegrationsPage />} />
      <Route path="/users" element={<UsersPage />} />
      <Route path="/reports" element={<DataFeaturePage title="Executive report" description="Generate a current report from persisted SAM records." endpoint="/reports/executive" />} />
      <Route path="/audit" element={<DataFeaturePage title="Audit log" description="Security events and chain integrity verification." endpoint="/audit" />} />
      <Route path="*" element={<PageNotFound />} />
    </Route>
  </Routes>;
}
