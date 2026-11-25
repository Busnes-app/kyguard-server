import React, { useEffect, useState } from 'react';
import { AppHeader } from './components/AppHeader';
import { BreakGlassBanner } from './components/BreakGlassBanner';
import { ReStepUp } from './components/ReStepUp';
import type { BreakGlassState } from './components/BreakGlassBanner';
import { Dashboard } from './pages/Dashboard';
import { Login } from './pages/Login';
import { ChangePassword } from './pages/ChangePassword';
import { StepUp } from './pages/StepUp';
import type { StepUpState } from './pages/StepUp';
import { Backup } from './pages/Backup';
import { SCIMAdmin } from './pages/SCIMAdmin';
import { Settings } from './pages/Settings';
import { Appearance } from './pages/Appearance';
import './styles/theme.css';
import './ky-ui/tokens.css';
import './ky-ui/navigation.css';
import './ky-ui/appearance.css';
import './ky-ui/appearance-themes.css';
import { secureFetch } from './api';

export const App: React.FC = () => {
  const [user, setUser] = useState<any>(null);
  const [breakGlass, setBreakGlass] = useState<BreakGlassState | null>(null);
  const [stepUp, setStepUp] = useState<StepUpState | null>(null);
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [settings, setSettings] = useState<any>(null);
  const [changingPassword, setChangingPassword] = useState(false);
  // Remounting Login solves a fresh CAPTCHA: the last token was spent on the sign-in.
  const [loginKey, setLoginKey] = useState(0);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const [authResp, setResp] = useResponses(
          await fetch('/api/auth/me'),
          await fetch('/api/settings')
        );

        if (setResp.ok) {
          const s = await setResp.json();
          setSettings(s);
        }

        if (authResp.ok) {
          const a = await authResp.json();
          if (a.authenticated) {
            setUser(a.user);
            setBreakGlass(a.break_glass ?? null);
            setStepUp(a.stepup ?? null);
          }
        }
      } catch (err) {
        console.error('Initialization error:', err);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  // /api/settings returns more fields once authenticated, so re-read it after login.
  const loadSettings = async () => {
    const resp = await fetch('/api/settings');
    if (resp.ok) {
      const s = await resp.json();
      setSettings(s);
    }
  };

  const handleLogout = async () => {
    await secureFetch('/api/auth/logout', { method: 'POST' });
    setUser(null);
    setBreakGlass(null);
    setStepUp(null);
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)', color: 'var(--ink)' }}>
        Loading {settings?.app_name || 'KyGuard'}...
      </div>
    );
  }

  if (!user) {
    return (
      <>
      {notice && <p role="status" style={{ padding: 16 }}>{notice}</p>}
      <Login
        key={loginKey}
        appName={settings?.app_name || 'KyGuard'}
        onSuccess={async (u) => {
          // A Secure session cookie is dropped on a plain-HTTP page, so a 200 from login does
          // not mean the browser is signed in: ask the server before showing the app.
          const me = await fetch('/api/auth/me').then((r) => r.json()).catch(() => null);
          if (me && me.authenticated === false) { // only a definite answer; a failed check proceeds
            setNotice(window.location.protocol === 'http:'
              ? 'Signed in, but this browser did not keep the session: the server only sends its cookie over HTTPS. Open this server at its https:// address (KY_APP_URL).'
              : 'Signed in, but this browser did not keep the session cookie. Check that cookies are allowed for this site.');
            setLoginKey((k) => k + 1);
            return;
          }
          setNotice('');
          setBreakGlass(me?.break_glass ?? null);
          setUser(u);
          void loadSettings();
        }}
      />
      </>
    );
  }

  if (stepUp) {
    return <StepUp state={stepUp} onLogout={handleLogout} onDone={async () => {
      // The exchange replaced the session cookie; read the active session and its settings.
      // A failed read rejects, and StepUp offers to retry it rather than another code.
      const r = await fetch('/api/auth/me');
      if (!r.ok) throw new Error('session check failed');
      const me = await r.json();
      if (!me?.authenticated) { setUser(null); setStepUp(null); return; }
      setUser(me.user); setStepUp(me.stepup ?? null);
      void loadSettings();
    }} />;
  }

  if (user.must_change_password || changingPassword) {
    return <ChangePassword onLogout={handleLogout}
      onCancel={user.must_change_password ? undefined : () => setChangingPassword(false)}
      onComplete={() => {
        setChangingPassword(false);
        setUser(null);
        setNotice('Password changed. Sign in with your new password.');
      }} />;
  }

  return (
    <div className="app-shell">
      <AppHeader
        appName={settings?.app_name || 'KyGuard'}
        activeTab={activeTab}
        onTabChange={(tab) => setActiveTab(tab)}
        user={user}
        onLogout={handleLogout}
        onChangePassword={user.account_type === 'break_glass' ? () => setChangingPassword(true) : undefined}
      />

      <ReStepUp />
      <main className="app-main">
        {breakGlass && <BreakGlassBanner state={breakGlass} onReason={(reason) => setBreakGlass({ ...breakGlass, reason })} />}
        {activeTab === 'dashboard' && <Dashboard settings={settings} user={user} onNavigate={(tab) => setActiveTab(tab)} />}
        {activeTab === 'scim' && <SCIMAdmin />}
        {activeTab === 'backup' && <Backup />}
        {activeTab === 'settings' && <Settings settings={settings} isAdmin={user.role === 'admin'} />}
        {activeTab === 'appearance' && <Appearance />}
      </main>
    </div>
  );
};

function useResponses(r1: Response, r2: Response): [Response, Response] {
  return [r1, r2];
}
