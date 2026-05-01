import { useState, useEffect, useCallback } from "react";

const API = "";

async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: {
      "Content-Type": "application/json",
      "X-Phalanx-Request": "1",
    },
    ...opts,
  });
  if (res.status === 401) throw new Error("AUTH");
  return res.json();
}

const FONT = `'DM Sans', 'Segoe UI', sans-serif`;
const MONO = `'JetBrains Mono', 'Fira Code', monospace`;

const C = {
  bg: "#0b0d11",
  surface: "#13161e",
  card: "#181c27",
  border: "#252a38",
  borderHover: "#3a4158",
  text: "#e4e6ec",
  textMuted: "#7c8298",
  textFaint: "#4e5470",
  accent: "#3d8bfd",
  accentSoft: "rgba(61,139,253,0.12)",
  green: "#2dd4a0",
  greenSoft: "rgba(45,212,160,0.12)",
  amber: "#f5a623",
  amberSoft: "rgba(245,166,35,0.12)",
  red: "#f05252",
  redSoft: "rgba(240,82,82,0.12)",
  purple: "#a78bfa",
};

const statusColor = (s) =>
  s === "healthy" ? C.green : s === "warning" ? C.amber : C.red;
const sevColor = (s) =>
  s === "high" || s === "critical" ? C.red : s === "medium" ? C.amber : C.green;
const sevBg = (s) =>
  s === "high" || s === "critical" ? C.redSoft : s === "medium" ? C.amberSoft : C.greenSoft;

const deviceIcon = (t) =>
  ({ phone: "\u{1F4F1}", tv: "\u{1F4FA}", laptop: "\u{1F4BB}", iot: "\u{1F321}\uFE0F", tablet: "\u{1F4CB}", desktop: "\u{1F5A5}\uFE0F" }[t] || "\u{1F4E1}");

function timeAgo(ts) {
  if (!ts) return "never";
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/* ─── Login ─── */
function LoginScreen({ onLogin }) {
  const [email, setEmail] = useState("");
  const [pass, setPass] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password: pass }),
      });
      if (res.success) onLogin();
      else setError(res.message || "Login failed");
    } catch {
      setError("Cannot reach Phalanx. Is the device running?");
    }
    setLoading(false);
  };

  return (
    <div style={{
      minHeight: "100vh", background: C.bg, display: "flex",
      alignItems: "center", justifyContent: "center", fontFamily: FONT,
    }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
      <div style={{
        background: C.surface, borderRadius: 20, padding: "48px 40px",
        border: `1px solid ${C.border}`, width: 380,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 32 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 12,
            background: `linear-gradient(135deg, ${C.accent}, ${C.green})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 22, fontWeight: 700, color: "#fff",
          }}>P</div>
          <div>
            <div style={{ fontSize: 20, fontWeight: 700, color: C.text }}>Phalanx</div>
            <div style={{ fontSize: 12, color: C.textMuted }}>Home Network Guardian</div>
          </div>
        </div>

        <input
          value={email} onChange={(e) => setEmail(e.target.value)}
          placeholder="Email" type="email"
          style={inputStyle} onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        <input
          value={pass} onChange={(e) => setPass(e.target.value)}
          placeholder="Password" type="password"
          style={{ ...inputStyle, marginTop: 10 }}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />

        {error && <div style={{ color: C.red, fontSize: 13, marginTop: 12 }}>{error}</div>}

        <button onClick={submit} disabled={loading} style={{
          width: "100%", padding: "12px 0", marginTop: 20, border: "none",
          borderRadius: 10, fontSize: 14, fontWeight: 600, cursor: "pointer",
          background: `linear-gradient(135deg, ${C.accent}, #2a6fdb)`,
          color: "#fff", fontFamily: FONT, opacity: loading ? 0.6 : 1,
        }}>
          {loading ? "Connecting..." : "Sign In"}
        </button>

        <div style={{ fontSize: 12, color: C.textFaint, marginTop: 16, textAlign: "center" }}>
          No account? Device works in free mode.
        </div>
      </div>
    </div>
  );
}

const inputStyle = {
  width: "100%", padding: "11px 14px", background: C.bg,
  border: `1px solid ${C.border}`, borderRadius: 10, color: C.text,
  fontSize: 14, fontFamily: FONT, outline: "none", boxSizing: "border-box",
};

/* ─── Main App ─── */
export default function PhalanxApp() {
  const [authed, setAuthed] = useState(null);
  const [tab, setTab] = useState("dashboard");
  const [dash, setDash] = useState(null);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [diag, setDiag] = useState(null);
  const [showDiag, setShowDiag] = useState(false);
  const [blocklist, setBlocklist] = useState(null);
  const [showWhitelist, setShowWhitelist] = useState(false);
  const [wlDomain, setWlDomain] = useState("");
  const [blDomain, setBlDomain] = useState("");
  const [renaming, setRenaming] = useState(null);
  const [newName, setNewName] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const d = await api("/api/dashboard");
      setDash(d);
      setError("");
      if (d.subscription?.authenticated === false && d.subscription?.user_id) {
        setAuthed(false);
        return;
      }
      setAuthed(true);
    } catch (e) {
      if (e.message === "AUTH") setAuthed(false);
      else setError("Connection lost");
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    if (authed === false) return;
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [authed, refresh]);

  useEffect(() => {
    if (tab === "alerts") {
      api("/api/alerts?limit=50&include_low=true").then((d) => setAlerts(d.alerts || [])).catch(() => {});
    }
  }, [tab, dash]);

  const loadDiag = async () => {
    setShowDiag(!showDiag);
    if (!showDiag) {
      try { setDiag(await api("/api/diagnostics")); } catch {}
    }
  };

  const loadBlocklist = async () => {
    try { setBlocklist(await api("/api/blocklist")); } catch {}
  };

  useEffect(() => { loadBlocklist(); }, []);

  const addWhitelist = async () => {
    if (!wlDomain.trim()) return;
    await api("/api/blocklist/whitelist", { method: "POST", body: JSON.stringify({ domain: wlDomain.trim() }) });
    setWlDomain("");
    loadBlocklist();
    refresh();
  };

  const addBlacklist = async () => {
    if (!blDomain.trim()) return;
    await api("/api/blocklist/blacklist", { method: "POST", body: JSON.stringify({ domain: blDomain.trim() }) });
    setBlDomain("");
    loadBlocklist();
    refresh();
  };

  const renameDevice = async (ip) => {
    if (!newName.trim()) return;
    await api("/api/devices/rename", { method: "POST", body: JSON.stringify({ ip, name: newName.trim() }) });
    setRenaming(null);
    setNewName("");
    refresh();
  };

  const logout = async () => {
    await api("/api/auth/logout", { method: "POST" });
    setAuthed(false);
  };

  if (authed === null) return <div style={{ minHeight: "100vh", background: C.bg }} />;
  if (authed === false) return <LoginScreen onLogin={() => { setAuthed(true); refresh(); }} />;
  if (!dash) return <div style={{ minHeight: "100vh", background: C.bg }} />;

  const devices = dash.devices?.list || [];
  const onlineCount = dash.devices?.online || 0;
  const totalDevices = dash.devices?.total || 0;
  const blockedDomains = dash.blocklist?.total_domains || 0;
  const dnsStats = dash.dns || {};
  const recentAlerts = dash.alerts?.recent || [];
  const sub = dash.subscription || {};

  const getDeviceStatus = (d) => {
    if (d.is_blocked) return "alert";
    const age = Date.now() / 1000 - (d.last_seen || 0);
    return age < 300 ? "healthy" : age < 1800 ? "warning" : "alert";
  };

  return (
    <div style={{ fontFamily: FONT, background: C.bg, color: C.text, minHeight: "100vh" }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />

      {/* ── Top Bar ── */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "14px 24px", background: C.surface,
        borderBottom: `1px solid ${C.border}`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 10,
            background: `linear-gradient(135deg, ${C.accent}, ${C.green})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 17, fontWeight: 700, color: "#fff",
          }}>P</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, letterSpacing: "-0.3px" }}>Phalanx</div>
            <div style={{ fontSize: 10, color: C.textMuted }}>
              {sub.status === "active" ? "Subscription active" :
               sub.status === "grace" ? `Grace period — ${sub.days_until_freeze}d left` :
               sub.status === "lapsed" ? "Blocklists frozen" : "Free mode"}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          {["dashboard", "devices", "alerts", "blocklist"].map((t) => (
            <button key={t} onClick={() => { setTab(t); setSelectedDevice(null); }} style={{
              padding: "7px 14px", borderRadius: 8, border: "none", cursor: "pointer",
              fontSize: 13, fontWeight: 600, fontFamily: FONT,
              background: tab === t ? C.accentSoft : "transparent",
              color: tab === t ? C.accent : C.textMuted,
            }}>{t.charAt(0).toUpperCase() + t.slice(1)}</button>
          ))}
          {sub.authenticated && (
            <button onClick={logout} style={{
              marginLeft: 8, padding: "7px 12px", borderRadius: 8,
              border: `1px solid ${C.border}`, background: "transparent",
              color: C.textMuted, fontSize: 12, fontFamily: FONT, cursor: "pointer",
            }}>Sign out</button>
          )}
        </div>
      </div>

      {error && <div style={{ padding: "8px 24px", background: C.redSoft, color: C.red, fontSize: 13 }}>{error}</div>}

      <div style={{ padding: "20px 24px", maxWidth: 960, margin: "0 auto" }}>

        {/* ══ DASHBOARD ══ */}
        {tab === "dashboard" && !selectedDevice && (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 24 }}>
              <Card label="Devices online" value={`${onlineCount} / ${totalDevices}`} color={C.green}
                sub={onlineCount === totalDevices ? "All connected" : `${totalDevices - onlineCount} offline`} />
              <Card label="Domains blocked" value={blockedDomains.toLocaleString()} color={C.accent}
                sub="In active blocklist" />
              <Card label="DNS queries" value={(dnsStats.queries || 0).toLocaleString()} color={C.purple}
                sub={`${dnsStats.blocked || 0} blocked · ${dnsStats.cached || 0} cached`} />
            </div>

            {recentAlerts.filter((a) => a.severity !== "low").length > 0 && (
              <Section title="Alerts">
                {recentAlerts.filter((a) => a.severity !== "low").map((a, i) => (
                  <AlertRow key={i} alert={a} />
                ))}
              </Section>
            )}

            <Section title="Devices">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {devices.map((d) => (
                  <DeviceCard key={d.ip} device={d} status={getDeviceStatus(d)}
                    onClick={() => setSelectedDevice(d)} />
                ))}
              </div>
              {devices.length === 0 && (
                <div style={{ color: C.textMuted, fontSize: 13, padding: 20, textAlign: "center" }}>
                  No devices seen yet. Point a device's DNS to this Pi.
                </div>
              )}
            </Section>

            {dash.blocklist?.staleness_warning && (
              <div style={{
                background: C.amberSoft, borderRadius: 12, padding: "14px 18px",
                border: `1px solid ${C.amber}33`, marginTop: 16,
                fontSize: 13, color: C.amber,
              }}>
                {dash.blocklist.staleness_warning}
              </div>
            )}
          </>
        )}

        {/* ══ DEVICE DETAIL ══ */}
        {selectedDevice && (
          <>
            <button onClick={() => setSelectedDevice(null)} style={{
              background: "none", border: "none", color: C.accent, cursor: "pointer",
              fontSize: 13, fontWeight: 600, marginBottom: 16, padding: 0, fontFamily: FONT,
            }}>&larr; Back</button>

            <div style={{
              background: C.card, borderRadius: 16, padding: "24px 28px",
              border: `1px solid ${C.border}`, marginBottom: 16,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
                <span style={{ fontSize: 38 }}>{deviceIcon(selectedDevice.device_type)}</span>
                <div style={{ flex: 1 }}>
                  {renaming === selectedDevice.ip ? (
                    <div style={{ display: "flex", gap: 8 }}>
                      <input value={newName} onChange={(e) => setNewName(e.target.value)}
                        placeholder="New name" style={{ ...inputStyle, width: 180, padding: "6px 10px" }}
                        onKeyDown={(e) => e.key === "Enter" && renameDevice(selectedDevice.ip)}
                        autoFocus />
                      <button onClick={() => renameDevice(selectedDevice.ip)}
                        style={smallBtn}>Save</button>
                      <button onClick={() => setRenaming(null)}
                        style={{ ...smallBtn, background: "transparent", color: C.textMuted }}>Cancel</button>
                    </div>
                  ) : (
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <div style={{ fontSize: 20, fontWeight: 700 }}>{selectedDevice.name}</div>
                      <button onClick={() => { setRenaming(selectedDevice.ip); setNewName(selectedDevice.name); }}
                        style={{ ...smallBtn, fontSize: 11, padding: "3px 8px" }}>Rename</button>
                    </div>
                  )}
                  <div style={{ fontSize: 12, color: C.textMuted, marginTop: 3 }}>
                    Last seen: {timeAgo(selectedDevice.last_seen)}
                  </div>
                </div>
                <StatusPill status={getDeviceStatus(selectedDevice)} />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                <StatBox label="IP address" value={selectedDevice.ip} />
                <StatBox label="Type" value={selectedDevice.device_type} />
                <StatBox label="MAC" value={selectedDevice.mac || "—"} />
              </div>
            </div>
          </>
        )}

        {/* ══ DEVICES TAB ══ */}
        {tab === "devices" && !selectedDevice && (
          <Section title={`All devices (${totalDevices})`}>
            {devices.map((d) => (
              <DeviceRow key={d.ip} device={d} status={getDeviceStatus(d)}
                onClick={() => setSelectedDevice(d)} />
            ))}
            {devices.length === 0 && (
              <div style={{ color: C.textMuted, fontSize: 13, padding: 20, textAlign: "center" }}>
                No devices detected yet.
              </div>
            )}
          </Section>
        )}

        {/* ══ ALERTS TAB ══ */}
        {tab === "alerts" && (
          <>
            <Section title="All alerts">
              {alerts.length === 0 && (
                <div style={{ color: C.textMuted, fontSize: 13, padding: 20, textAlign: "center" }}>
                  No alerts. Your network looks clean.
                </div>
              )}
              {alerts.map((a, i) => <AlertRow key={i} alert={a} />)}
            </Section>

            {/* Advanced Diagnostics */}
            <div style={{ marginTop: 24, borderTop: `1px solid ${C.border}`, paddingTop: 20 }}>
              <button onClick={loadDiag} style={{
                background: "none", border: `1px solid ${C.border}`, borderRadius: 10,
                padding: "10px 18px", cursor: "pointer", fontFamily: FONT,
                fontSize: 13, fontWeight: 600, color: C.textMuted, width: "100%",
                display: "flex", alignItems: "center", gap: 8,
              }}>
                Advanced Diagnostics
                <span style={{ marginLeft: "auto", fontSize: 11, transform: showDiag ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>{"\u25BC"}</span>
              </button>

              {showDiag && diag && (
                <div style={{
                  marginTop: 14, background: C.bg, borderRadius: 12,
                  border: `1px solid ${C.border}`, padding: 18, fontFamily: MONO, fontSize: 12,
                }}>
                  <div style={{ color: C.textMuted, fontWeight: 600, marginBottom: 10, fontFamily: FONT, fontSize: 13 }}>System</div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 16 }}>
                    <StatBox label="Memory (RSS)" value={`${diag.system?.memory_rss_mb || "—"} MB`} />
                    <StatBox label="CPU" value={`${diag.system?.cpu_percent || "—"}%`} />
                    <StatBox label="Uptime" value={diag.system?.uptime_seconds ? `${Math.floor(diag.system.uptime_seconds / 60)}m` : "—"} />
                  </div>
                  <div style={{ color: C.textMuted, fontWeight: 600, marginBottom: 10, fontFamily: FONT, fontSize: 13 }}>DNS proxy</div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
                    <StatBox label="Queries" value={(diag.dns?.queries || 0).toLocaleString()} />
                    <StatBox label="Blocked" value={(diag.dns?.blocked || 0).toLocaleString()} />
                    <StatBox label="Forwarded" value={(diag.dns?.forwarded || 0).toLocaleString()} />
                    <StatBox label="Cached" value={(diag.dns?.cached || 0).toLocaleString()} />
                  </div>
                </div>
              )}
            </div>
          </>
        )}

        {/* ══ BLOCKLIST TAB ══ */}
        {tab === "blocklist" && (
          <>
            <Section title="Blocklist">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 20 }}>
                <Card label="Total domains" value={(blocklist?.total_domains || blockedDomains).toLocaleString()} color={C.accent} />
                <Card label="Sources" value={Object.keys(blocklist?.sources || {}).length.toString()} color={C.green} />
              </div>

              {blocklist?.sources && Object.entries(blocklist.sources).map(([name, info]) => (
                <div key={name} style={{
                  background: C.card, borderRadius: 12, padding: "14px 18px",
                  border: `1px solid ${C.border}`, marginBottom: 8,
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                }}>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 600 }}>{name}</div>
                    <div style={{ fontSize: 12, color: C.textMuted, marginTop: 2 }}>
                      {(info.count || 0).toLocaleString()} domains · Updated {timeAgo(info.updated_at)}
                    </div>
                  </div>
                </div>
              ))}

              {blocklist?.staleness_warning && (
                <div style={{
                  background: C.amberSoft, borderRadius: 10, padding: "12px 16px",
                  color: C.amber, fontSize: 13, marginTop: 12,
                }}>
                  {blocklist.staleness_warning}
                </div>
              )}
            </Section>

            {/* Whitelist / Blacklist controls */}
            <Section title="Manual overrides">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: C.textMuted, marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.5px" }}>
                    Whitelist a domain
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <input value={wlDomain} onChange={(e) => setWlDomain(e.target.value)}
                      placeholder="e.g. example.com" style={{ ...inputStyle, flex: 1, padding: "8px 12px" }}
                      onKeyDown={(e) => e.key === "Enter" && addWhitelist()} />
                    <button onClick={addWhitelist} style={smallBtn}>Allow</button>
                  </div>
                  <div style={{ fontSize: 11, color: C.textFaint, marginTop: 6 }}>
                    Stop blocking this domain
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: C.textMuted, marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.5px" }}>
                    Blacklist a domain
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <input value={blDomain} onChange={(e) => setBlDomain(e.target.value)}
                      placeholder="e.g. sketchy-site.com" style={{ ...inputStyle, flex: 1, padding: "8px 12px" }}
                      onKeyDown={(e) => e.key === "Enter" && addBlacklist()} />
                    <button onClick={addBlacklist} style={{ ...smallBtn, background: C.redSoft, color: C.red }}>Block</button>
                  </div>
                  <div style={{ fontSize: 11, color: C.textFaint, marginTop: 6 }}>
                    Force-block this domain
                  </div>
                </div>
              </div>
            </Section>
          </>
        )}
      </div>
    </div>
  );
}

/* ─── Reusable Components ─── */

function Card({ label, value, color, sub }) {
  return (
    <div style={{
      background: C.card, borderRadius: 14, padding: "18px 20px",
      border: `1px solid ${C.border}`,
    }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.7px" }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color, marginTop: 5, fontFamily: MONO }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: C.textMuted, marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: C.textMuted, marginBottom: 12 }}>{title}</div>
      {children}
    </div>
  );
}

function StatBox({ label, value }) {
  return (
    <div style={{ background: C.bg, borderRadius: 10, padding: "10px 14px" }}>
      <div style={{ fontSize: 10, fontWeight: 600, color: C.textFaint, textTransform: "uppercase", letterSpacing: "0.5px" }}>{label}</div>
      <div style={{ fontSize: 15, fontWeight: 600, color: C.text, marginTop: 3, fontFamily: MONO }}>{value}</div>
    </div>
  );
}

function StatusPill({ status }) {
  const label = status === "healthy" ? "Healthy" : status === "warning" ? "Idle" : "Alert";
  const color = statusColor(status);
  return (
    <div style={{
      padding: "4px 14px", borderRadius: 20, fontSize: 12, fontWeight: 600,
      background: `${color}18`, color, border: `1px solid ${color}44`,
    }}>{label}</div>
  );
}

function DeviceCard({ device, status, onClick }) {
  const color = statusColor(status);
  return (
    <button onClick={onClick} style={{
      background: C.card, border: `1px solid ${C.border}`, borderRadius: 12,
      padding: "14px 16px", cursor: "pointer", textAlign: "left",
      display: "flex", alignItems: "center", gap: 12, fontFamily: FONT,
      transition: "border-color 0.2s", width: "100%",
    }}>
      <span style={{ fontSize: 24 }}>{deviceIcon(device.device_type)}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{device.name}</div>
        <div style={{ fontSize: 11, color: C.textMuted, marginTop: 2 }}>{timeAgo(device.last_seen)}</div>
      </div>
      <div style={{
        width: 9, height: 9, borderRadius: "50%", background: color,
        boxShadow: `0 0 7px ${color}66`, flexShrink: 0,
      }} />
    </button>
  );
}

function DeviceRow({ device, status, onClick }) {
  const color = statusColor(status);
  return (
    <button onClick={onClick} style={{
      width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 12,
      padding: "14px 18px", marginBottom: 8, cursor: "pointer", textAlign: "left",
      display: "flex", alignItems: "center", gap: 14, fontFamily: FONT,
    }}>
      <span style={{ fontSize: 26 }}>{deviceIcon(device.device_type)}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: C.text }}>{device.name}</div>
        <div style={{ fontSize: 11, color: C.textMuted, marginTop: 2 }}>
          {device.ip} · {timeAgo(device.last_seen)}
        </div>
      </div>
      <div style={{ textAlign: "right" }}>
        <div style={{ fontSize: 11, color, fontWeight: 600 }}>
          {status === "healthy" ? "Online" : status === "warning" ? "Idle" : "Offline"}
        </div>
      </div>
    </button>
  );
}

function AlertRow({ alert }) {
  const color = sevColor(alert.severity);
  return (
    <div style={{
      background: C.card, border: `1px solid ${color}22`, borderRadius: 12,
      padding: "13px 18px", marginBottom: 8, display: "flex", alignItems: "flex-start", gap: 12,
    }}>
      <span style={{
        fontSize: 10, fontWeight: 700, padding: "3px 9px", borderRadius: 6,
        background: sevBg(alert.severity), color, whiteSpace: "nowrap", marginTop: 2,
        textTransform: "uppercase",
      }}>{alert.severity}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600 }}>{alert.device_name || alert.device_ip}</div>
        <div style={{ fontSize: 12, color: C.textMuted, marginTop: 3, lineHeight: 1.4 }}>{alert.message}</div>
        {alert.details && <div style={{ fontSize: 11, color: C.textFaint, marginTop: 2 }}>{alert.details}</div>}
      </div>
      <div style={{ fontSize: 11, color: C.textFaint, whiteSpace: "nowrap", flexShrink: 0 }}>{timeAgo(alert.timestamp)}</div>
    </div>
  );
}

const smallBtn = {
  padding: "6px 14px", borderRadius: 8, border: "none", cursor: "pointer",
  fontSize: 12, fontWeight: 600, fontFamily: FONT,
  background: C.accentSoft, color: C.accent,
};
