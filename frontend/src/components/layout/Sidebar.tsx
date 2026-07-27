import { useAuth } from "../../context/AuthContext";
import { Link, useLocation } from "wouter";

export type SectionId =
  | "overview"
  | "agents"
  | "agent-detail"
  | "incidents"
  | "replay"
  | "graph"
  | "memory"
  | "tools"
  | "policies"
  | "threats"
  | "mcp"
  | "redteam"
  | "sandbox"
  | "audit-logs";

interface NavItem {
  id: SectionId;
  label: string;
  icon: string;
  badge?: number;
  href: string;
}

const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: "Observability",
    items: [
      { id: "overview", label: "Dashboard", icon: "◈", href: "/" },
      { id: "agents", label: "Agent Fleet", icon: "⬡", href: "/agents" },
      { id: "incidents", label: "Incidents", icon: "⚠", href: "/incidents" },
      { id: "replay", label: "Attack Replay", icon: "▶", href: "/replay" },
    ],
  },
  {
    section: "Intelligence",
    items: [
      { id: "graph", label: "Security Graph", icon: "⎈", href: "/graph" },
      { id: "memory", label: "Memory Objects", icon: "≡", href: "/memory" },
      { id: "tools", label: "Tool Trust", icon: "⚙", href: "/tools" },
      { id: "threats", label: "Threat Intel", icon: "⚡", href: "/threats" },
    ],
  },
  {
    section: "Control",
    items: [
      { id: "policies", label: "Policies", icon: "🛡", href: "/policies" },
      { id: "mcp", label: "MCP Security", icon: "⏣", href: "/mcp" },
      { id: "sandbox", label: "Sandboxes", icon: "📦", href: "/sandbox" },
      { id: "redteam", label: "Red Team", icon: "🎯", href: "/redteam" },
      { id: "audit-logs", label: "Audit Logs", icon: "📝", href: "/audit-logs" },
    ],
  },
];

interface Props {
  incidentCount?: number;
}

function isActive(item: NavItem, pathname: string): boolean {
  if (item.href === "/") {
    return pathname === "/";
  }
  return pathname.startsWith(item.href);
}

export default function Sidebar({ incidentCount = 0 }: Props) {
  const { user, org, logout } = useAuth();
  const [pathname] = useLocation();

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-logo">AS</div>
        <div className="sidebar-brand-text">
          <h1>Agent Sentinel</h1>
          <p>RUNTIME SECURITY</p>
        </div>
      </div>

      <nav className="sidebar-nav">
        {NAV.map((group) => (
          <div key={group.section} style={{ marginBottom: 12 }}>
            <div className="nav-section-label">{group.section}</div>
            {group.items.map((item) => {
              const active = isActive(item, pathname);
              return (
                <Link
                  key={item.id}
                  href={item.href}
                  className={`nav-item ${active ? "active" : ""}`}
                  style={
                    active
                      ? ({
                          "--nav-accent":
                            item.id === "incidents"
                              ? "var(--red)"
                              : item.id === "redteam"
                                ? "var(--amber)"
                                : "var(--cyan)",
                        } as React.CSSProperties)
                      : {}
                  }
                >
                  <span className="nav-icon">{item.icon}</span>
                  {item.label}
                  {item.id === "incidents" && incidentCount > 0 && (
                    <span className="nav-badge">{incidentCount}</span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-user">
          <div className="user-avatar">{user?.email?.[0]?.toUpperCase() ?? "U"}</div>
          <div className="user-info">
            <div className="user-email">{user?.email}</div>
            <div className="user-role">{org?.name ?? "Default Org"}</div>
          </div>
          <button className="logout-btn" onClick={logout} title="Sign Out">
            ⎋
          </button>
        </div>
      </div>
    </aside>
  );
}
