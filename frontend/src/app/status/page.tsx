"use client";
import { useState, useEffect } from "react";
import { Shield, RefreshCw, Play, AlertCircle, CheckCircle, Server, Cpu } from "lucide-react";
import { useRouter } from "next/navigation";

interface ContainerStatus {
  name: string;
  status: string;
  running: boolean;
  started_at?: string;
}

interface ImageStatus {
  name: string;
  present: boolean;
  size_gb?: number;
}

export default function StatusPage() {
  const router = useRouter();
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [restarting, setRestarting] = useState<string | null>(null);

  const fetchHealth = async () => {
    const token = localStorage.getItem("zangbeto_token");
    if (!token) { router.push("/security-gate"); return; }
    try {
      const res = await fetch("http://localhost:8000/api/health", {
        headers: { "Authorization": `Bearer ${token}` },
      });
      const data = await res.json();
      setHealth(data);
    } catch (e) {
      setHealth({ error: "Backend unreachable" });
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const restartContainer = async (name: string) => {
    if (!confirm(`Restart ${name}?`)) return;
    setRestarting(name);
    const token = localStorage.getItem("zangbeto_token");
    try {
      await fetch(`http://localhost:8000/api/health/restart/${name}`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
      });
      setTimeout(fetchHealth, 3000);
    } catch (e) {}
    setRestarting(null);
  };

  if (loading) {
    return <div className="min-h-screen bg-black flex items-center justify-center text-green-400">Loading...</div>;
  }

  const isHealthy = health?.overall === "healthy";

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-300 p-6 font-sans">
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Shield className="w-7 h-7 text-green-500" />
            <div>
              <h1 className="text-2xl font-bold text-white">System Health</h1>
              <p className="text-xs text-zinc-500">Live status of all Zangbeto services</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={fetchHealth} className="px-3 py-2 bg-zinc-800 hover:bg-zinc-700 rounded text-sm flex items-center gap-2">
              <RefreshCw className="w-4 h-4" /> Refresh
            </button>
            <button onClick={() => router.push("/dashboard")} className="px-3 py-2 bg-green-600 hover:bg-green-500 rounded text-sm text-white">
              Back to Dashboard
            </button>
          </div>
        </div>

        <div className={`p-4 rounded-lg mb-6 border-2 ${isHealthy ? "border-green-600 bg-green-950/30" : "border-yellow-600 bg-yellow-950/30"}`}>
          <div className="flex items-center gap-3">
            {isHealthy ? <CheckCircle className="w-6 h-6 text-green-400" /> : <AlertCircle className="w-6 h-6 text-yellow-400" />}
            <div>
              <p className={`font-bold ${isHealthy ? "text-green-400" : "text-yellow-400"}`}>
                {isHealthy ? "ALL SYSTEMS OPERATIONAL" : "DEGRADED — Check Below"}
              </p>
              <p className="text-xs text-zinc-400">Last checked: {new Date(health?.timestamp).toLocaleTimeString()}</p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 mb-6">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Server className="w-4 h-4 text-blue-400" />
              <span className="font-semibold text-white">Backend API</span>
            </div>
            <p className="text-sm text-green-400">● Running — localhost:8000</p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              <span className="font-semibold text-white">Ollama AI Brain</span>
            </div>
            <p className={`text-sm ${health?.ollama?.running ? "text-green-400" : "text-red-400"}`}>
              {health?.ollama?.running ? "● Running — llama3.2" : "● Offline — run 'ollama serve'"}
            </p>
          </div>
        </div>

        <h2 className="text-lg font-bold text-white mb-3">🐳 Running Containers</h2>
        <div className="space-y-2 mb-6">
          {health?.containers?.map((c: ContainerStatus) => (
            <div key={c.name} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full ${c.running ? "bg-green-500 animate-pulse" : "bg-red-500"}`}></div>
                <div>
                  <p className="font-mono text-sm text-white">{c.name}</p>
                  <p className="text-xs text-zinc-500">{c.status} {c.started_at && `— started ${new Date(c.started_at).toLocaleString()}`}</p>
                </div>
              </div>
              <button
                onClick={() => restartContainer(c.name)}
                disabled={restarting === c.name}
                className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 rounded text-xs flex items-center gap-1"
              >
                <Play className="w-3 h-3" /> {restarting === c.name ? "Restarting..." : "Restart"}
              </button>
            </div>
          ))}
        </div>

        <h2 className="text-lg font-bold text-white mb-3">📦 Docker Images (Sandbox Layer)</h2>
        <div className="space-y-2">
          {health?.images?.map((img: ImageStatus) => (
            <div key={img.name} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full ${img.present ? "bg-green-500" : "bg-red-500"}`}></div>
                <p className="font-mono text-sm text-white">{img.name}</p>
              </div>
              <p className="text-xs text-zinc-400">{img.present ? `${img.size_gb} GB` : "Not built"}</p>
            </div>
          ))}
        </div>

        <p className="text-xs text-zinc-600 text-center mt-8">Auto-refreshes every 10 seconds.</p>
      </div>
    </div>
  );
}