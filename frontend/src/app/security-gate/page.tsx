"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck, Lock, UserPlus, KeyRound } from "lucide-react";

export default function SecurityGate() {
  const router = useRouter();
  const [setupMode, setSetupMode] = useState(false);
  const [username, setUsername] = useState("guardian");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    fetch("/api/auth/setup-required")
      .then(r => r.json())
      .then(d => { setSetupMode(d.setup_required); setChecking(false); })
      .catch(() => { setError("Backend unreachable — start the backend first"); setChecking(false); });
  }, []);

  const handleSetup = async () => {
    setError("");
    if (password.length < 6) { setError("Password must be at least 6 characters"); return; }
    if (password !== password2) { setError("Passwords don't match"); return; }
    setLoading(true);
    try {
      const res = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (data.status === "success") {
        localStorage.setItem("zangbeto_token", data.token);
        localStorage.setItem("zangbeto_user", data.username);
        router.push("/dashboard");
      } else {
        setError(data.detail || "Setup failed");
      }
    } catch (err) { setError("Connection error"); }
    finally { setLoading(false); }
  };

  const handleLogin = async () => {
    setError("");
    setLoading(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (data.status === "success") {
        localStorage.setItem("zangbeto_token", data.token);
        localStorage.setItem("zangbeto_user", data.username);
        router.push("/dashboard");
      } else {
        setError(data.detail || "Invalid credentials");
      }
    } catch (err) { setError("Connection error"); }
    finally { setLoading(false); }
  };

  if (checking) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-green-400 font-mono animate-pulse">Connecting...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-zinc-900 border border-zinc-800 rounded-xl p-8 shadow-2xl">
        <div className="flex justify-center mb-6">
          <ShieldCheck className="w-16 h-16 text-green-500" />
        </div>

        <h1 className="text-2xl font-bold text-center mb-2">ZANGBETO</h1>
        <p className="text-zinc-400 text-center mb-8 text-sm">
          {setupMode ? "First-time Setup — Create your Guardian account" : "Enter credentials to access"}
        </p>

        {error && (
          <div className="bg-red-950/30 border border-red-800 text-red-300 text-xs p-3 rounded mb-4">
            ⚠️ {error}
          </div>
        )}

        <div className="space-y-4">
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Username</label>
            <div className="flex items-center gap-2 bg-zinc-800 p-3 rounded-lg border border-zinc-700 focus-within:border-green-500">
              <UserPlus className="w-4 h-4 text-zinc-400" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="bg-transparent border-none outline-none text-white w-full"
              />
            </div>
          </div>

          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Password</label>
            <div className="flex items-center gap-2 bg-zinc-800 p-3 rounded-lg border border-zinc-700 focus-within:border-green-500">
              <KeyRound className="w-4 h-4 text-zinc-400" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && (setupMode ? handleSetup() : handleLogin())}
                placeholder="Enter password"
                className="bg-transparent border-none outline-none text-white w-full"
              />
            </div>
          </div>

          {setupMode && (
            <div>
              <label className="text-xs text-zinc-500 mb-1 block">Confirm Password</label>
              <div className="flex items-center gap-2 bg-zinc-800 p-3 rounded-lg border border-zinc-700 focus-within:border-green-500">
                <Lock className="w-4 h-4 text-zinc-400" />
                <input
                  type="password"
                  value={password2}
                  onChange={(e) => setPassword2(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSetup()}
                  placeholder="Confirm password"
                  className="bg-transparent border-none outline-none text-white w-full"
                />
              </div>
            </div>
          )}

          <button
            onClick={setupMode ? handleSetup : handleLogin}
            disabled={loading}
            className="w-full bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white font-semibold py-3 rounded-lg transition-all"
          >
            {loading ? "..." : setupMode ? "Create Account" : "Unlock Zangbeto"}
          </button>
        </div>

        <p className="text-xs text-zinc-600 text-center mt-6">
          All actions are logged in the tamper-evident audit chain.
        </p>
      </div>
    </div>
  );
}