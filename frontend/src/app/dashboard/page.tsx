"use client";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import { Terminal as TerminalIcon, FileCode, Bot, Send, Settings, Shield, Cpu, Folder, Play, AlertTriangle, Moon, Eye, Maximize2, LogOut, Globe, CheckCircle2 } from "lucide-react";
import { useState, useEffect, useRef, Fragment } from "react";

export default function Dashboard() {
  const [messages, setMessages] = useState([
    { sender: "Zangbeto", text: "Zangbeto Orchestrator online. All systems nominal. I am ready to assist with authorized security operations." }
  ]);
  const [input, setInput] = useState("");
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [lastCommand, setLastCommand] = useState("");
  const [pendingCommand, setPendingCommand] = useState<string | null>(null);
  const [pendingTargets, setPendingTargets] = useState<string[]>([]);
  const [terminalPendingCommand, setTerminalPendingCommand] = useState<string | null>(null);
  const [browserPendingAction, setBrowserPendingAction] = useState<string | null>(null);
  const [aiState, setAiState] = useState<"sleeping" | "awake">("sleeping");
  const [micEnabled, setMicEnabled] = useState(false);
  const [toolPrompt, setToolPrompt] = useState<string | null>(null);
  const [speakEnabled, setSpeakEnabled] = useState(true);
  const [aiEnabled, setAiEnabled] = useState(true);
  const [username, setUsername] = useState("Guardian");
  const [panels, setPanels] = useState({ ai: true, terminal: false, browser: false });
  const [showIdleWarning, setShowIdleWarning] = useState(false);
  const [idleSecondsLeft, setIdleSecondsLeft] = useState(60);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const terminalContainerRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<any>(null);
  const fitAddonRef = useRef<any>(null);
  const recognitionRef = useRef<any>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const clapStateRef = useRef({ lastClap: 0, lastWake: 0 });
  const aiStateRef = useRef(aiState);
  const isSpeakingRef = useRef(false);
  const micEnabledRef = useRef(false);
  const aiEnabledRef = useRef(true);
  const speakEnabledRef = useRef(true);
  const sleepTimerRef = useRef<any>(null);
  const idleTimerRef = useRef<any>(null);
  const warningTimerRef = useRef<any>(null);
  const countdownRef = useRef<any>(null);
  const sandboxInputRef = useRef("");

  // AUTH GUARD
  useEffect(() => {
    const token = localStorage.getItem("zangbeto_token");
    const user = localStorage.getItem("zangbeto_user");
    if (!token) { window.location.href = "/security-gate"; return; }
    if (user) setUsername(user);
  }, []);

  const apiFetch = async (url: string, options: any = {}) => {
    const token = localStorage.getItem("zangbeto_token") || "";
    const res = await fetch(url, {
      ...options,
      headers: { ...(options.headers || {}), "Authorization": `Bearer ${token}` },
    });
    if (res.status === 401) {
      localStorage.removeItem("zangbeto_token");
      localStorage.removeItem("zangbeto_user");
      window.location.href = "/security-gate";
      throw new Error("Unauthorized");
    }
    return res;
  };

  const handleLogout = () => {
    localStorage.removeItem("zangbeto_token");
    localStorage.removeItem("zangbeto_user");
    window.location.href = "/security-gate";
  };

  // IDLE TIMEOUT
  const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
  const WARNING_TIME_MS = 60 * 1000;

  const resetIdleTimer = () => {
    if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    if (warningTimerRef.current) clearTimeout(warningTimerRef.current);
    if (countdownRef.current) clearInterval(countdownRef.current);
    setShowIdleWarning(false);
    setIdleSecondsLeft(60);

    warningTimerRef.current = setTimeout(() => {
      setShowIdleWarning(true);
      setIdleSecondsLeft(60);
      countdownRef.current = setInterval(() => {
        setIdleSecondsLeft((prev) => {
          if (prev <= 1) {
            if (countdownRef.current) clearInterval(countdownRef.current);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }, IDLE_TIMEOUT_MS - WARNING_TIME_MS);

    idleTimerRef.current = setTimeout(() => {
      if (countdownRef.current) clearInterval(countdownRef.current);
      const u = localStorage.getItem("zangbeto_user") || "unknown";
      fetch("http://localhost:8000/api/audit/idle-logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: u }),
      }).catch(() => {});
      localStorage.removeItem("zangbeto_token");
      localStorage.removeItem("zangbeto_user");
      window.location.href = "/security-gate?reason=idle";
    }, IDLE_TIMEOUT_MS);
  };

  useEffect(() => {
    const token = localStorage.getItem("zangbeto_token");
    if (!token) return;
    resetIdleTimer();
    const events = ["mousedown", "mousemove", "keydown", "scroll", "touchstart", "click"];
    const handler = () => resetIdleTimer();
    events.forEach(e => window.addEventListener(e, handler));
    return () => {
      events.forEach(e => window.removeEventListener(e, handler));
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      if (warningTimerRef.current) clearTimeout(warningTimerRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);
    };
  }, []);

  const continueSession = () => resetIdleTimer();

  useEffect(() => { aiStateRef.current = aiState; }, [aiState]);
  useEffect(() => { isSpeakingRef.current = isSpeaking; }, [isSpeaking]);
  useEffect(() => { micEnabledRef.current = micEnabled; }, [micEnabled]);
  useEffect(() => { aiEnabledRef.current = aiEnabled; }, [aiEnabled]);
  useEffect(() => { speakEnabledRef.current = speakEnabled; }, [speakEnabled]);

  // XTERM TERMINAL
  useEffect(() => {
    let disposed = false;
    const initTerminal = async () => {
      if (!terminalContainerRef.current || xtermRef.current) return;
      const { Terminal: XTerm } = await import("@xterm/xterm");
      const { FitAddon } = await import("@xterm/addon-fit");
      await import("@xterm/xterm/css/xterm.css");
      if (disposed || !terminalContainerRef.current) return;

      const term = new XTerm({
        cursorBlink: true, fontSize: 13,
        fontFamily: "Consolas, 'Courier New', monospace",
        theme: { background: "#000000", foreground: "#d4d4d4", cursor: "#00ff00", green: "#00ff00", red: "#ff5555", yellow: "#ffff55" },
        rows: 20, scrollback: 5000, convertEol: true,
      });
      const fitAddon = new FitAddon();
      term.loadAddon(fitAddon);
      term.open(terminalContainerRef.current);
      fitAddon.fit();
      term.writeln("\x1b[1;32m╔════════════════════════════════════════════╗\x1b[0m");
      term.writeln("\x1b[1;32m║   ZANGBETO SANDBOX TERMINAL - KALI LINUX   ║\x1b[0m");
      term.writeln("\x1b[1;32m╚════════════════════════════════════════════╝\x1b[0m");
      term.writeln("");
      term.writeln("\x1b[1;33m[GUARDIAN] Click here and type directly, or let AI run commands.\x1b[0m");
      term.writeln("");
      
      term.onData(async (data) => {
        if (data === '\r') {
          const cmd = sandboxInputRef.current.trim();
          if (cmd) {
            term.write('\r\n');
            try {
              const res = await apiFetch("http://localhost:8000/api/sandbox/write", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ command: cmd }),
              });
              const result = await res.json();
              if (result.output) {
                result.output.split('\n').forEach((line: string) => term.writeln(line));
              }
            } catch (e) {
              term.writeln("\x1b[1;31mError connecting to sandbox.\x1b[0m");
            }
            term.write('\x1b[33m$ \x1b[0m');
            sandboxInputRef.current = "";
          } else {
            term.write('\r\n\x1b[33m$ \x1b[0m');
          }
        } else if (data === '\x7f') {
          if (sandboxInputRef.current.length > 0) {
            sandboxInputRef.current = sandboxInputRef.current.slice(0, -1);
            term.write('\b \b');
          }
        } else if (data >= ' ' || data === '\t') {
          sandboxInputRef.current += data;
          term.write(data);
        }
      });

      term.write('\x1b[33m$ \x1b[0m');
      xtermRef.current = term;
      fitAddonRef.current = fitAddon;
      const handleResize = () => { try { fitAddon.fit(); } catch(e){} };
      window.addEventListener("resize", handleResize);
      return () => { window.removeEventListener("resize", handleResize); term.dispose(); };
    };
    if (panels.ai) initTerminal();
    return () => { disposed = true; };
  }, [panels.ai]);

  useEffect(() => {
    if (panels.ai && fitAddonRef.current) {
      setTimeout(() => { try { fitAddonRef.current.fit(); } catch(e){} }, 150);
    }
  }, [panels.ai, panels.terminal, panels.browser]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const termWrite = (text: string) => {
    if (!xtermRef.current) return;
    xtermRef.current.writeln(text);
    xtermRef.current.scrollToBottom();
  };

  const getTerminalContext = (): string => {
    if (!xtermRef.current) return "";
    const buffer = xtermRef.current.buffer.active;
    const lines: string[] = [];
    const start = Math.max(0, buffer.length - 50);
    for (let i = start; i < buffer.length; i++) {
      const line = buffer.getLine(i);
      if (line) lines.push(line.translateToString(true));
    }
    return lines.join("\n").trim();
  };

  const resetSleepTimer = () => {
    if (sleepTimerRef.current) clearTimeout(sleepTimerRef.current);
    sleepTimerRef.current = setTimeout(() => {
      setAiState("sleeping");
      termWrite("\x1b[90m[Zangbeto: going back to sleep...]\x1b[0m");
    }, 30000);
  };

  const wakeUpZangbeto = () => {
    if (!aiEnabledRef.current) return;
    const now = Date.now();
    if (now - clapStateRef.current.lastWake < 5000) return;
    clapStateRef.current.lastWake = now;
    setAiState("awake");
    resetSleepTimer();
    termWrite("\x1b[1;32m⚡ Zangbeto is AWAKE\x1b[0m");
    termWrite("\x1b[33m  Listening...\x1b[0m");
    speakText("Yes, Guardian?");
  };

  const speakText = (text: string) => {
    if (!speakEnabledRef.current || !aiEnabledRef.current) return;
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      if (recognitionRef.current) { try { recognitionRef.current.stop(); } catch(e){} }
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 1.0;
      utterance.onstart = () => setIsSpeaking(true);
      utterance.onend = () => {
        setIsSpeaking(false);
        setTimeout(() => {
          if (micEnabledRef.current && recognitionRef.current) {
            try { recognitionRef.current.start(); } catch(e){}
          }
        }, 600);
      };
      window.speechSynthesis.speak(utterance);
    }
  };

  useEffect(() => {
    if (!micEnabled) return;
    let disposed = false;
    let stream: MediaStream | null = null;
    let audioCtx: AudioContext | null = null;
    let analyser: AnalyserNode | null = null;
    let animFrame: number | null = null;

    const startListening = async () => {
      try {
        if (typeof window !== "undefined" && ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window)) {
          const SR = (window as any).webkitSpeechRecognition || (window as any).SpeechRecognition;
          const rec = new SR();
          rec.continuous = true; rec.interimResults = true; rec.lang = 'en-US';
          rec.onresult = (event: any) => {
            if (isSpeakingRef.current || !aiEnabledRef.current) return;
            const lastResult = event.results[event.results.length - 1];
            const transcript = lastResult[0].transcript.toLowerCase().trim();
            const wakeMatch = /\b(hey\s+zangbeto|wake\s+up\s+zangbeto|zangbeto\s+wake\s+up)\b/.test(transcript);
            if (aiStateRef.current === "sleeping" && wakeMatch) { wakeUpZangbeto(); return; }
            if (aiStateRef.current === "awake" && lastResult.isFinal) {
              const cleaned = transcript.replace(/\b(hey|wake up)\s+zangbeto\b/g, "").trim();
              if (cleaned.length > 2) { handleSendMessage(cleaned); resetSleepTimer(); }
            }
          };
          rec.onerror = (e: any) => { if (e.error !== "no-speech" && e.error !== "aborted") console.warn(e.error); };
          rec.onend = () => {
            if (!disposed && micEnabledRef.current && !isSpeakingRef.current) {
              setTimeout(() => { try { rec.start(); } catch(e){} }, 500);
            }
          };
          try { rec.start(); } catch(e){}
          recognitionRef.current = rec;
        }
        stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        audioCtx = new AudioContext(); audioCtxRef.current = audioCtx;
        analyser = audioCtx.createAnalyser();
        const source = audioCtx.createMediaStreamSource(stream);
        source.connect(analyser); analyser.fftSize = 512;
        const dataArray = new Uint8Array(analyser.frequencyBinCount);
        const detectClap = () => {
          if (!analyser || disposed) return;
          analyser.getByteFrequencyData(dataArray);
          let sum = 0; for (let i = 0; i < dataArray.length; i++) sum += dataArray[i];
          const avg = sum / dataArray.length;
          if (avg > 90 && aiStateRef.current === "sleeping" && !isSpeakingRef.current && aiEnabledRef.current) {
            const now = Date.now();
            if (clapStateRef.current.lastClap === 0) clapStateRef.current.lastClap = now;
            else if (now - clapStateRef.current.lastClap < 800) { wakeUpZangbeto(); clapStateRef.current.lastClap = 0; }
            else clapStateRef.current.lastClap = now;
          }
          animFrame = requestAnimationFrame(detectClap);
        };
        detectClap();
      } catch (err) { console.error(err); setMicEnabled(false); }
    };
    startListening();
    return () => {
      disposed = true;
      if (animFrame) cancelAnimationFrame(animFrame);
      if (audioCtx) audioCtx.close();
      if (stream) stream.getTracks().forEach(t => t.stop());
      if (recognitionRef.current) { try { recognitionRef.current.stop(); } catch(e){} }
    };
  }, [micEnabled]);

  const toggleMic = () => {
    if (micEnabled) {
      setMicEnabled(false); setAiState("sleeping");
      if (recognitionRef.current) { try { recognitionRef.current.stop(); } catch(e){} }
    } else {
      setMicEnabled(true);
      speakText("Voice activation online.");
    }
  };

  const handleSendMessage = async (overrideInput?: string) => {
    if (!aiEnabled) { termWrite("\x1b[33m[AI Disabled]\x1b[0m"); return; }
    const messageToSend = overrideInput || input;
    if (!messageToSend.trim()) return;
    const terminalContext = getTerminalContext();
    const contextualMessage = terminalContext ? `${messageToSend}\n\n[TERMINAL CONTEXT]\n${terminalContext.substring(0, 1000)}` : messageToSend;
    const newMessages = [...messages, { sender: "You", text: messageToSend }];
    setMessages(newMessages);
    setInput(""); setToolPrompt(null);
    try {
      const response = await apiFetch("http://localhost:8000/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: contextualMessage }),
      });
      const data = await response.json();
      setMessages([...newMessages, { sender: "Zangbeto", text: data.reply }]);
      speakText(data.reply);

      // Browser actions trigger a modal (they need special approval)
      const browserMatches = data.reply.match(/```browser\n([\s\S]*?)```/g);
      if (browserMatches && browserMatches.length > 0) {
        const actionStr = browserMatches[0].replace(/```browser\n?/, "").replace(/```$/, "").trim();
        requestBrowserAction(actionStr);
      }
      // Note: bash commands do NOT auto-trigger. User clicks "Sandbox" or "Live Terminal".
    } catch (error) {
      setMessages([...newMessages, { sender: "Zangbeto", text: "Error: Backend unreachable." }]);
    }
  };

  const useTool = (toolName: string) => {
    const prompts: Record<string, string> = {
      "Nmap": "Scan my local network for open ports using nmap",
      "Masscan": "Give me a masscan command to scan my local subnet",
      "Wireshark": "Capture 100 packets on my local interface using tshark",
      "Nuclei": "Give me a nuclei command to scan example.com for critical CVEs",
      "Subfinder": "Enumerate subdomains for example.com using subfinder",
      "WPScan": "Give me a wpscan command to check a WordPress site",
      "SQLmap": "Give me a sqlmap command to test a URL for SQL injection",
      "Metasploit": "Show me how to search Metasploit for MS17-010 exploits",
    };
    const prompt = prompts[toolName] || `Show me how to use ${toolName}`;
    setInput(prompt); setToolPrompt(prompt);
  };

  const requestExecution = (command: string) => {
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const domainPattern = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
    const ips = command.match(ipPattern) || [];
    const domains = (command.match(domainPattern) || []).filter(d => !d.includes("nmap.org"));
    setPendingCommand(command);
    setPendingTargets(Array.from(new Set([...ips, ...domains])));
  };

  const confirmExecution = async () => {
    if (!pendingCommand) return;
    const command = pendingCommand, targets = pendingTargets;
    setPendingCommand(null); setPendingTargets([]);
    setLastCommand(command);
    termWrite("");
    termWrite(`\x1b[1;36m▶ SANDBOX EXECUTION:\x1b[0m ${command}`);
    termWrite(`\x1b[33m  Targets: ${targets.length ? targets.join(", ") : "local operation"}\x1b[0m`);
    termWrite(`\x1b[90m  ─────────────────────────────────────────\x1b[0m`);
    setIsExecuting(true);
    try {
      const res = await apiFetch("http://localhost:8000/api/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command, authorization_confirmed: true }),
      });
      const data = await res.json();
      const output = data.output || data.reason || "Unknown response";
      output.split("\n").forEach((line: string) => termWrite(line));
      termWrite("");
      termWrite(`\x1b[1;32m✔ COMPLETE\x1b[0m (status: ${data.status})`);
      if (data.screenshot) termWrite(`\x1b[90m  [Screenshot: ${data.screenshot}]\x1b[0m`);
      termWrite("");
    } catch (error) {
      termWrite("\x1b[1;31m✘ Error: Backend unreachable.\x1b[0m");
    } finally {
      setIsExecuting(false);
    }
  };

  const cancelExecution = () => {
    setPendingCommand(null); setPendingTargets([]);
    termWrite("\x1b[33m⚠ Sandbox execution cancelled by Guardian.\x1b[0m");
  };

  const requestTerminalWrite = (command: string) => {
    setTerminalPendingCommand(command);
  };

  const confirmTerminalWrite = async () => {
    if (!terminalPendingCommand) return;
    const command = terminalPendingCommand;
    setTerminalPendingCommand(null);
    try {
      const res = await apiFetch("http://localhost:8000/api/terminal/write", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command, authorization_confirmed: true }),
      });
      const data = await res.json();
      if (data.status === "success") {
        setPanels(prev => ({ ...prev, terminal: true }));
      }
    } catch (e) { /* ignore */ }
  };

  const cancelTerminalWrite = () => {
    setTerminalPendingCommand(null);
  };

  const requestBrowserAction = (actionStr: string) => {
    setBrowserPendingAction(actionStr);
  };

  const confirmBrowserAction = async () => {
    if (!browserPendingAction) return;
    const parts = browserPendingAction.split(" ");
    const action = parts[0];
    const arg1 = parts[1] || "";
    const arg2 = parts.slice(2).join(" ") || "";
    setBrowserPendingAction(null);
    
    try {
      const res = await apiFetch("http://localhost:8000/api/browser/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, arg1, arg2, authorization_confirmed: true }),
      });
      const data = await res.json();
      if (data.status === "success") {
        setPanels(prev => ({ ...prev, ai: true }));
        termWrite(`\x1b[1;36m🌐 BROWSER ACTION:\x1b[0m ${browserPendingAction}`);
        data.output.split("\n").forEach((line: string) => termWrite(line));
        if (data.screenshot) {
          termWrite(`\x1b[90m  [Screenshot: ${data.screenshot}]\x1b[0m`);
        }
      } else {
        termWrite(`\x1b[1;31m✘ Browser Error: ${data.output || data.message}\x1b[0m`);
      }
    } catch (e) {
      termWrite("\x1b[1;31m✘ Browser connection failed.\x1b[0m");
    }
  };

  const cancelBrowserAction = () => {
    setBrowserPendingAction(null);
  };

  const handleGenerateReport = async () => {
    const fmt = prompt("Report format? (pdf / html / md / json)", "pdf");
    if (!fmt) return;
    try {
      const res = await apiFetch("http://localhost:8000/api/report/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ engagement_name: "Security Assessment", client_name: username, format: fmt.toLowerCase() })
      });
      const data = await res.json();
      if (data.status === "success") {
        alert(`✅ Report Generated!\n\nFile: ${data.filename}\nFindings: ${data.findings_count}\nScreenshots: ${data.screenshots_count}`);
        const token = localStorage.getItem("zangbeto_token") || "";
        window.open(`http://localhost:8000${data.download_url}?token=${token}`, "_blank");
      }
    } catch (err) { alert(`Error: ${err}`); }
  };

  const extractCommands = (text: string): string[] => {
    const regex = /```(?:bash|sh)?\s*\n?([\s\S]*?)```/g;
    const matches = [];
    let match;
    while ((match = regex.exec(text)) !== null) matches.push(match[1].trim());
    return matches;
  };

  const togglePanel = (key: "ai" | "terminal" | "browser") => {
    setPanels(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const expandPanel = (key: "ai" | "terminal" | "browser") => {
    if (key === "browser") window.open("http://localhost:7800", "_blank");
    else if (key === "terminal") window.open("http://localhost:7681", "_blank");
  };

  const killAI = async () => {
    const next = !aiEnabled;
    setAiEnabled(next);
    if (!next) {
      window.speechSynthesis.cancel();
      setAiState("sleeping");
      termWrite("\x1b[1;31m⛔ AI KILL SWITCH ENGAGED\x1b[0m");
      termWrite("\x1b[90m   Terminal and Browser remain operational\x1b[0m");
      
      try {
        await apiFetch("http://localhost:8000/api/terminal/system-notify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: "⛔ AI KILL SWITCH ENGAGED", color: "red" }),
        });
      } catch (e) { /* ignore */ }
    } else {
      termWrite("\x1b[1;32m✔ AI re-enabled\x1b[0m");
      try {
        await apiFetch("http://localhost:8000/api/terminal/system-notify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: "✔ AI re-enabled", color: "green" }),
        });
      } catch (e) { /* ignore */ }
    }
  };

  const tools = [
    { section: "Blue Team (Defense)", color: "text-blue-400", items: [
      "Wireshark", "TShark", "Suricata", "Zeek", "ClamAV", "YARA",
      "Lynis", "AIDE", "Auditd", "Fail2ban", "UFW", "rkhunter",
      "chkrootkit", "tcpdump", "tcpflow", "netsniff-ng", "ngrep",
      "Sleuthkit", "Binwalk", "Foremost", "ExifTool"
    ]},
    { section: "Red Team (Authorized)", color: "text-red-400", items: [
      "Nmap", "Masscan", "ARP-scan", "Netdiscover", "Nikto", "SQLmap",
      "Dirb", "Gobuster", "Wfuzz", "FFuf", "Hydra", "John the Ripper",
      "Metasploit", "ExploitDB", "Aircrack-ng", "Reaver", "SNMP",
      "SMBClient", "LDAP-utils", "Hping3", "Searchsploit"
    ]},
    { section: "Bug Bounty", color: "text-purple-400", items: [
      "Nuclei", "Subfinder", "HTTPX", "Katana", "DNSX", "Naabu",
      "Dalfox", "Waybackurls", "Assetfinder", "Httprobe", "Gau",
      "WPScan", "TestSSL", "Amass"
    ]},
    { section: "Python / Forensics", color: "text-yellow-400", items: [
      "Impacket", "Scapy", "Pwntools", "Volatility3", "Cryptography",
      "YARA-Python", "DNSPython"
    ]},
  ];

  const activePanels: Array<"ai" | "terminal" | "browser"> = [];
  if (panels.ai) activePanels.push("ai");
  if (panels.terminal) activePanels.push("terminal");
  if (panels.browser) activePanels.push("browser");

  return (
    <div className="h-screen w-screen bg-zinc-950 text-zinc-300 flex flex-col overflow-hidden font-sans">
      <header className="h-12 border-b border-zinc-800 flex items-center px-4 justify-between bg-zinc-900 flex-shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-green-500" />
          <span className="font-bold text-white tracking-wider">ZANGBETO ORCHESTRATOR</span>
          <span className="text-xs text-zinc-500 ml-2">[{username}]</span>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <span className="flex items-center gap-1 mr-2">
            {aiState === "sleeping" ? (
              <><Moon className="w-3 h-3 text-zinc-500" /><span className="text-zinc-500 text-xs">Sleeping</span></>
            ) : (
              <><Eye className="w-3 h-3 text-green-400" /><span className="text-green-400 text-xs">Awake</span></>
            )}
          </span>
          <button onClick={toggleMic}
            className={`px-3 py-1.5 text-white text-xs font-semibold rounded transition-all ${micEnabled ? 'bg-red-600 hover:bg-red-500' : 'bg-zinc-700 hover:bg-zinc-600'}`}>
            {micEnabled ? '🎤 Mic' : '🔇 Mic'}
          </button>
          <button onClick={() => setSpeakEnabled(!speakEnabled)}
            className={`px-3 py-1.5 text-white text-xs font-semibold rounded transition-all ${speakEnabled ? 'bg-green-700 hover:bg-green-600' : 'bg-zinc-700 hover:bg-zinc-600'}`}>
            {speakEnabled ? '🔊 Speak' : '🔇 Mute'}
          </button>
          <button onClick={killAI}
            className={`px-3 py-1.5 text-white text-xs font-semibold rounded transition-all ${aiEnabled ? 'bg-orange-600 hover:bg-orange-500' : 'bg-red-700 animate-pulse'}`}>
            {aiEnabled ? '⏸️ AI' : '⛔ KILLED'}
          </button>
          <button onClick={() => window.location.href = "/status"}
            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded transition-all">
            💊 Health
          </button>
          <button onClick={handleGenerateReport}
            className="px-3 py-1.5 bg-green-600 hover:bg-green-500 text-white text-xs font-semibold rounded transition-all">
            📄 Report
          </button>
          <button onClick={handleLogout}
            className="px-2 py-1.5 bg-zinc-800 hover:bg-red-700 text-zinc-400 hover:text-white text-xs rounded transition-all"
            title="Logout">
            <LogOut className="w-4 h-4" />
          </button>
          <Settings className="w-4 h-4 cursor-pointer hover:text-white ml-1" />
        </div>
      </header>

      <PanelGroup direction="horizontal" className="flex-1">
        <Panel defaultSize={18} minSize={12} className="bg-zinc-900 border-r border-zinc-800 flex flex-col">
          <div className="p-3 border-b border-zinc-800 flex items-center gap-2 text-sm font-semibold text-zinc-400">
            <Folder className="w-4 h-4" /> TOOLS & TARGETS
          </div>
          <div className="flex-1 overflow-auto p-2">
            {tools.map((group) => (
              <div key={group.section} className="mb-3">
                <p className="text-xs text-zinc-500 mb-1 uppercase tracking-wider flex items-center justify-between px-2">
                  <span>{group.section}</span>
                  <span className="text-zinc-600">{group.items.length}</span>
                </p>
                <ul className="space-y-0.5">
                  {group.items.map((item) => (
                    <li key={item} onClick={() => useTool(item)}
                      className="flex items-center gap-2 px-2 py-1 hover:bg-zinc-800 rounded cursor-pointer transition-colors text-xs">
                      <Cpu className={`w-3 h-3 ${group.color}`} />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <div className="p-2 border-t border-zinc-800 text-xs text-zinc-500">
            Click a tool to auto-fill
          </div>
        </Panel>

        <PanelResizeHandle className="w-1 bg-zinc-800 hover:bg-blue-500 transition-colors" />

        <Panel defaultSize={52} minSize={30} className="flex flex-col bg-zinc-950">
          <div className="h-10 border-b border-zinc-800 flex items-center px-2 bg-zinc-900 gap-1 flex-shrink-0">
            <button onClick={() => togglePanel("ai")}
              className={`px-3 py-1.5 text-xs font-semibold rounded transition-all ${panels.ai ? "bg-green-600 text-white" : "text-zinc-400 hover:text-white hover:bg-zinc-800"}`}>
              🤖 AI
            </button>
            <button onClick={() => togglePanel("terminal")}
              className={`px-3 py-1.5 text-xs font-semibold rounded transition-all ${panels.terminal ? "bg-purple-600 text-white" : "text-zinc-400 hover:text-white hover:bg-zinc-800"}`}>
              ⌨️ Terminal
            </button>
            <button onClick={() => togglePanel("browser")}
              className={`px-3 py-1.5 text-xs font-semibold rounded transition-all ${panels.browser ? "bg-blue-600 text-white" : "text-zinc-400 hover:text-white hover:bg-zinc-800"}`}>
              🖥️ Browser
            </button>
            <div className="flex-1" />
            {activePanels.length > 0 && (
              <div className="flex items-center gap-1">
                {activePanels.map((key) => (
                  <button key={key} onClick={() => expandPanel(key)}
                    className="px-2 py-1 text-xs text-zinc-400 hover:text-white hover:bg-zinc-800 rounded flex items-center gap-1"
                    title={`Expand ${key}`}>
                    <Maximize2 className="w-3 h-3" />
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="flex-1 overflow-hidden">
            {activePanels.length === 0 ? (
              <div className="h-full flex items-center justify-center text-zinc-600 text-sm">
                Select a panel above: AI, Terminal, or Browser
              </div>
            ) : (
              <PanelGroup direction="vertical" className="h-full">
                {activePanels.map((key, idx) => (
                  <Fragment key={key}>
                    <Panel defaultSize={100 / activePanels.length} minSize={15} className="flex flex-col bg-zinc-950">
                      {key === "ai" && (
                        <PanelGroup direction="vertical" className="h-full">
                          <Panel defaultSize={40} className="flex flex-col border-b border-zinc-800">
                            <div className="h-7 border-b border-zinc-800 flex items-center px-3 bg-zinc-900 text-xs text-zinc-400 gap-2">
                              <FileCode className="w-3 h-3" /> attack_plan.yaml
                            </div>
                            <div className="flex-1 p-3 font-mono text-sm text-green-300 overflow-auto">
                              <p className="text-zinc-500"># Zangbeto AI Generated Command</p>
                              {lastCommand ? (
                                <p className="text-white mt-2 whitespace-pre-wrap">$ {lastCommand}</p>
                              ) : (
                                <p className="text-zinc-500 mt-2"># Awaiting command from AI...</p>
                              )}
                            </div>
                          </Panel>
                          <PanelResizeHandle className="h-1 bg-zinc-800 hover:bg-blue-500 transition-colors" />
                          <Panel defaultSize={60} className="bg-black flex flex-col">
                            <div className="h-7 border-b border-zinc-800 flex items-center justify-between px-3 bg-zinc-900 text-xs text-zinc-400">
                              <div className="flex items-center gap-2">
                                <TerminalIcon className="w-3 h-3" /> AI Output Stream
                              </div>
                              <span className={isExecuting ? "text-orange-400 animate-pulse" : "text-green-400"}>
                                {isExecuting ? "● Executing" : "● Ready"}
                              </span>
                            </div>
                            <div ref={terminalContainerRef} className="flex-1 overflow-hidden" />
                          </Panel>
                        </PanelGroup>
                      )}
                      {key === "terminal" && (
                        <div className="h-full flex flex-col">
                          <div className="h-7 border-b border-zinc-800 flex items-center px-3 bg-zinc-900 text-xs text-zinc-400 gap-2">
                            <TerminalIcon className="w-3 h-3" /> Kali Linux Terminal (shared with AI)
                          </div>
                          <iframe src="http://localhost:7681" className="flex-1 w-full border-0 bg-black" title="Kali Terminal" />
                        </div>
                      )}
                      {key === "browser" && (
                        <div className="h-full flex flex-col">
                          <div className="h-7 border-b border-zinc-800 flex items-center px-3 bg-zinc-900 text-xs text-zinc-400 gap-2">
                            🖥️ Chromium Browser (VPS-like)
                          </div>
                          <iframe src="http://localhost:7800" className="flex-1 w-full border-0 bg-black" title="Chromium Browser" />
                        </div>
                      )}
                    </Panel>
                    {idx < activePanels.length - 1 && (
                      <PanelResizeHandle className="h-1 bg-zinc-800 hover:bg-blue-500 transition-colors" />
                    )}
                  </Fragment>
                ))}
              </PanelGroup>
            )}
          </div>
        </Panel>

        <PanelResizeHandle className="w-1 bg-zinc-800 hover:bg-blue-500 transition-colors" />

        <Panel defaultSize={30} minSize={20} className="bg-zinc-900 border-l border-zinc-800 flex flex-col">
          <div className="p-3 border-b border-zinc-800 flex items-center gap-2 text-sm font-semibold text-zinc-400">
            <Bot className="w-4 h-4" /> ZANGBETO AI
          </div>

          <div className="flex-1 p-4 overflow-auto flex flex-col gap-4 text-sm">
            {messages.map((msg, index) => {
              const commands = msg.sender === "Zangbeto" ? extractCommands(msg.text) : [];
              const browserActions = msg.sender === "Zangbeto" ? (msg.text.match(/```browser\n([\s\S]*?)```/g) || []) : [];
              return (
                <div key={index} className={`p-3 rounded-lg max-w-[95%] ${msg.sender === "You" ? "bg-blue-900/50 self-end rounded-tr-none" : "bg-zinc-800 self-start rounded-tl-none"}`}>
                  <p className={`font-bold mb-1 ${msg.sender === "You" ? "text-blue-400" : "text-green-400"}`}>{msg.sender}:</p>
                  <p className="whitespace-pre-wrap">{msg.text}</p>

                  {/* EVERY bash command shows BOTH buttons — user chooses */}
                  {commands.map((cmd, cmdIndex) => (
                    <div key={`cmd-${cmdIndex}`} className="mt-3 flex flex-col gap-2 bg-zinc-900/70 border border-zinc-700 rounded-lg p-3">
                      <p className="text-xs text-zinc-500 uppercase tracking-wider font-semibold">Choose Execution Environment:</p>
                      <div className="flex gap-2">
                        <button onClick={() => requestExecution(cmd)} disabled={isExecuting}
                          className="flex-1 flex items-center justify-center gap-2 bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white text-xs font-semibold px-3 py-2 rounded transition-all"
                          title="Isolated Docker container — safe, disposable">
                          <Play className="w-3 h-3" /> Run in Sandbox
                        </button>
                        <button onClick={() => requestTerminalWrite(cmd)}
                          className="flex-1 flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold px-3 py-2 rounded transition-all"
                          title="Live shared tmux session — you watch in real time">
                          <TerminalIcon className="w-3 h-3" /> Run in Live Terminal
                        </button>
                      </div>
                    </div>
                  ))}

                  {/* Browser actions */}
                  {browserActions.map((act, actIndex) => {
                    const actionStr = act.replace(/```browser\n?/, "").replace(/```$/, "").trim();
                    return (
                      <button key={`br-${actIndex}`} onClick={() => requestBrowserAction(actionStr)}
                        className="mt-2 flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold px-3 py-1.5 rounded transition-all">
                        <Globe className="w-3 h-3" /> Approve & Control Browser
                      </button>
                    );
                  })}
                </div>
              );
            })}
            <div ref={messagesEndRef} />
          </div>

          <div className="p-3 border-t border-zinc-800 bg-zinc-950 flex items-center gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
              placeholder={!aiEnabled ? "AI Disabled — enable to chat" : (toolPrompt ? "Tool prompt loaded" : "Ask Zangbeto for guidance...")}
              disabled={!aiEnabled}
              className={`flex-1 bg-zinc-900 border rounded px-3 py-2 text-sm text-white focus:outline-none disabled:opacity-50 ${toolPrompt ? 'border-blue-500' : 'border-zinc-700 focus:border-green-500'}`}
            />
            <button onClick={() => handleSendMessage()} disabled={!aiEnabled}
              className="p-2 hover:bg-zinc-800 rounded-full text-zinc-500 hover:text-white transition-all disabled:opacity-50">
              <Send className="w-5 h-5" />
            </button>
          </div>
        </Panel>
      </PanelGroup>

      {/* IDLE WARNING MODAL */}
      {showIdleWarning && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 backdrop-blur-sm">
          <div className="bg-zinc-900 border-2 border-orange-600 rounded-lg p-6 max-w-md w-full mx-4 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="w-8 h-8 text-orange-500" />
              <div>
                <h2 className="text-lg font-bold text-white">Session Timeout Warning</h2>
                <p className="text-xs text-zinc-400">Security policy: 15 minutes idle</p>
              </div>
            </div>
            <p className="text-sm text-zinc-300 mb-4">
              You will be logged out in <span className="font-bold text-orange-400 text-2xl">{idleSecondsLeft}</span> seconds due to inactivity.
            </p>
            <p className="text-xs text-zinc-500 mb-4">All actions are logged in the audit chain.</p>
            <button onClick={continueSession}
              className="w-full bg-orange-600 hover:bg-orange-500 text-white font-semibold py-2.5 rounded transition-all">
              Continue Session
            </button>
          </div>
        </div>
      )}

      {/* SANDBOX AUTHORIZATION MODAL */}
      {pendingCommand && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 backdrop-blur-sm">
          <div className="bg-zinc-900 border-2 border-green-600 rounded-lg p-6 max-w-xl w-full mx-4 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <Play className="w-8 h-8 text-green-500" />
              <div>
                <h2 className="text-lg font-bold text-white">Sandbox Execution Authorization</h2>
                <p className="text-xs text-zinc-400">Scope Gate — Legal Confirmation Required</p>
              </div>
            </div>

            <div className="bg-green-950/30 border border-green-800/50 rounded p-3 mb-3">
              <p className="text-xs text-green-200 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" /> Environment: <strong>ISOLATED SANDBOX</strong>
              </p>
              <p className="text-xs text-green-300 mt-1">Disposable Docker container — no impact on your system or network.</p>
            </div>

            <div className="bg-zinc-950 border border-zinc-800 rounded p-3 mb-4 font-mono text-sm">
              <p className="text-green-400 mb-2">$ {pendingCommand}</p>
              <p className="text-zinc-500 text-xs mb-1">Detected targets:</p>
              <p className="text-yellow-400 text-xs">
                {pendingTargets.length > 0 ? pendingTargets.join(", ") : "local operation (no external targets)"}
              </p>
            </div>

            <div className="bg-yellow-950/30 border border-yellow-800/50 rounded p-3 mb-4">
              <p className="text-xs text-yellow-200 font-semibold mb-2">By authorizing this execution:</p>
              <ul className="text-xs text-yellow-200 space-y-1 list-disc list-inside">
                <li>You own these systems <strong>OR</strong> hold written authorization</li>
                <li>This action is written to the tamper-evident audit chain</li>
                <li>You accept full legal responsibility for this operation</li>
              </ul>
            </div>

            <div className="flex gap-3">
              <button onClick={cancelExecution}
                className="flex-1 bg-zinc-800 hover:bg-zinc-700 text-white font-semibold py-2.5 rounded transition-all">
                Cancel
              </button>
              <button onClick={confirmExecution}
                className="flex-1 bg-green-600 hover:bg-green-500 text-white font-semibold py-2.5 rounded transition-all">
                Authorize &amp; Execute in Sandbox
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TERMINAL AUTHORIZATION MODAL */}
      {terminalPendingCommand && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 backdrop-blur-sm">
          <div className="bg-zinc-900 border-2 border-purple-600 rounded-lg p-6 max-w-xl w-full mx-4 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <TerminalIcon className="w-8 h-8 text-purple-500" />
              <div>
                <h2 className="text-lg font-bold text-white">Live Terminal Authorization</h2>
                <p className="text-xs text-zinc-400">Zangbeto will type into your shared Kali session</p>
              </div>
            </div>

            <div className="bg-purple-950/30 border border-purple-800/50 rounded p-3 mb-3">
              <p className="text-xs text-purple-200 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" /> Environment: <strong>LIVE SHARED TERMINAL (tmux)</strong>
              </p>
              <p className="text-xs text-purple-300 mt-1">You will see the command execute live in the Terminal tab.</p>
            </div>

            <div className="bg-zinc-950 border border-zinc-800 rounded p-3 mb-4 font-mono text-sm">
              <p className="text-purple-400 mb-2">$ {terminalPendingCommand}</p>
              <p className="text-zinc-500 text-xs">This command will appear in your Kali terminal immediately.</p>
            </div>

            <div className="flex gap-3">
              <button onClick={cancelTerminalWrite}
                className="flex-1 bg-zinc-800 hover:bg-zinc-700 text-white font-semibold py-2.5 rounded transition-all">
                Deny
              </button>
              <button onClick={confirmTerminalWrite}
                className="flex-1 bg-purple-600 hover:bg-purple-500 text-white font-semibold py-2.5 rounded transition-all">
                Allow AI to Type
              </button>
            </div>
          </div>
        </div>
      )}

      {/* BROWSER AUTHORIZATION MODAL */}
      {browserPendingAction && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 backdrop-blur-sm">
          <div className="bg-zinc-900 border-2 border-blue-600 rounded-lg p-6 max-w-xl w-full mx-4 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <Globe className="w-8 h-8 text-blue-500" />
              <div>
                <h2 className="text-lg font-bold text-white">Browser Automation Authorization</h2>
                <p className="text-xs text-zinc-400">Zangbeto will control a headless Chromium instance</p>
              </div>
            </div>

            <div className="bg-blue-950/30 border border-blue-800/50 rounded p-3 mb-3">
              <p className="text-xs text-blue-200 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" /> Environment: <strong>HEADLESS CHROMIUM (Playwright)</strong>
              </p>
              <p className="text-xs text-blue-300 mt-1">Screenshots and output will be returned to the dashboard.</p>
            </div>

            <div className="bg-zinc-950 border border-zinc-800 rounded p-3 mb-4 font-mono text-sm">
              <p className="text-blue-400 mb-2">$ {browserPendingAction}</p>
              <p className="text-zinc-500 text-xs">This action will execute in the isolated browser container.</p>
            </div>

            <div className="flex gap-3">
              <button onClick={cancelBrowserAction}
                className="flex-1 bg-zinc-800 hover:bg-zinc-700 text-white font-semibold py-2.5 rounded transition-all">
                Deny
              </button>
              <button onClick={confirmBrowserAction}
                className="flex-1 bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded transition-all">
                Allow Browser Action
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}