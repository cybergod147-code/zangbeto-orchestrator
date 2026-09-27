"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem("zangbeto_token");
    if (token) {
      router.push("/dashboard");
    } else {
      router.push("/security-gate");
    }
  }, [router]);

  return (
    <div className="min-h-screen bg-black flex items-center justify-center">
      <div className="text-green-400 font-mono animate-pulse">
        Authenticating Zangbeto...
      </div>
    </div>
  );
}