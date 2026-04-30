import { useState, useEffect, useRef } from "react";
import axios from "axios";
import jsPDF from "jspdf";
import html2canvas from "html2canvas";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

function App() {
  // =======================
  // CORE STATE (PHASE 10)
  // =======================
  const [cve, setCve] = useState("");
  const [result, setResult] = useState(null);

  // =======================
  // AUTH (PHASE 11C)
  // =======================
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState("");

  // =======================
  // PDF REF
  // =======================
  const reportRef = useRef();

  // =======================
  // MULTI CVE (11D)
  // =======================
  const [cveList, setCveList] = useState([]);
  const [compareInput, setCompareInput] = useState("");
  const [compareResult, setCompareResult] = useState([]);

  // =======================
  // THREAT ACTOR (11E)
  // =======================
  const [threatActor, setThreatActor] = useState(null);

  // =======================
  // HISTORY (11F)
  // =======================
  const [history, setHistory] = useState([]);

  // =======================
  // LIVE FEED (11G)
  // =======================
  const [feed, setFeed] = useState([]);

  // =======================
  // AUTO LOGIN
  // =======================
  useEffect(() => {
    const saved = localStorage.getItem("sentryiq_user");
    if (saved) {
      setUsername(saved);
      setIsLoggedIn(true);
    }
  }, []);

  // =======================
  // LIVE CVE FEED
  // =======================
  useEffect(() => {
    if (!isLoggedIn) return;

    const interval = setInterval(() => {
      const fakeCVE = `CVE-2024-${Math.floor(Math.random() * 9999)}`;

      setFeed((prev) => [
        {
          cve: fakeCVE,
          severity: ["LOW", "MEDIUM", "HIGH", "CRITICAL"][
            Math.floor(Math.random() * 4)
          ],
          time: new Date().toLocaleTimeString(),
        },
        ...prev.slice(0, 6),
      ]);
    }, 5000);

    return () => clearInterval(interval);
  }, [isLoggedIn]);

  // =======================
  // LOGIN
  // =======================
  const handleLogin = () => {
    if (!username) return;
    localStorage.setItem("sentryiq_user", username);
    setIsLoggedIn(true);
  };

  const handleLogout = () => {
    localStorage.removeItem("sentryiq_user");
    setIsLoggedIn(false);
    setUsername("");
    setResult(null);
    setCve("");
  };

  // =======================
  // CVE ANALYSIS
  // =======================
  const analyzeCVE = async () => {
    try {
      const response = await axios.post("http://127.0.0.1:8000/analyze", {
        cve,
      });

      setResult(response.data);

      setHistory((prev) => [
        {
          cve,
          time: new Date().toLocaleTimeString(),
          risk: response.data.risk_score,
        },
        ...prev,
      ]);
    } catch (error) {
      console.error(error);
    }
  };

  // =======================
  // PDF EXPORT (11A)
  // =======================
  const downloadPDF = async () => {
    const input = reportRef.current;
    const canvas = await html2canvas(input, { scale: 2 });
    const imgData = canvas.toDataURL("image/png");

    const pdf = new jsPDF("p", "mm", "a4");
    const width = pdf.internal.pageSize.getWidth();
    const height = (canvas.height * width) / canvas.width;

    pdf.addImage(imgData, "PNG", 0, 0, width, height);
    pdf.save(`${cve || "incident"}.pdf`);
  };

  // =======================
  // JSON EXPORT (11B)
  // =======================
  const downloadJSON = () => {
    const report = {
      cve,
      result,
      timestamp: new Date().toISOString(),
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${cve || "incident"}.json`;
    a.click();
  };

  // =======================
  // MULTI CVE (11D)
  // =======================
  const addCVEToCompare = () => {
    if (!compareInput) return;
    setCveList([...cveList, compareInput]);
    setCompareInput("");
  };

  const compareCVEs = async () => {
    const results = await Promise.all(
      cveList.map(async (item) => {
        const res = await axios.post("http://127.0.0.1:8000/analyze", {
          cve: item,
        });
        return { cve: item, ...res.data };
      })
    );

    setCompareResult(results);
  };

  // =======================
  // THREAT ACTOR (11E)
  // =======================
  const lookupThreatActor = () => {
    const actors = ["APT29", "Lazarus Group", "FIN7", "Anonymous Sudan"];

    setThreatActor({
      name: actors[Math.floor(Math.random() * actors.length)],
      motivation: "Espionage / Financial Gain",
      activity: "Exploiting CVEs for lateral movement",
    });
  };

  // =======================
  // CHART DATA
  // =======================
  const severityData = [
    { name: "Critical", value: result?.risk_level === "CRITICAL" ? 1 : 0 },
    { name: "High", value: result?.risk_level === "HIGH" ? 1 : 0 },
    { name: "Medium", value: result?.risk_level === "MEDIUM" ? 1 : 0 },
    { name: "Low", value: result?.risk_level === "LOW" ? 1 : 0 },
  ];

  const cvssTrendData = [
    { name: "CVSS", score: result?.cvss || 0 },
    { name: "Risk", score: result?.risk_score || 0 },
  ];

  const COLORS = ["#ef4444", "#f97316", "#facc15", "#22c55e"];

  // =======================
  // LOGIN SCREEN
  // =======================
  if (!isLoggedIn) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#F3F8FF]">
        <div className="bg-white p-8 rounded-xl shadow-md w-96 border border-blue-100">
          <h1 className="text-2xl font-bold text-blue-700 mb-6">
            SentryIQ Analyst Login
          </h1>

          <input
            className="w-full p-3 border border-blue-200 rounded-lg mb-4"
            placeholder="Enter Analyst Name"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />

          <button
            onClick={handleLogin}
            className="w-full bg-blue-600 text-white py-3 rounded-lg"
          >
            Access Dashboard
          </button>
        </div>
      </div>
    );
  }

  // =======================
  // DASHBOARD
  // =======================
  return (
    <div className="min-h-screen bg-[#F3F8FF] text-gray-900 p-10 space-y-6">

      {/* HEADER */}
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-blue-700">
          SentryIQ Security Dashboard
        </h1>

        <div className="flex gap-3 items-center">
          <span className="text-sm">
            Analyst: <b>{username}</b>
          </span>

          <button
            onClick={handleLogout}
            className="bg-red-500 px-4 py-2 rounded-lg text-white"
          >
            Logout
          </button>
        </div>
      </div>

      {/* INPUT */}
      <div className="flex gap-3">
        <input
          className="p-3 w-96 border rounded-lg"
          placeholder="Enter CVE"
          value={cve}
          onChange={(e) => setCve(e.target.value)}
        />

        <button onClick={analyzeCVE} className="bg-blue-600 text-white px-5 rounded-lg">
          Analyze
        </button>

        <button onClick={downloadPDF} className="bg-green-600 text-white px-5 rounded-lg">
          PDF
        </button>

        <button onClick={downloadJSON} className="bg-purple-600 text-white px-5 rounded-lg">
          JSON
        </button>
      </div>

      {/* REPORT AREA */}
      <div ref={reportRef} className="space-y-6">

        {/* PHASE 10 CHARTS */}
        {result && (
          <>
            <div className="grid grid-cols-2 gap-6">

              <div className="bg-white p-5 rounded-xl">
                <h2>Severity Distribution</h2>
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie data={severityData} dataKey="value" outerRadius={90}>
                      {severityData.map((_, i) => (
                        <Cell key={i} fill={COLORS[i]} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-white p-5 rounded-xl">
                <h2>Risk Score</h2>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={cvssTrendData}>
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="score" fill="#0ea5e9" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

            </div>

            {/* LIVE FEED */}
            <div className="bg-white p-5 rounded-xl">
              <h2>Live CVE Feed</h2>
              {feed.map((f, i) => (
                <div key={i} className="flex justify-between border-b py-2">
                  <span>{f.cve}</span>
                  <span>{f.severity}</span>
                  <span>{f.time}</span>
                </div>
              ))}
            </div>

            {/* THREAT ACTOR */}
            <div className="bg-white p-5 rounded-xl">
              <h2>Threat Actor Intelligence</h2>
              <button onClick={lookupThreatActor} className="bg-purple-600 text-white px-3 py-2 rounded">
                Lookup
              </button>

              {threatActor && (
                <div>
                  <p>{threatActor.name}</p>
                  <p>{threatActor.motivation}</p>
                </div>
              )}
            </div>

            {/* HISTORY */}
            <div className="bg-white p-5 rounded-xl">
              <h2>CVE History</h2>
              {history.map((h, i) => (
                <div key={i}>
                  {h.cve} - {h.risk}
                </div>
              ))}
            </div>

          </>
        )}
      </div>

      {/* MULTI CVE */}
      <div className="bg-white p-5 rounded-xl">
        <h2>Multi-CVE Comparison</h2>

        <div className="flex gap-2">
          <input
            value={compareInput}
            onChange={(e) => setCompareInput(e.target.value)}
            className="border p-2"
          />
          <button onClick={addCVEToCompare}>Add</button>
          <button onClick={compareCVEs}>Compare</button>
        </div>

        {compareResult.map((r, i) => (
          <div key={i}>
            {r.cve} - {r.risk_score}
          </div>
        ))}
      </div>

    </div>
  );
}

export default App;