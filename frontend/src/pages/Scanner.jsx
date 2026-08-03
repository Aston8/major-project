import React, { useState } from 'react';
import axios from 'axios';
import { RiskMeter } from '../components/RiskMeter';
import { ProtectionBadge } from '../components/ProtectionBadge';

const CpuIcon = () => (
  <svg className="w-5 h-5 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
  </svg>
);

const formatExplanation = (text) => {
  if (!text) return '';
  const verdictRegex = /^(Final Risk Engine VERDICT:\s*\[.*?\]\s*\(Score:\s*\d+(?:\.\d+)?\)\.?)(.*)$/i;
  const match = text.match(verdictRegex);
  if (match) {
    return (
      <div className="flex flex-col gap-3">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 w-fit text-2xs font-mono uppercase tracking-wider text-indigo-300">
          <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse"></span>
          {match[1]}
        </div>
        <p className="text-xs text-gray-300 leading-relaxed font-light">{match[2].trim()}</p>
      </div>
    );
  }
  return <p className="text-xs text-gray-300 leading-relaxed font-light">{text}</p>;
};

export const Scanner = () => {
  const [activeTab, setActiveTab] = useState('text');
  
  // Scanning States
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState('');
  const [result, setResult] = useState(null);
  const [bulkResult, setBulkResult] = useState(null);
  const [error, setError] = useState('');

  // Form Inputs
  const [textContent, setTextContent] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [imageFile, setImageFile] = useState(null);
  const [voiceFile, setVoiceFile] = useState(null);
  
  // Bulk Classifier Inputs
  const [bulkTextContent, setBulkTextContent] = useState('');

  // Sandbox progress visualizer
  const simulateSandboxProgress = () => {
    const steps = [
      "Running WHOIS domain registration age checks...",
      "Querying VirusTotal, OpenPhish & PhishTank threat databases...",
      "Initializing Docker container instance (smartshield-sandbox:latest)...",
      "Launching Playwright Chromium browser inside container...",
      "Navigating safely to target URL & tracking HTTP redirects...",
      "Monitoring page DOM for credential forms, popups, and click triggers...",
      "Capturing full-page visual screenshot & HTML snapshot...",
      "Orchestrating Risk Fusion Engine & Generating visual-based threat reports...",
      "Tearing down isolated Docker sandbox container..."
    ];

    let i = 0;
    setScanProgress(steps[0]);
    const interval = setInterval(() => {
      i++;
      if (i < steps.length) {
        setScanProgress(steps[i]);
      } else {
        clearInterval(interval);
      }
    }, 2500);
    return interval;
  };

  const handleTextScan = async (e) => {
    e.preventDefault();
    setScanning(true);
    setResult(null);
    setBulkResult(null);
    setError('');

    let progressTimer;
    if (textContent.includes('http') || textContent.includes('.com') || textContent.includes('.org')) {
      progressTimer = simulateSandboxProgress();
    } else {
      setScanProgress("Analyzing text semantics via deep learning models...");
    }

    try {
      const res = await axios.post('/api/scans/text', {
        content: textContent,
        source_type: 'SMS'
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Scan failed. Please verify API connections.");
    } finally {
      if (progressTimer) clearInterval(progressTimer);
      setScanning(false);
    }
  };

  const handleUrlScan = async (e) => {
    e.preventDefault();
    setScanning(true);
    setResult(null);
    setBulkResult(null);
    setError('');

    const progressTimer = simulateSandboxProgress();

    try {
      const res = await axios.post('/api/scans/url', {
        url: urlInput
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Sandbox execution failed. Check container logs.");
    } finally {
      clearInterval(progressTimer);
      setScanning(false);
    }
  };

  const handleImageScan = async (e) => {
    e.preventDefault();
    if (!imageFile) return;
    setScanning(true);
    setResult(null);
    setBulkResult(null);
    setError('');
    
    let progressTimer;
    // Check if the filename hints that it might contain links for progress simulation
    const filename = imageFile.name.toLowerCase();
    if (filename.includes('qr') || filename.includes('link') || filename.includes('url')) {
      progressTimer = simulateSandboxProgress();
    } else {
      setScanProgress("Extracting image content using EasyOCR & verifying text...");
    }

    const formData = new FormData();
    formData.append('file', imageFile);

    try {
      const res = await axios.post('/api/scans/image', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Image upload scan failed.");
    } finally {
      if (progressTimer) clearInterval(progressTimer);
      setScanning(false);
    }
  };

  const handleVoiceScan = async (e) => {
    e.preventDefault();
    if (!voiceFile) return;
    setScanning(true);
    setResult(null);
    setBulkResult(null);
    setError('');
    setScanProgress("Transcribing audio dialogue via neural speech recognition...");

    const formData = new FormData();
    formData.append('file', voiceFile);

    try {
      const res = await axios.post('/api/scans/voice', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Audio upload transcription failed.");
    } finally {
      setScanning(false);
    }
  };

  const handleBulkScan = async (e) => {
    e.preventDefault();
    if (!bulkTextContent.trim()) return;
    setScanning(true);
    setResult(null);
    setBulkResult(null);
    setError('');
    setScanProgress("Analyzing multiple messages concurrently...");

    // Split text into messages by newlines (ignoring empty lines)
    const messagesList = bulkTextContent.split('\n').map(m => m.trim()).filter(m => m.length > 0);
    
    try {
      const res = await axios.post('/api/scans/bulk', {
        messages: messagesList
      });
      setBulkResult(res.data.results);
    } catch (err) {
      setError(err.response?.data?.detail || "Bulk classification failed.");
    } finally {
      setScanning(false);
    }
  };

  const resetAll = () => {
    setResult(null);
    setBulkResult(null);
    setTextContent('');
    setUrlInput('');
    setImageFile(null);
    setVoiceFile(null);
    setBulkTextContent('');
    setError('');
  };

  const downloadReport = async (scanId) => {
    try {
      const response = await axios.get(`/api/scans/report/${scanId}`, {
        responseType: 'blob'
      });
      const file = new Blob([response.data], { type: 'application/pdf' });
      const fileURL = URL.createObjectURL(file);
      const link = document.createElement('a');
      link.href = fileURL;
      link.setAttribute('download', `SmartShield_Report_${scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert("Failed to download PDF report.");
    }
  };

  return (
    <div className="p-6 flex flex-col gap-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">Diagnostic Scanner</h1>
        <p className="text-xs text-gray-400 mt-1">Select an input page, submit assets, and audit real-time sandbox verdicts</p>
      </div>

      {/* Tabs */}
      {!scanning && !result && !bulkResult && (
        <div className="flex border-b border-gray-800 gap-2 overflow-x-auto">
          {[
            { id: 'text', label: 'Message Texts / SMS' },
            { id: 'url', label: 'URL Sandbox' },
            { id: 'image', label: 'Image Screenshot OCR' },
            { id: 'voice', label: 'Voice Audio' },
            { id: 'bulk', label: 'Bulk Text Classifier' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id);
                setError('');
              }}
              className={`px-4 py-3 text-xs font-semibold uppercase tracking-wider border-b-2 transition whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-400 font-bold'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      )}

      {/* Input Panels */}
      {!scanning && !result && !bulkResult && (
        <div className="glass-card p-6 rounded-2xl border border-white/5">
          {activeTab === 'text' && (
            <form onSubmit={handleTextScan} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Message Content</label>
                <textarea
                  value={textContent}
                  onChange={(e) => setTextContent(e.target.value)}
                  required
                  rows="4"
                  placeholder="Paste the SMS, WhatsApp, or Telegram message text here..."
                  className="w-full px-4 py-3 rounded-xl bg-cyber-bg border border-gray-800 text-sm text-gray-200 focus:outline-none focus:border-indigo-500/50 transition resize-none"
                />
              </div>
              <button
                type="submit"
                className="py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end"
              >
                Trigger AI Threat Scan
              </button>
            </form>
          )}

          {activeTab === 'url' && (
            <form onSubmit={handleUrlScan} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Webpage URL Target</label>
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  required
                  placeholder="e.g. secure-verification-bank-login.com"
                  className="w-full px-4 py-3 rounded-xl bg-cyber-bg border border-gray-800 text-sm text-gray-200 focus:outline-none focus:border-indigo-500/50 transition"
                />
              </div>
              <button
                type="submit"
                className="py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end"
              >
                Launch Containerized Sandbox
              </button>
            </form>
          )}

          {activeTab === 'image' && (
            <form onSubmit={handleImageScan} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Screenshot Upload</label>
                <div className="border-2 border-dashed border-gray-800 rounded-2xl p-8 text-center hover:border-indigo-500/40 transition cursor-pointer relative bg-cyber-bg/30">
                  <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => setImageFile(e.target.files[0])}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  />
                  <span className="text-xs font-semibold text-gray-300">
                    {imageFile ? imageFile.name : 'Select or drop warning notice screenshot / payment screenshot'}
                  </span>
                </div>
              </div>
              <button
                type="submit"
                disabled={!imageFile}
                className="py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end disabled:opacity-50"
              >
                Extract & Verify Image
              </button>
            </form>
          )}

          {activeTab === 'voice' && (
            <form onSubmit={handleVoiceScan} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Audio Recording (Call/Voice Message)</label>
                <div className="border-2 border-dashed border-gray-800 rounded-2xl p-8 text-center hover:border-indigo-500/40 transition cursor-pointer relative bg-cyber-bg/30">
                  <input
                    type="file"
                    accept="audio/*"
                    onChange={(e) => setVoiceFile(e.target.files[0])}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  />
                  <span className="text-xs font-semibold text-gray-300">
                    {voiceFile ? voiceFile.name : 'Select or drop voice call recordings / MP3 file'}
                  </span>
                </div>
              </div>
              <button
                type="submit"
                disabled={!voiceFile}
                className="py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end disabled:opacity-50"
              >
                Transcribe & Scan Voice
              </button>
            </form>
          )}

          {activeTab === 'bulk' && (
            <form onSubmit={handleBulkScan} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Bulk Messages (Enter each message on a new line)</label>
                <textarea
                  value={bulkTextContent}
                  onChange={(e) => setBulkTextContent(e.target.value)}
                  required
                  rows="8"
                  placeholder="Example:&#10;Congratulations! You won 5 Lakhs reward. Claim at http://lottery-draw.in&#10;Hi mom, I lost my phone, WhatsApp me on this number&#10;Hey are you coming to the party tonight?"
                  className="w-full px-4 py-3 rounded-xl bg-cyber-bg border border-gray-800 text-sm text-gray-200 focus:outline-none focus:border-indigo-500/50 transition font-mono resize-none"
                />
              </div>
              <button
                type="submit"
                disabled={!bulkTextContent.trim()}
                className="py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end disabled:opacity-50"
              >
                Classify Messages List
              </button>
            </form>
          )}
        </div>
      )}

      {/* Progress Loader Overlay */}
      {scanning && (
        <div className="glass-card p-12 rounded-2xl border border-white/5 text-center flex flex-col items-center justify-center gap-6 shadow-2xl">
          <div className="relative w-16 h-16">
            <span className="absolute inset-0 border-4 border-indigo-500/20 border-t-indigo-400 rounded-full animate-spin"></span>
            <span className="absolute inset-2 border-4 border-cyan-500/20 border-t-cyan-400 rounded-full animate-spin" style={{ animationDirection: 'reverse' }}></span>
          </div>
          <div className="flex flex-col gap-1 max-w-md">
            <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider">SmartShield Threat Assessment Live</h3>
            <p className="text-xs text-indigo-400 pulse-cyber font-medium min-h-[16px]">{scanProgress}</p>
          </div>
        </div>
      )}

      {/* Result View */}
      {result && (
        <div className="flex flex-col gap-6">
          <div className="flex justify-between items-center bg-gray-900/30 p-4 border border-gray-800 rounded-xl">
            <span className="text-2xs font-semibold text-gray-500 uppercase tracking-wider">Diagnostic ID: {result._id}</span>
            <div className="flex gap-2">
              <button
                onClick={() => downloadReport(result._id)}
                className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 hover:shadow-lg hover:shadow-indigo-500/25 active:scale-95 text-white font-semibold text-xs tracking-wide transition flex items-center gap-1.5"
              >
                <span>Download Report</span>
              </button>
              <button
                onClick={resetAll}
                className="px-4 py-2 rounded-lg border border-gray-800 text-gray-400 hover:text-white hover:border-gray-600 hover:bg-gray-800/20 active:scale-95 transition text-xs font-semibold"
              >
                New Scan
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
            <div className="lg:col-span-1">
              <RiskMeter
                score={result.fusion_result.final_score}
                category={result.fusion_result.category}
              />
            </div>

            <div className="lg:col-span-2 flex flex-col gap-4">
              <div className={`p-6 rounded-2xl border transition-all duration-300 ${
                result.fusion_result.category === 'Dangerous' || result.fusion_result.category === 'Suspicious' || result.fusion_result.category === 'Scam'
                  ? 'bg-red-500/10 border-red-500/20 text-red-300 glow-danger'
                  : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300 glow-success'
              }`}>
                <h3 className="font-extrabold text-sm uppercase tracking-wider mb-2">Verdict Outcome</h3>
                <p className="text-2xl font-bold">
                  {result.fusion_result.category === 'Dangerous' || result.fusion_result.category === 'Suspicious' || result.fusion_result.category === 'Scam'
                    ? '⚠️ SCAM DETECTED'
                    : '✅ LEGITIMATE / SAFE'}
                </p>
              </div>

              <div className="glass-card p-6 rounded-2xl border border-white/5 flex flex-col gap-4 relative overflow-hidden hover:border-indigo-500/30 transition-all duration-300">
                <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 rounded-full blur-3xl -z-10"></div>
                
                <div className="flex items-center gap-2.5 border-b border-white/5 pb-3">
                  <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/20">
                    <CpuIcon />
                  </div>
                  <div>
                    <h3 className="font-extrabold text-sm text-gray-100 uppercase tracking-wider">AI Verdict & Mechanical Analysis</h3>
                  </div>
                </div>

                <div className="pl-1">
                  {formatExplanation(result.fusion_result.explanation)}
                </div>
              </div>
            </div>
          </div>

          {/* Verification Logs */}
          {(result.qwen_result || result.type === 'voice') && (
            <div className="glass-card p-6 rounded-2xl border border-white/5">
              <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider mb-6">AI Verification Audits</h3>
              <div className={`grid grid-cols-1 ${result.qwen_result && result.type === 'voice' ? 'md:grid-cols-2' : ''} gap-6`}>
                {result.qwen_result && (
                  <div className="p-4 bg-gray-900/20 border border-gray-800 rounded-xl flex flex-col gap-2">
                    <span className="text-2xs font-bold text-gray-400 uppercase tracking-widest font-semibold">AI Vision & Content Analysis</span>
                    <span className="text-xl font-extrabold text-indigo-400">{result.qwen_result.score} <span className="text-xs text-gray-500 font-normal">/ 100</span></span>
                    <p className="text-2xs text-gray-400 mt-2 font-light leading-relaxed">{result.qwen_result.explanation}</p>
                  </div>
                )}

                {result.type === 'voice' && (
                  <div className="p-4 bg-gray-900/20 border border-gray-800 rounded-xl flex flex-col gap-2">
                    <span className="text-2xs font-bold text-gray-400 uppercase tracking-widest font-semibold">Speech-to-Text Analysis</span>
                    {result.input_data?.transcript ? (
                      <>
                        <span className="text-xs text-emerald-400 font-bold">Transcription Complete</span>
                        <p className="text-2xs text-gray-400 mt-1 font-light leading-normal italic">"{result.input_data.transcript}"</p>
                      </>
                    ) : (
                      <span className="text-xs text-gray-500">No transcript available</span>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Sandbox Logs details if sandbox executed */}
          {result.sandbox_report && (
            <div className="glass-card p-6 rounded-2xl border border-white/5 flex flex-col gap-6">
              <div className="border-b border-gray-800 pb-4">
                <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider">Isolated Sandbox Browser Findings</h3>
                <p className="text-3xs text-gray-500 mt-1">Playwright execution inside container</p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {result.sandbox_report.screenshot_url && (
                  <div className="lg:col-span-1 flex flex-col gap-2">
                    <span className="text-2xs font-bold uppercase tracking-widest text-gray-400">Sandbox Screenshot</span>
                    <div className="border border-gray-800 rounded-xl overflow-hidden shadow-lg aspect-video flex items-center justify-center bg-black/40 relative group transition-all duration-300 hover:scale-[1.02] hover:shadow-xl hover:shadow-cyan-500/10">
                      <img
                        src={result.sandbox_report.screenshot_url}
                        alt="Sandbox browser preview"
                        className="w-full h-full object-cover"
                        onError={(e) => {
                          e.target.style.display = 'none';
                        }}
                      />
                      <a
                        href={result.sandbox_report.screenshot_url}
                        target="_blank"
                        rel="noreferrer"
                        className="absolute inset-0 bg-black/60 flex items-center justify-center opacity-0 group-hover:opacity-100 transition duration-300 text-xs font-semibold text-white"
                      >
                        Open Full Screenshot
                      </a>
                    </div>
                  </div>
                )}

                <div className="lg:col-span-2 flex flex-col gap-4">
                  <div className="flex flex-col gap-2">
                    <span className="text-2xs font-bold uppercase tracking-widest text-gray-400">Dynamic Behavior Detections</span>
                    <div className="flex flex-col gap-1.5 max-h-40 overflow-y-auto border border-gray-800 p-3 rounded-xl bg-cyber-bg/40">
                      {result.sandbox_report.behavior_findings.length > 0 ? (
                        result.sandbox_report.behavior_findings.map((finding, idx) => (
                          <div key={idx} className="flex gap-2 text-2xs text-rose-400 items-start font-light leading-normal">
                            <span className="text-rose-500 font-bold shrink-0">[!]</span>
                            <span>{finding}</span>
                          </div>
                        ))
                      ) : (
                        <span className="text-xs text-gray-500">No dynamic behavioral threats flagged in the browser sandbox.</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Bulk Results View */}
      {bulkResult && (
        <div className="flex flex-col gap-6">
          <div className="flex justify-between items-center bg-gray-900/30 p-4 border border-gray-800 rounded-xl">
            <span className="text-2xs font-semibold text-gray-500 uppercase tracking-wider">Bulk Classification Complete</span>
            <button
              onClick={resetAll}
              className="px-4 py-2 rounded-lg border border-gray-800 text-gray-400 hover:text-white hover:border-gray-700 transition text-xs font-semibold"
            >
              New Bulk Scan
            </button>
          </div>

          <div className="glass-card p-6 rounded-2xl border border-white/5 flex flex-col gap-4">
            <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider mb-2">Classified Bulk Messages</h3>
            <div className="flex flex-col gap-4">
              {bulkResult.map((res, index) => (
                <div key={index} className="p-4 bg-gray-950/40 border border-gray-800 rounded-xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                  <div className="flex-1 flex flex-col gap-1">
                    <p className="text-xs text-gray-400 font-mono italic">"{res.message}"</p>
                    <p className="text-3xs text-gray-500 font-light mt-1">{res.explanation}</p>
                  </div>
                  <div className="shrink-0 flex items-center gap-3">
                    <span className="text-xs font-bold text-gray-400">{res.score} / 100</span>
                    <ProtectionBadge category={res.category} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
