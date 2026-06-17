import React, { useState } from 'react';
import axios from 'axios';
import { RiskMeter } from '../components/RiskMeter';
import { ProtectionBadge } from '../components/ProtectionBadge';

export const Scanner = () => {
  const [activeTab, setActiveTab] = useState('text');
  
  // Scanning States
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  // Form Inputs
  const [textContent, setTextContent] = useState('');
  const [textSource, setTextSource] = useState('SMS');
  const [urlInput, setUrlInput] = useState('');
  
  const [imageFile, setImageFile] = useState(null);
  const [voiceFile, setVoiceFile] = useState(null);
  
  const [emailContent, setEmailContent] = useState('');
  const [emailSender, setEmailSender] = useState('');
  const [emailHeaders, setEmailHeaders] = useState('');

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
      "Orchestrating Risk Fusion Engine & Generating Gemini Vision reports...",
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
    }, 2800);
    return interval;
  };

  const handleTextScan = async (e) => {
    e.preventDefault();
    setScanning(true);
    setResult(null);
    setError('');
    setScanProgress("Analyzing message semantics via Local ML...");
    
    try {
      const res = await axios.post('/api/scans/text', {
        content: textContent,
        source_type: textSource
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Scan failed. Please verify API connections.");
    } finally {
      setScanning(false);
    }
  };

  const handleUrlScan = async (e) => {
    e.preventDefault();
    setScanning(true);
    setResult(null);
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
    setError('');
    setScanProgress("Extracting image content using EasyOCR & searching QR codes...");

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
      setScanning(false);
    }
  };

  const handleVoiceScan = async (e) => {
    e.preventDefault();
    if (!voiceFile) return;
    setScanning(true);
    setResult(null);
    setError('');
    setScanProgress("Transcribing audio dialogue via Whisper ASR models...");

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

  const handleEmailScan = async (e) => {
    e.preventDefault();
    setScanning(true);
    setResult(null);
    setError('');
    setScanProgress("Validating SPF/DKIM headers and assessing content...");

    try {
      const res = await axios.post('/api/scans/email', {
        content: emailContent,
        sender_email: emailSender,
        headers: emailHeaders
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Email verification failed.");
    } finally {
      setScanning(false);
    }
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
      alert("Failed to download PDF report. Confirm file storage permissions.");
    }
  };

  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">Diagnostic Scanner</h1>
        <p className="text-xs text-gray-400 mt-1">Select an input channel, submit assets, and audit real-time sandbox verdicts</p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-800 gap-2 overflow-x-auto">
        {[
          { id: 'text', label: 'Message Texts / SMS' },
          { id: 'url', label: 'URL Sandbox Analyzer' },
          { id: 'image', label: 'Image Screenshot OCR & QR' },
          { id: 'voice', label: 'Voice Audio Whisper' },
          { id: 'email', label: 'Email Header & SPF' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => {
              setActiveTab(tab.id);
              setResult(null);
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

      {/* Input Panels */}
      {!scanning && !result && (
        <div className="glass-card p-6 rounded-2xl border border-white/5">
          {activeTab === 'text' && (
            <form onSubmit={handleTextScan} className="flex flex-col gap-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex flex-col gap-1.5 md:col-span-2">
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
                <div className="flex flex-col gap-1.5">
                  <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Message Source</label>
                  <select
                    value={textSource}
                    onChange={(e) => setTextSource(e.target.value)}
                    className="w-full px-4 py-3 rounded-xl bg-cyber-bg border border-gray-800 text-sm text-gray-200 focus:outline-none focus:border-indigo-500/50 transition"
                  >
                    <option value="SMS">SMS Message</option>
                    <option value="WhatsApp">WhatsApp Message</option>
                    <option value="Telegram">Telegram Message</option>
                    <option value="Social Media">Social Media Message</option>
                  </select>
                </div>
              </div>
              <button
                type="submit"
                className="mt-2 py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end flex items-center gap-2"
              >
                <span>Trigger AI Threat Scan</span>
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
              <div className="p-4 bg-indigo-950/10 border border-indigo-900/20 rounded-xl text-2xs text-gray-400 leading-relaxed">
                <span className="font-bold text-indigo-400">Safe Sandboxing Mode:</span> This scanner triggers a temporary, isolated Docker container executing Google Playwright. The browser visits the URL, captures visual layouts, collects logs, checks downloads, and destroys the container instantly to avoid executing malicious scripts on host.
              </div>
              <button
                type="submit"
                className="py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end flex items-center gap-2"
              >
                <span>Launch Containerized Sandbox</span>
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
                  <div className="flex flex-col items-center gap-2">
                    <svg className="w-10 h-10 text-gray-500" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z"></path>
                    </svg>
                    <span className="text-xs font-semibold text-gray-300">
                      {imageFile ? imageFile.name : 'Select or drop warning notice screenshot / payment screenshot'}
                    </span>
                    <span className="text-3xs text-gray-500">Supports PNG, JPG, JPEG up to 5MB</span>
                  </div>
                </div>
              </div>
              <button
                type="submit"
                disabled={!imageFile}
                className="py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end flex items-center gap-2 disabled:opacity-50"
              >
                <span>Extract & Verify Image</span>
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
                  <div className="flex flex-col items-center gap-2">
                    <svg className="w-10 h-10 text-gray-500" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19.114 5.636a9 9 0 010 12.728M16.463 8.288a5.25 5.25 0 010 7.424M6.75 8.25l4.72-4.72a.75.75 0 011.28.53v15.88a.75.75 0 01-1.28.53l-4.72-4.72H4.51c-.88 0-1.704-.507-1.938-1.354A9.01 9.01 0 012.25 12c0-.83.112-1.633.322-2.396C2.806 8.756 3.63 8.25 4.51 8.25H6.75z"></path>
                    </svg>
                    <span className="text-xs font-semibold text-gray-300">
                      {voiceFile ? voiceFile.name : 'Select or drop voice calling recordings / MP3 file'}
                    </span>
                    <span className="text-3xs text-gray-500">Supports MP3, WAV, M4A up to 10MB</span>
                  </div>
                </div>
              </div>
              <button
                type="submit"
                disabled={!voiceFile}
                className="py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end flex items-center gap-2 disabled:opacity-50"
              >
                <span>Transcribe & Scan Voice</span>
              </button>
            </form>
          )}

          {activeTab === 'email' && (
            <form onSubmit={handleEmailScan} className="flex flex-col gap-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex flex-col gap-1.5 md:col-span-2">
                  <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Email Body Message</label>
                  <textarea
                    value={emailContent}
                    onChange={(e) => setEmailContent(e.target.value)}
                    required
                    rows="6"
                    placeholder="Paste the email body content here..."
                    className="w-full px-4 py-3 rounded-xl bg-cyber-bg border border-gray-800 text-sm text-gray-200 focus:outline-none focus:border-indigo-500/50 transition resize-none"
                  />
                </div>
                <div className="flex flex-col gap-4">
                  <div className="flex flex-col gap-1.5">
                    <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">Sender Domain / Email</label>
                    <input
                      type="text"
                      value={emailSender}
                      onChange={(e) => setEmailSender(e.target.value)}
                      required
                      placeholder="e.g. notifications@paypal.com"
                      className="w-full px-4 py-3 rounded-xl bg-cyber-bg border border-gray-800 text-sm text-gray-200 focus:outline-none focus:border-indigo-500/50 transition"
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label className="text-2xs font-bold uppercase tracking-wider text-gray-400">SMTP Headers (Optional)</label>
                    <textarea
                      value={emailHeaders}
                      onChange={(e) => setEmailHeaders(e.target.value)}
                      rows="3"
                      placeholder="Paste header fields like 'Received', 'DKIM-Signature' for SPF verification checks..."
                      className="w-full px-4 py-2 rounded-xl bg-cyber-bg border border-gray-800 text-xs text-gray-200 focus:outline-none focus:border-indigo-500/50 transition resize-none"
                    />
                  </div>
                </div>
              </div>
              <button
                type="submit"
                className="py-3 px-6 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm tracking-wide transition self-end flex items-center gap-2"
              >
                <span>Audit Email Integrity</span>
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

      {/* Results View */}
      {result && (
        <div className="flex flex-col gap-6">
          <div className="flex justify-between items-center bg-gray-900/30 p-4 border border-gray-800 rounded-xl">
            <span className="text-2xs font-semibold text-gray-500 uppercase tracking-wider">Diagnostic ID: {result._id}</span>
            <div className="flex gap-2">
              <button
                onClick={() => downloadReport(result._id)}
                className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs tracking-wide transition flex items-center gap-1.5"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"></path>
                </svg>
                <span>Download PDF Report</span>
              </button>
              <button
                onClick={() => setResult(null)}
                className="px-4 py-2 rounded-lg border border-gray-800 text-gray-400 hover:text-white hover:border-gray-700 transition text-xs font-semibold"
              >
                New Scan
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
            {/* Risk dial */}
            <div className="lg:col-span-1">
              <RiskMeter
                score={result.fusion_result.final_score}
                category={result.fusion_result.category}
              />
            </div>

            {/* Explanations & Recs */}
            <div className="lg:col-span-2 flex flex-col gap-6">
              {/* Risk Fusion explanation box */}
              <div className="glass-card p-6 rounded-2xl border border-white/5 bg-gradient-to-b from-gray-800/10 to-transparent">
                <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider mb-3">AI Verdict & Mechanical Analysis</h3>
                <p className="text-xs text-gray-300 leading-relaxed font-light">{result.fusion_result.explanation}</p>
              </div>

              {/* Recommendations Box */}
              <div className="glass-card p-6 rounded-2xl border border-white/5">
                <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider mb-3">Safety Actions & Directives</h3>
                <ul className="flex flex-col gap-2">
                  {result.fusion_result.recommendations.map((rec, index) => (
                    <li key={index} className="flex gap-2 text-xs text-gray-300 items-start font-light">
                      <svg className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"></path>
                      </svg>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Engine Multi-Model check verification logs */}
          <div className="glass-card p-6 rounded-2xl border border-white/5">
            <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider mb-6">Multi-Model Verification Audits</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="p-4 bg-gray-900/20 border border-gray-800 rounded-xl flex flex-col gap-2">
                <span className="text-2xs font-bold text-gray-400 uppercase tracking-widest">Local ML Model (DistilBERT)</span>
                {result.local_ml_result ? (
                  <>
                    <span className="text-xl font-extrabold text-white">{result.local_ml_result.score} <span className="text-xs text-gray-500 font-normal">/ 100</span></span>
                    <p className="text-2xs text-gray-400 mt-2 font-light leading-relaxed">{result.local_ml_result.explanation}</p>
                  </>
                ) : (
                  <span className="text-xs text-gray-500">Not assessed</span>
                )}
              </div>

              <div className="p-4 bg-gray-900/20 border border-gray-800 rounded-xl flex flex-col gap-2">
                <span className="text-2xs font-bold text-gray-400 uppercase tracking-widest font-semibold">Primary AI (Google Gemini)</span>
                {result.gemini_result ? (
                  <>
                    <span className="text-xl font-extrabold text-indigo-400">{result.gemini_result.score} <span className="text-xs text-gray-500 font-normal">/ 100</span></span>
                    <p className="text-2xs text-gray-400 mt-2 font-light leading-relaxed">{result.gemini_result.explanation}</p>
                  </>
                ) : (
                  <span className="text-xs text-gray-500">Not assessed</span>
                )}
              </div>

              <div className="p-4 bg-gray-900/20 border border-gray-800 rounded-xl flex flex-col gap-2">
                <span className="text-2xs font-bold text-gray-400 uppercase tracking-widest font-semibold">Secondary AI Verification (Grok)</span>
                {result.grok_result ? (
                  <>
                    <span className="text-xl font-extrabold text-cyan-400">{result.grok_result.score} <span className="text-xs text-gray-500 font-normal">/ 100</span></span>
                    <p className="text-2xs text-gray-400 mt-2 font-light leading-relaxed">{result.grok_result.explanation}</p>
                  </>
                ) : (
                  <span className="text-xs text-gray-500">Not assessed</span>
                )}
              </div>
            </div>
          </div>

          {/* Sandbox Logs details if type URL */}
          {result.type === 'url' && result.sandbox_report && (
            <div className="glass-card p-6 rounded-2xl border border-white/5 flex flex-col gap-6">
              <div className="border-b border-gray-800 pb-4">
                <h3 className="font-extrabold text-sm text-gray-200 uppercase tracking-wider">Isolated Sandbox Browser Findings</h3>
                <p className="text-3xs text-gray-500 mt-1">Playwright execution inside container</p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Screenshot layout */}
                {result.sandbox_report.screenshot_url && (
                  <div className="lg:col-span-1 flex flex-col gap-2">
                    <span className="text-2xs font-bold uppercase tracking-widest text-gray-400">Sandbox Screenshot</span>
                    <div className="border border-gray-800 rounded-xl overflow-hidden shadow-lg aspect-video flex items-center justify-center bg-black/40 relative group">
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
                    {result.sandbox_report.ai_vision_analysis && (
                      <div className="p-3 bg-indigo-950/20 border border-indigo-900/30 rounded-xl mt-2">
                        <span className="text-3xs font-bold uppercase text-indigo-400 tracking-wider">Gemini Vision Check</span>
                        <p className="text-3xs text-gray-400 mt-1 font-light leading-relaxed">{result.sandbox_report.ai_vision_analysis.explanation}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Network & Form findings */}
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

                  <div className="flex flex-col gap-2">
                    <span className="text-2xs font-bold uppercase tracking-widest text-gray-400">HTTP Redirect Chain</span>
                    <div className="flex flex-col gap-1 border border-gray-800 p-3 rounded-xl bg-cyber-bg/40 font-mono text-3xs max-h-32 overflow-y-auto text-gray-400">
                      {result.url_metadata?.redirect_chain.map((url, idx) => (
                        <div key={idx} className="flex gap-2 items-center">
                          <span className="text-gray-600 font-semibold">{idx + 1}.</span>
                          <span className="truncate">{url}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
