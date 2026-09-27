import React, { useState, useRef, useEffect } from 'react';
import { 
  FileText, 
  Image as ImageIcon, 
  Mic, 
  Globe, 
  Layers, 
  ArrowRight, 
  Upload, 
  Play, 
  Pause, 
  ShieldAlert, 
  Sparkles, 
  Check, 
  RefreshCw,
  Plus,
  Lock,
  AlertTriangle,
  Activity,
  RotateCw,
  Terminal,
  ExternalLink,
  ShieldCheck
} from 'lucide-react';
import AnalysisModeCard from '../components/AnalysisModeCard';
import AnalysisProgress from '../components/AnalysisProgress';
import ThreatBadge from '../components/ThreatBadge';
import ThreatScore from '../components/ThreatScore';
import RevealScamPanel from '../components/RevealScamPanel';
import ScamDNA from '../components/ScamDNA';
import SandboxBrowser from '../components/SandboxBrowser';
import investigationService from '../services/investigationService';

export const Investigate = ({ onSaveNewInvestigation }) => {
  const [selectedMode, setSelectedMode] = useState('text');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [activeTab, setActiveTab] = useState('result');

  // Input states (clean, no fake prefilled data)
  const [textInput, setTextInput] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [isPlayingAudio, setIsPlayingAudio] = useState(false);
  const [isRecording, setIsRecording] = useState(false);
  const [recordingTime, setRecordingTime] = useState(0);

  // Live Website Sandbox state
  const [sandboxUrlInput, setSandboxUrlInput] = useState("");
  const [activeSandboxUrl, setActiveSandboxUrl] = useState("");
  const [sandboxIframeKey, setSandboxIframeKey] = useState(Date.now());
  const [loadingSandboxPage, setLoadingSandboxPage] = useState(false);
  const [sandboxPageInfo, setSandboxPageInfo] = useState({
    title: '',
    pageText: '',
    passInputs: 0,
    formsCount: 0,
    linksCount: 0,
    scriptsCount: 0
  });
  const [sandboxEvents, setSandboxEvents] = useState([]);
  const [showSandboxFullText, setShowSandboxFullText] = useState(false);

  // Auto-scroll refs
  const progressSectionRef = useRef(null);
  const resultSectionRef = useRef(null);

  // Listen to postMessage events from live proxy iframe
  useEffect(() => {
    const handleMessage = (event) => {
      if (event.data && event.data.source === 'SMARTSHIELD_SANDBOX') {
        const { eventType, payload } = event.data;
        const timestamp = new Date().toLocaleTimeString();

        const newEvt = {
          id: Date.now() + Math.random(),
          timestamp,
          eventType,
          payload
        };

        setSandboxEvents((prev) => [newEvt, ...prev]);

        if (eventType === 'PAGE_LOADED' && payload) {
          setLoadingSandboxPage(false);
          setSandboxPageInfo({
            title: payload.title || 'Target Page',
            pageText: payload.pageText || '',
            passInputs: payload.passInputs || 0,
            formsCount: payload.formsCount || 0,
            linksCount: payload.linksCount || 0,
            scriptsCount: payload.scriptsCount || 0
          });
        }
      }
    };

    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [activeSandboxUrl]);

  const handleNavigateSandbox = (target) => {
    let formatted = (target || '').trim();
    if (!formatted) return;
    if (!formatted.startsWith('http://') && !formatted.startsWith('https://')) {
      formatted = 'https://' + formatted;
    }
    setSandboxUrlInput(formatted);
    setActiveSandboxUrl(formatted);
    setUrlInput(formatted);
    setSandboxIframeKey(Date.now());
    setLoadingSandboxPage(true);
    setSandboxEvents([]);
    setSandboxPageInfo({
      title: 'Connecting & Loading DOM...',
      pageText: '',
      passInputs: 0,
      formsCount: 0,
      linksCount: 0,
      scriptsCount: 0
    });
    setAnalysisResult(null);
    setScanError(null);
  };

  // Microphone recording refs
  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);
  const recordingTimerRef = useRef(null);

  // Synchronization refs for async API responses
  const pendingResultRef = useRef(null);
  const pendingInvestigationRef = useRef(null);
  const apiCompletedRef = useRef(false);
  const progressCompletedRef = useRef(false);

  // Multimodal items state (supports Text, Image, Audio/Voice together)
  const [multiText, setMultiText] = useState("");
  const [multiImageFile, setMultiImageFile] = useState(null);
  const [multiAudioFile, setMultiAudioFile] = useState(null);
  const [isMultiRecording, setIsMultiRecording] = useState(false);
  const [multiRecordingTime, setMultiRecordingTime] = useState(0);

  // Multimodal mic recorder refs
  const multiMediaRecorderRef = useRef(null);
  const multiAudioChunksRef = useRef([]);
  const multiRecordingTimerRef = useRef(null);

  const handleStartMultiMicRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      multiAudioChunksRef.current = [];
      const mediaRecorder = new MediaRecorder(stream);
      multiMediaRecorderRef.current = mediaRecorder;

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          multiAudioChunksRef.current.push(event.data);
        }
      };

      mediaRecorder.onstop = () => {
        const audioBlob = new Blob(multiAudioChunksRef.current, { type: 'audio/webm' });
        const recordedAudioFile = new File([audioBlob], `multimodal_voice_evidence_${Date.now()}.webm`, { type: 'audio/webm' });
        setMultiAudioFile(recordedAudioFile);
        stream.getTracks().forEach(track => track.stop());
      };

      mediaRecorder.start();
      setIsMultiRecording(true);
      setMultiRecordingTime(0);

      multiRecordingTimerRef.current = setInterval(() => {
        setMultiRecordingTime((prev) => prev + 1);
      }, 1000);
    } catch (err) {
      console.error("Microphone access denied or not available:", err);
      alert("Unable to access microphone. Please grant permission in your browser.");
    }
  };

  const handleStopMultiMicRecording = () => {
    if (multiMediaRecorderRef.current && multiMediaRecorderRef.current.state !== 'inactive') {
      multiMediaRecorderRef.current.stop();
    }
    setIsMultiRecording(false);
    if (multiRecordingTimerRef.current) {
      clearInterval(multiRecordingTimerRef.current);
    }
  };

  const handleStartRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      audioChunksRef.current = [];
      const mediaRecorder = new MediaRecorder(stream);
      mediaRecorderRef.current = mediaRecorder;

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          audioChunksRef.current.push(event.data);
        }
      };

      mediaRecorder.onstop = () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        const recordedFile = new File([audioBlob], `voice_evidence_${Date.now()}.webm`, { type: 'audio/webm' });
        setSelectedFile(recordedFile);
        stream.getTracks().forEach(track => track.stop());
      };

      mediaRecorder.start();
      setIsRecording(true);
      setRecordingTime(0);

      recordingTimerRef.current = setInterval(() => {
        setRecordingTime((prev) => prev + 1);
      }, 1000);
    } catch (err) {
      console.error("Microphone access denied or not available:", err);
      alert("Unable to access microphone. Please ensure microphone permissions are granted.");
    }
  };

  const handleStopRecording = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
    }
    setIsRecording(false);
    if (recordingTimerRef.current) {
      clearInterval(recordingTimerRef.current);
    }
  };

  const handleModeChange = (mode) => {
    setSelectedMode(mode);
    setAnalysisResult(null);
    setScanError(null);
    setSelectedFile(null);
    if (isRecording) handleStopRecording();
    if (isMultiRecording) handleStopMultiMicRecording();
  };

  const parseBackendScanResponse = (data, mode, inputs = {}) => {
    if (!data) return null;

    const fusion = data.fusion_result || {};
    const qwen = data.qwen_result || {};
    const sandbox = data.sandbox_report || {};
    const inputData = data.input_data || {};

    const isInconclusive = fusion.category === "Inconclusive" || 
                           fusion.category === "Insufficient Evidence" || 
                           qwen.category === "Inconclusive" || 
                           qwen.category === "Insufficient Evidence";

    const rawScore = fusion.final_score ?? qwen.score ?? null;
    const score = isInconclusive ? null : (rawScore !== null ? Math.round(rawScore) : null);

    const rawCategory = qwen.category || fusion.category || "Threat Scan";
    const scamType = isInconclusive 
      ? "Insufficient Evidence" 
      : (rawCategory === "Safe" ? "Legitimate / Verified Safe" : rawCategory);

    let threatLevel = "SAFE";
    if (isInconclusive) {
      threatLevel = "INCONCLUSIVE";
    } else if (fusion.category === "Dangerous" || (score !== null && score >= 75)) {
      threatLevel = "CRITICAL";
    } else if (fusion.category === "Suspicious" || (score !== null && score >= 40)) {
      threatLevel = "HIGH";
    } else if (score !== null && score >= 20) {
      threatLevel = "SUSPICIOUS";
    } else {
      threatLevel = "SAFE";
    }

    const rawText = inputData.content || inputData.text || inputData.extracted_text || inputData.transcript || inputs.textInput || "";
    const rawUrl = inputData.url || inputData.url_content || inputData.detected_url || sandbox.url || inputs.urlInput || "";
    const keywords = qwen.highlighted_keywords || [];
    const explanation = fusion.explanation || qwen.explanation || (isInconclusive ? "Not enough behavioral evidence was collected to classify this target." : "Analysis complete.");
    const recommendations = fusion.recommendations || [];

    const tacticBreakdown = fusion.tactic_breakdown || qwen.tactic_breakdown || null;
    const dnaSignals = fusion.dna_signals || qwen.dna_signals || null;

    let highlights = fusion.tactic_highlights || qwen.tactic_highlights || [];
    if (!highlights || highlights.length === 0) {
      if (keywords.length > 0) {
        highlights = keywords.map(kw => ({
          phrase: kw,
          tactic: "RISK INDICATOR DETECTED",
          description: `Flagged phrase "${kw}" as suspicious indicator associated with ${scamType}.`,
          severity: (score || 50) >= 70 ? "CRITICAL" : "HIGH"
        }));
      }
    }

    const sandboxData = {
      url: rawUrl || inputs.urlInput || "",
      status: sandbox.sandbox_verdict || (threatLevel === "CRITICAL" ? "CONTAINED" : (isInconclusive ? "INCONCLUSIVE" : "CLEARED")),
      redirects: sandbox.redirect_chain?.length || (rawUrl ? 1 : 0),
      networkRequests: sandbox.network_requests?.length || (rawUrl ? 8 : 0),
      formsDetected: sandbox.detected_forms?.length || 0,
      scriptsExecuted: sandbox.scripts_count || 0,
      suspiciousActions: sandbox.behavior_findings?.length || 0,
      behaviorFindings: sandbox.behavior_findings || []
    };

    const result = {
      id: data._id,
      score,
      threatLevel,
      scamType,
      explanation,
      recommendations,
      tacticBreakdown,
      dnaSignals,
      originalText: rawText,
      transcript: inputData.transcript || rawText,
      sandboxData,
      highlights
    };

    const investigation = {
      id: data._id ? (String(data._id).length > 8 ? `SC-${String(data._id).slice(-4).toUpperCase()}` : String(data._id)) : `SC-${Date.now()}`,
      title: `${scamType}`,
      type: mode,
      threatLevel,
      score: score ?? 0,
      timestamp: data.created_at || new Date().toISOString(),
      timeAgo: "Just now",
      vector: mode === 'multimodal' ? "MULTIMODAL" : `${mode.toUpperCase()} Vector`,
      evidenceTypes: [mode],
      summary: explanation,
      originalContent: {
        text: rawText,
        url: rawUrl,
        imageName: inputData.filename || (inputs.selectedFile ? inputs.selectedFile.name : null),
        voiceTranscript: inputData.transcript
      },
      tacticBreakdown,
      dnaSignals,
      sandboxData
    };

    return { result, investigation };
  };

  const handleStartAnalysis = async () => {
    // Validate inputs per mode
    if (selectedMode === 'text' && !textInput.trim()) {
      alert("Please enter message or text content to analyze.");
      return;
    }
    if (selectedMode === 'image' && !selectedFile) {
      alert("Please select or upload an image file first.");
      return;
    }
    if (selectedMode === 'voice' && !selectedFile) {
      alert("Please record audio or upload an audio file first.");
      return;
    }
    if (selectedMode === 'sandbox' && !(activeSandboxUrl || sandboxUrlInput || urlInput).trim()) {
      alert("Please enter and load a website URL to investigate.");
      return;
    }
    if (selectedMode === 'multimodal' && !multiText.trim() && !multiImageFile && !multiAudioFile) {
      alert("Please provide at least one multimodal input (Text, Image, or Audio).");
      return;
    }

    setIsAnalyzing(true);
    setAnalysisResult(null);
    setScanError(null);
    apiCompletedRef.current = false;
    progressCompletedRef.current = false;
    pendingResultRef.current = null;
    pendingInvestigationRef.current = null;

    // Smooth scroll down to progress tracker
    setTimeout(() => {
      progressSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 100);

    try {
      let resData = null;
      const targetUrl = activeSandboxUrl || sandboxUrlInput || urlInput;

      if (selectedMode === 'text') {
        resData = await investigationService.scanText(textInput, 'SMS');
      } else if (selectedMode === 'sandbox') {
        resData = await investigationService.auditSandboxSession({
          url: targetUrl,
          events: sandboxEvents,
          page_text: sandboxPageInfo.pageText,
          page_title: sandboxPageInfo.title
        });
      } else if (selectedMode === 'image') {
        if (selectedFile) {
          resData = await investigationService.scanImage(selectedFile);
        }
      } else if (selectedMode === 'voice') {
        if (selectedFile) {
          resData = await investigationService.scanVoice(selectedFile);
        }
      } else if (selectedMode === 'multimodal') {
        resData = await investigationService.scanUnified({
          text: multiText,
          image: multiImageFile,
          audio: multiAudioFile
        });
      }

      if (resData) {
        const parsed = parseBackendScanResponse(resData, selectedMode, { 
          textInput: selectedMode === 'multimodal' ? multiText : textInput, 
          urlInput: targetUrl, 
          selectedFile: selectedMode === 'multimodal' ? multiImageFile : selectedFile,
          multiImageFile,
          multiAudioFile
        });
        pendingResultRef.current = parsed.result;
        pendingInvestigationRef.current = parsed.investigation;
      }
    } catch (err) {
      console.error("Backend API scan error:", err);
      setScanError("Threat analysis failed or backend is unreachable. Please verify server connectivity.");
    } finally {
      apiCompletedRef.current = true;
      if (progressCompletedRef.current) {
        setIsAnalyzing(false);
        if (pendingResultRef.current) {
          setAnalysisResult(pendingResultRef.current);
          if (pendingInvestigationRef.current && onSaveNewInvestigation) {
            onSaveNewInvestigation(pendingInvestigationRef.current);
          }
          setTimeout(() => {
            resultSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }, 150);
        }
      }
    }
  };

  const handleAnalysisProgressComplete = async () => {
    progressCompletedRef.current = true;
    if (apiCompletedRef.current) {
      setIsAnalyzing(false);
      if (pendingResultRef.current) {
        setAnalysisResult(pendingResultRef.current);
        if (pendingInvestigationRef.current && onSaveNewInvestigation) {
          onSaveNewInvestigation(pendingInvestigationRef.current);
        }
        setTimeout(() => {
          resultSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 150);
      }
    }
  };

  return (
    <div className="space-y-8 font-sans">
      {/* Header */}
      <div className="border-b border-[#E5E5E5] pb-6">
        <div className="text-[10px] font-mono font-medium tracking-widest text-[#6B6B6B] uppercase">
          FORENSIC INVESTIGATION SUITE
        </div>
        <h1 className="text-3xl lg:text-4xl font-bold tracking-tight text-[#111111] mt-0.5">
          Investigate Threat
        </h1>
        <p className="text-sm text-[#6B6B6B] mt-1 font-mono">
          Analyze suspicious text, screenshots, voice calls, isolated website sandboxes, or multimodal payloads.
        </p>
      </div>

      {/* Mode Selector Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {['text', 'image', 'voice', 'sandbox', 'multimodal'].map((m) => (
          <AnalysisModeCard
            key={m}
            modeKey={m}
            isSelected={selectedMode === m}
            onClick={() => handleModeChange(m)}
          />
        ))}
      </div>

      {/* INPUT WORKSPACE AREA */}
      <div className="space-y-6">
        {/* 1. TEXT MODE */}
        {selectedMode === 'text' && (
          <div className="shield-card p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
              <span className="text-xs font-mono font-bold text-[#111111] uppercase tracking-wider">
                INPUT SUSPECT MESSAGE / TEXT CONTENT
              </span>
            </div>
            
            <textarea
              rows={5}
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
              placeholder="Paste suspicious SMS, phishing email, WhatsApp alert, or threat message here..."
              className="w-full p-4 rounded-xl border border-[#E5E5E5] bg-[#F7F7F5] text-xs font-mono text-[#111111] focus:bg-white focus:border-[#111111] outline-none transition-colors leading-relaxed placeholder-[#8E8E8E]"
            />

            <div className="flex justify-end pt-2">
              <button
                onClick={handleStartAnalysis}
                disabled={isAnalyzing || !textInput.trim()}
                className="px-6 py-3 bg-[#111111] text-white rounded-xl font-mono text-xs font-bold hover:bg-black transition-all flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    <span>Analyzing Text Payload...</span>
                  </>
                ) : (
                  <>
                    <span>Run Deep Threat Analysis</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* 2. IMAGE MODE */}
        {selectedMode === 'image' && (
          <div className="shield-card p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
              <span className="text-xs font-mono font-bold text-[#111111] uppercase tracking-wider">
                UPLOAD SUSPICIOUS SCREENSHOT / IMAGE
              </span>
            </div>

            <div className="border-2 border-dashed border-[#E5E5E5] hover:border-[#111111] transition-colors rounded-2xl p-8 text-center bg-[#F7F7F5] relative">
              <input
                type="file"
                accept="image/*"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    setSelectedFile(e.target.files[0]);
                  }
                }}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              />
              <div className="space-y-3 pointer-events-none">
                <div className="w-12 h-12 rounded-xl bg-white border border-[#E5E5E5] flex items-center justify-center mx-auto shadow-2xs">
                  <Upload className="w-6 h-6 text-[#111111]" />
                </div>
                <div className="font-mono">
                  <div className="text-xs font-bold text-[#111111]">
                    {selectedFile ? selectedFile.name : "Drop screenshot here or click to browse"}
                  </div>
                  <p className="text-[11px] text-[#6B6B6B] mt-0.5">
                    PNG, JPG, WEBP up to 10MB. Automatic OCR &amp; brand verification.
                  </p>
                </div>
              </div>
            </div>

            {selectedFile && (
              <div className="p-3 bg-white border border-[#E5E5E5] rounded-xl flex items-center justify-between text-xs font-mono">
                <span className="text-[#111111] font-bold truncate max-w-xs">{selectedFile.name}</span>
                <span className="text-[#6B6B6B]">{(selectedFile.size / 1024).toFixed(1)} KB</span>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={handleStartAnalysis}
                disabled={isAnalyzing || !selectedFile}
                className="px-6 py-3 bg-[#111111] text-white rounded-xl font-mono text-xs font-bold hover:bg-black transition-all flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    <span>Analyzing Image...</span>
                  </>
                ) : (
                  <>
                    <span>Analyze Image Payload</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* 3. VOICE MODE */}
        {selectedMode === 'voice' && (
          <div className="shield-card p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
              <span className="text-xs font-mono font-bold text-[#111111] uppercase tracking-wider">
                VOICE &amp; ROBOCALL AUDIO INSPECTION
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Record Mic */}
              <div className="p-6 rounded-2xl bg-[#F7F7F5] border border-[#E5E5E5] flex flex-col items-center justify-center space-y-3 text-center">
                <div className="w-12 h-12 rounded-full bg-white border border-[#E5E5E5] flex items-center justify-center shadow-xs">
                  <Mic className={`w-6 h-6 ${isRecording ? 'text-red-600 animate-pulse' : 'text-[#111111]'}`} />
                </div>
                <div>
                  <div className="text-xs font-mono font-bold text-[#111111]">
                    {isRecording ? `Recording... (${recordingTime}s)` : "Live Microphone Capture"}
                  </div>
                  <p className="text-[11px] font-mono text-[#6B6B6B] mt-0.5">
                    Record suspected scam call directly
                  </p>
                </div>
                <button
                  onClick={isRecording ? handleStopRecording : handleStartRecording}
                  className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all cursor-pointer ${
                    isRecording 
                      ? 'bg-red-600 text-white hover:bg-red-700' 
                      : 'bg-[#111111] text-white hover:bg-black'
                  }`}
                >
                  {isRecording ? "Stop Recording" : "Start Live Recording"}
                </button>
              </div>

              {/* Upload Audio File */}
              <div className="border-2 border-dashed border-[#E5E5E5] hover:border-[#111111] transition-colors rounded-2xl p-6 text-center bg-[#F7F7F5] relative flex flex-col items-center justify-center space-y-2">
                <input
                  type="file"
                  accept="audio/*"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      setSelectedFile(e.target.files[0]);
                    }
                  }}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                />
                <Upload className="w-6 h-6 text-[#111111]" />
                <div className="text-xs font-mono font-bold text-[#111111]">
                  {selectedFile ? selectedFile.name : "Upload audio recording (MP3, WAV, M4A)"}
                </div>
                <p className="text-[10px] font-mono text-[#6B6B6B]">Drag &amp; drop audio file here</p>
              </div>
            </div>

            {selectedFile && (
              <div className="p-3 bg-white border border-[#E5E5E5] rounded-xl flex items-center justify-between text-xs font-mono">
                <span className="text-[#111111] font-bold truncate max-w-xs">Audio: {selectedFile.name}</span>
                <span className="text-[#6B6B6B]">{(selectedFile.size / 1024).toFixed(1)} KB</span>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={handleStartAnalysis}
                disabled={isAnalyzing || !selectedFile}
                className="px-6 py-3 bg-[#111111] text-white rounded-xl font-mono text-xs font-bold hover:bg-black transition-all flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    <span>Analyzing Audio Call...</span>
                  </>
                ) : (
                  <>
                    <span>Analyze Voice Evidence</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* 4. WEBSITE SANDBOX MODE */}
        {selectedMode === 'sandbox' && (
          <div className="shield-card p-6 space-y-6 font-mono">
            <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-[#E5E5E5] pb-4 gap-3">
              <div>
                <span className="text-[10px] text-[#6B6B6B] uppercase font-bold tracking-widest">
                  MODE: WEBSITE SANDBOX THREAT INVESTIGATION
                </span>
                <h2 className="text-xl font-bold text-[#111111] mt-0.5">
                  Live Interactive Website Sandbox
                </h2>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                <span className="text-xs font-bold text-emerald-700 uppercase">Live Interaction Active</span>
              </div>
            </div>

            {/* URL Input Bar */}
            <div className="space-y-3">
              <label className="block text-xs font-bold text-[#111111] uppercase tracking-wider">
                Suspect Website Target &amp; Isolated Proxy Viewport
              </label>
              <div className="flex flex-col sm:flex-row items-center gap-2">
                <div className="flex-1 w-full flex items-center gap-2 bg-[#F7F7F5] border border-[#E5E5E5] rounded-xl px-4 py-3 focus-within:border-[#111111] focus-within:bg-white transition-all">
                  <Globe className="w-4 h-4 text-[#6B6B6B] shrink-0" />
                  <input
                    type="text"
                    value={sandboxUrlInput}
                    onChange={(e) => setSandboxUrlInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        handleNavigateSandbox(sandboxUrlInput);
                      }
                    }}
                    placeholder="Enter suspect URL to investigate (e.g. https://example.com)..."
                    className="w-full bg-transparent border-none outline-none text-xs font-mono text-[#111111] placeholder-[#8E8E8E]"
                  />
                </div>
                <button
                  onClick={() => handleNavigateSandbox(sandboxUrlInput)}
                  className="w-full sm:w-auto px-6 py-3 bg-[#111111] text-white rounded-xl text-xs font-bold hover:bg-black transition-colors cursor-pointer shrink-0"
                >
                  Load Target
                </button>
              </div>
            </div>

            {/* Live Sandbox Viewport Frame */}
            {activeSandboxUrl ? (
              <div className="space-y-4">
                <div className="border border-[#E5E5E5] rounded-2xl overflow-hidden bg-white shadow-sm">
                  {/* Viewport Header */}
                  <div className="bg-[#111111] text-white px-4 py-2.5 flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-2 truncate">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <div className="w-2.5 h-2.5 rounded-full bg-red-500"></div>
                        <div className="w-2.5 h-2.5 rounded-full bg-amber-500"></div>
                        <div className="w-2.5 h-2.5 rounded-full bg-emerald-500"></div>
                      </div>
                      <span className="text-gray-400 truncate text-[11px]">
                        {sandboxPageInfo.title || activeSandboxUrl}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      {loadingSandboxPage && <span className="text-amber-400 animate-pulse text-[11px]">Loading DOM...</span>}
                      <span className="text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded font-bold">
                        ● ISOLATED PROXY
                      </span>
                    </div>
                  </div>

                  {/* Isolated Proxy Iframe */}
                  <div className="relative w-full h-[450px] bg-[#FAFAFA]">
                    <iframe
                      key={sandboxIframeKey}
                      src={`http://localhost:8000/api/scans/sandbox/proxy?url=${encodeURIComponent(activeSandboxUrl)}`}
                      title="Website Sandbox Viewport"
                      className="w-full h-full border-none"
                      sandbox="allow-scripts allow-forms allow-same-origin"
                    />
                  </div>

                  {/* Viewport Live Telemetry Footer */}
                  <div className="bg-[#F7F7F5] border-t border-[#E5E5E5] px-4 py-2 flex flex-wrap items-center justify-between text-[11px] font-mono text-[#6B6B6B] gap-2">
                    <div className="flex items-center gap-4">
                      <span>Forms: <strong className="text-[#111111]">{sandboxPageInfo.formsCount}</strong></span>
                      <span>Pass Fields: <strong className="text-red-600 font-bold">{sandboxPageInfo.passInputs}</strong></span>
                      <span>Links: <strong className="text-[#111111]">{sandboxPageInfo.linksCount}</strong></span>
                      <span>Scripts: <strong className="text-[#111111]">{sandboxPageInfo.scriptsCount}</strong></span>
                    </div>

                    <button
                      onClick={() => {
                        setSandboxIframeKey(Date.now());
                        setLoadingSandboxPage(true);
                      }}
                      className="flex items-center gap-1.5 text-xs text-[#111111] hover:underline cursor-pointer"
                    >
                      <RotateCw className="w-3.5 h-3.5" />
                      <span>Reload Viewport</span>
                    </button>
                  </div>
                </div>

                {/* Live Telemetry Log Feed */}
                {sandboxEvents.length > 0 && (
                  <div className="p-4 bg-[#F7F7F5] border border-[#E5E5E5] rounded-xl space-y-2 text-xs">
                    <div className="text-[10px] font-bold text-[#6B6B6B] uppercase tracking-wider">
                      Live Telemetry Feed ({sandboxEvents.length} events)
                    </div>
                    <div className="max-h-28 overflow-y-auto space-y-1">
                      {sandboxEvents.slice(0, 5).map((evt) => (
                        <div key={evt.id} className="text-[11px] text-[#111111]">
                          <span className="text-[#8E8E8E] mr-2">{evt.timestamp}</span>
                          <strong className="text-blue-700">{evt.eventType}</strong>: {typeof evt.payload === 'object' ? JSON.stringify(evt.payload) : evt.payload}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-12 text-center bg-[#F7F7F5] border border-dashed border-[#E5E5E5] rounded-2xl space-y-2">
                <Globe className="w-8 h-8 text-[#8E8E8E] mx-auto stroke-1" />
                <div className="text-xs font-bold text-[#111111] uppercase">No Sandbox Target Active</div>
                <p className="text-xs text-[#6B6B6B] max-w-sm mx-auto">
                  Enter a website address above and click "Load Target" to safely interact inside the isolated proxy.
                </p>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={handleStartAnalysis}
                disabled={isAnalyzing || !activeSandboxUrl}
                className="px-6 py-3 bg-[#111111] text-white rounded-xl font-mono text-xs font-bold hover:bg-black transition-all flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    <span>Auditing Website Sandbox Session...</span>
                  </>
                ) : (
                  <>
                    <span>Analyze Sandbox Session Evidence</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* 5. MULTIMODAL MODE */}
        {selectedMode === 'multimodal' && (
          <div className="shield-card p-6 space-y-6 font-mono">
            <div className="border-b border-[#E5E5E5] pb-3">
              <span className="text-xs font-mono font-bold text-[#111111] uppercase tracking-wider">
                CROSS-MODAL EVIDENCE INGESTION (TEXT + IMAGE + VOICE)
              </span>
              <p className="text-[11px] text-[#6B6B6B] mt-0.5">
                Ingest multiple vectors simultaneously to perform cross-modal fusion analysis.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Text Vector */}
              <div className="p-4 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5] space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold text-[#111111]">
                  <FileText className="w-4 h-4 text-blue-600" />
                  <span>1. Message Text</span>
                </div>
                <textarea
                  rows={4}
                  value={multiText}
                  onChange={(e) => setMultiText(e.target.value)}
                  placeholder="Paste SMS/Email copy here..."
                  className="w-full p-2.5 rounded-lg border border-[#E5E5E5] bg-white text-xs outline-none text-[#111111]"
                />
              </div>

              {/* Image Vector */}
              <div className="p-4 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5] space-y-2 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2 text-xs font-bold text-[#111111]">
                    <ImageIcon className="w-4 h-4 text-emerald-600" />
                    <span>2. Screenshot / Image</span>
                  </div>
                  <div className="mt-2 border border-dashed border-[#E5E5E5] rounded-lg p-3 text-center bg-white relative">
                    <input
                      type="file"
                      accept="image/*"
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          setMultiImageFile(e.target.files[0]);
                        }
                      }}
                      className="absolute inset-0 opacity-0 cursor-pointer"
                    />
                    <Upload className="w-5 h-5 text-[#8E8E8E] mx-auto mb-1" />
                    <div className="text-[11px] font-bold text-[#111111] truncate">
                      {multiImageFile ? multiImageFile.name : "Select Image"}
                    </div>
                  </div>
                </div>
                {multiImageFile && (
                  <div className="text-[10px] text-[#6B6B6B]">{(multiImageFile.size / 1024).toFixed(1)} KB loaded</div>
                )}
              </div>

              {/* Voice Vector */}
              <div className="p-4 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5] space-y-2 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2 text-xs font-bold text-[#111111]">
                    <Mic className="w-4 h-4 text-amber-600" />
                    <span>3. Suspect Voice Audio</span>
                  </div>
                  <div className="mt-2 flex flex-col gap-2">
                    <button
                      onClick={isMultiRecording ? handleStopMultiMicRecording : handleStartMultiMicRecording}
                      className={`w-full py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                        isMultiRecording ? 'bg-red-600 text-white' : 'bg-white border border-[#E5E5E5] text-[#111111] hover:bg-[#F0F0EE]'
                      }`}
                    >
                      {isMultiRecording ? `Recording (${multiRecordingTime}s)...` : "Record Mic Audio"}
                    </button>
                    <div className="relative border border-dashed border-[#E5E5E5] rounded-lg p-2 text-center bg-white">
                      <input
                        type="file"
                        accept="audio/*"
                        onChange={(e) => {
                          if (e.target.files && e.target.files[0]) {
                            setMultiAudioFile(e.target.files[0]);
                          }
                        }}
                        className="absolute inset-0 opacity-0 cursor-pointer"
                      />
                      <span className="text-[10px] text-[#6B6B6B] truncate block">
                        {multiAudioFile ? multiAudioFile.name : "Or upload audio file"}
                      </span>
                    </div>
                  </div>
                </div>
                {multiAudioFile && (
                  <div className="text-[10px] text-[#6B6B6B]">{(multiAudioFile.size / 1024).toFixed(1)} KB voice data</div>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={handleStartAnalysis}
                disabled={isAnalyzing || (!multiText.trim() && !multiImageFile && !multiAudioFile)}
                className="px-6 py-3 bg-[#111111] text-white rounded-xl font-mono text-xs font-bold hover:bg-black transition-all flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    <span>Performing Cross-Modal Fusion...</span>
                  </>
                ) : (
                  <>
                    <span>Execute Multimodal Analysis</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Error state */}
      {scanError && (
        <div className="shield-card p-4 border-red-200 bg-red-50/60 font-mono text-xs text-red-700 flex items-center justify-between">
          <span>{scanError}</span>
          <button onClick={() => setScanError(null)} className="underline cursor-pointer font-bold">Dismiss</button>
        </div>
      )}

      {/* PROGRESS BAR DISPLAY */}
      {isAnalyzing && (
        <div ref={progressSectionRef} className="scroll-mt-6">
          <AnalysisProgress mode={selectedMode} onComplete={handleAnalysisProgressComplete} />
        </div>
      )}

      {/* RESULT DISPLAY PANELS */}
      {analysisResult && !isAnalyzing && (
        <div ref={resultSectionRef} className="space-y-8 font-sans animate-in fade-in duration-300 scroll-mt-6">
          
          {/* 1. ANALYZED IMAGE SECTION */}
          {(selectedMode === 'image' || selectedFile || (selectedMode === 'multimodal' && multiImageFile)) && (selectedFile || multiImageFile) && (
            <div className="bg-white border border-[#E5E5E5] rounded-2xl p-6 shadow-xs space-y-4">
              <div className="text-xs font-mono font-bold text-[#111111] uppercase tracking-wider flex items-center justify-between">
                <span>ANALYZED IMAGE PAYLOAD</span>
                <span className="text-[10px] font-mono text-emerald-700 font-bold bg-emerald-50 px-2.5 py-1 rounded-md border border-emerald-200">
                  ✓ Verified Payload
                </span>
              </div>
              <div className="p-4 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5] text-center">
                <img 
                  src={URL.createObjectURL(multiImageFile || selectedFile)} 
                  alt="Analyzed Screenshot Payload" 
                  className="max-h-72 object-contain mx-auto rounded-lg shadow-sm border border-[#E5E5E5]" 
                />
              </div>
            </div>
          )}

          {/* 2. RISK ASSESSMENT & CATEGORY CARD */}
          <div className="bg-white border border-[#E5E5E5] rounded-2xl p-8 shadow-xs font-mono">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
              
              {/* RISK SCORE BLOCK */}
              <div className="space-y-2 border-b md:border-b-0 md:border-r border-[#E5E5E5] pb-6 md:pb-0 md:pr-8">
                <div className="text-xs font-bold text-[#6B6B6B] uppercase tracking-widest">
                  RISK SCORE
                </div>
                <div className="text-5xl lg:text-6xl font-extrabold tracking-tight text-[#111111]">
                  {analysisResult.score !== null ? (
                    <>
                      {analysisResult.score} <span className="text-2xl lg:text-3xl text-[#8E8E8E] font-normal">/ 100</span>
                    </>
                  ) : (
                    <span>—</span>
                  )}
                </div>
                <div className="pt-2 flex items-center gap-2">
                  <span className={`text-sm font-extrabold tracking-wider flex items-center gap-2 ${
                    analysisResult.threatLevel === 'INCONCLUSIVE'
                      ? 'text-amber-600'
                      : analysisResult.threatLevel === 'SAFE'
                      ? 'text-emerald-600'
                      : 'text-red-600'
                  }`}>
                    <span className={`w-3 h-3 rounded-full ${
                      analysisResult.threatLevel === 'INCONCLUSIVE'
                        ? 'bg-amber-500 animate-pulse'
                        : analysisResult.threatLevel === 'SAFE'
                        ? 'bg-emerald-500 animate-pulse'
                        : 'bg-red-600 animate-pulse'
                    }`}></span>
                    ● {analysisResult.threatLevel}
                  </span>
                </div>
              </div>

              {/* CATEGORY BLOCK */}
              <div className="space-y-2">
                <div className="text-xs font-bold text-[#6B6B6B] uppercase tracking-widest">
                  CATEGORY
                </div>
                <div className="text-2xl lg:text-3xl font-extrabold tracking-tight text-[#111111]">
                  {analysisResult.scamType || "Threat Scan"}
                </div>
                <p className="text-xs text-[#6B6B6B] pt-1 font-normal">
                  Identified threat category derived from deep AI content inspection.
                </p>
              </div>

            </div>
          </div>

          {/* 3. SUB-NAVIGATION TABS */}
          <div className="bg-white border border-[#E5E5E5] rounded-2xl p-2 flex flex-wrap items-center gap-2 font-mono text-xs shadow-xs">
            <button 
              onClick={() => setActiveTab('result')}
              className={`px-5 py-3 rounded-xl font-bold transition-all cursor-pointer ${
                activeTab === 'result'
                  ? 'bg-[#111111] text-white shadow-sm' 
                  : 'bg-transparent text-[#6B6B6B] hover:text-[#111111] hover:bg-[#F7F7F5]'
              }`}
            >
              Behavioral Breakdown
            </button>
            <button 
              onClick={() => setActiveTab('reveal')}
              className={`px-5 py-3 rounded-xl font-bold transition-all cursor-pointer ${
                activeTab === 'reveal' 
                  ? 'bg-[#111111] text-white shadow-sm' 
                  : 'bg-transparent text-[#6B6B6B] hover:text-[#111111] hover:bg-[#F7F7F5]'
              }`}
            >
              Reveal Scam
            </button>
            <button 
              onClick={() => setActiveTab('dna')}
              className={`px-5 py-3 rounded-xl font-bold transition-all cursor-pointer ${
                activeTab === 'dna' 
                  ? 'bg-[#111111] text-white shadow-sm' 
                  : 'bg-transparent text-[#6B6B6B] hover:text-[#111111] hover:bg-[#F7F7F5]'
              }`}
            >
              Scam DNA
            </button>
            {selectedMode === 'sandbox' && (
              <button 
                onClick={() => setActiveTab('sandbox')}
                className={`px-5 py-3 rounded-xl font-bold transition-all cursor-pointer ${
                  activeTab === 'sandbox' 
                    ? 'bg-[#111111] text-white shadow-sm' 
                    : 'bg-transparent text-[#6B6B6B] hover:text-[#111111] hover:bg-[#F7F7F5]'
                }`}
              >
                Sandbox Browser
              </button>
            )}
          </div>

          {/* 4. TAB CONTENTS */}
          
          {/* TAB 1: BEHAVIORAL BREAKDOWN */}
          {activeTab === 'result' && (
            <div className="space-y-8 font-sans">
              
              {/* MODEL BEHAVIORAL TACTIC BREAKDOWN */}
              {analysisResult.tacticBreakdown && (
                <div className="bg-white border border-[#E5E5E5] rounded-2xl p-6 md:p-8 space-y-6 font-mono shadow-xs">
                  <div className="text-xs font-bold text-[#111111] uppercase tracking-wider flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                    <span>MODEL BEHAVIORAL TACTIC BREAKDOWN</span>
                    <span className="text-[10px] text-[#6B6B6B]">SmartShield AI Engine Assessment</span>
                  </div>
                  <div className="space-y-4">
                    {Object.entries(analysisResult.tacticBreakdown).map(([k, v]) => (
                      <div key={k} className="space-y-1.5">
                        <div className="flex justify-between text-xs font-bold text-[#111111] uppercase tracking-wide">
                          <span>{k.replace(/([A-Z])/g, ' $1')}</span>
                          <span className={v >= 60 ? 'text-red-600' : 'text-[#111111]'}>{v}%</span>
                        </div>
                        <div className="w-full h-3 bg-[#F0F0EE] rounded-full overflow-hidden border border-[#E5E5E5]">
                          <div 
                            className={`h-full rounded-full transition-all duration-500 ${v >= 60 ? 'bg-red-600' : 'bg-[#111111]'}`} 
                            style={{ width: `${Math.min(100, Math.max(0, v))}%` }} 
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* MODEL VERDICT EXPLANATION */}
              <div className="bg-white border border-[#E5E5E5] rounded-2xl p-6 md:p-8 space-y-5 shadow-xs">
                <div className="text-xs font-mono font-bold text-[#111111] uppercase tracking-wider border-b border-[#E5E5E5] pb-3">
                  MODEL VERDICT EXPLANATION
                </div>

                {/* Verdict Headline Header */}
                <div className="p-4 rounded-xl bg-[#F7F7F5] border border-[#E5E5E5] space-y-1 font-mono">
                  <div className="text-sm font-extrabold flex items-center gap-2">
                    <span>Final Risk Engine Verdict:</span>
                    <span className={
                      analysisResult.threatLevel === 'INCONCLUSIVE' 
                        ? 'text-amber-600 uppercase font-black tracking-wider'
                        : analysisResult.threatLevel === 'SAFE' 
                        ? 'text-emerald-600 uppercase font-black tracking-wider' 
                        : 'text-red-600 uppercase font-black tracking-wider'
                    }>
                      {analysisResult.threatLevel}
                    </span>
                  </div>
                  <div className="text-xs text-[#6B6B6B]">
                    Risk Score: <strong className={
                      analysisResult.threatLevel === 'SAFE' ? 'text-emerald-600 font-extrabold' : 'text-red-600 font-extrabold'
                    }>
                      {analysisResult.score !== null ? `${analysisResult.score} / 100` : 'INCONCLUSIVE'}
                    </strong>
                  </div>
                </div>

                {/* Explanation Content */}
                <div className="text-sm text-[#111111] leading-relaxed font-sans space-y-3 pt-1">
                  <p className="whitespace-pre-line font-medium text-[#222222]">
                    {analysisResult.explanation}
                  </p>
                </div>
              </div>

              {/* RECOMMENDED ACTIONS */}
              <div className="bg-white border border-[#E5E5E5] rounded-2xl p-6 md:p-8 space-y-6 shadow-xs">
                <div className="text-xs font-mono font-bold text-[#111111] uppercase tracking-wider border-b border-[#E5E5E5] pb-3">
                  RECOMMENDED DEFENSIVE ACTIONS
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono">
                  {analysisResult.recommendations && analysisResult.recommendations.length > 0 ? (
                    analysisResult.recommendations.map((rec, idx) => (
                      <div key={idx} className="p-4 rounded-xl border border-[#E5E5E5] bg-[#F7F7F5] flex items-start gap-3 transition-all hover:border-[#111111]">
                        <span className="text-sm font-extrabold text-[#111111] bg-white px-2.5 py-1 rounded border border-[#E5E5E5] shrink-0 font-mono">
                          0{idx + 1}
                        </span>
                        <p className="text-xs text-[#111111] leading-normal pt-1 font-medium font-sans">
                          {rec}
                        </p>
                      </div>
                    ))
                  ) : (
                    analysisResult.threatLevel === 'SAFE' ? (
                      [
                        "01 No immediate malicious activity or credential harvesting forms detected.",
                        "02 Verified communication or notification pattern.",
                        "03 Exercise standard security caution when opening unverified links.",
                        "04 Keep security credentials and 2FA tokens private."
                      ].map((rec, idx) => (
                        <div key={idx} className="p-4 rounded-xl border border-[#E5E5E5] bg-[#F7F7F5] flex items-start gap-3">
                          <span className="text-sm font-extrabold text-emerald-700 bg-white px-2.5 py-1 rounded border border-[#E5E5E5] shrink-0">
                            {rec.slice(0, 2)}
                          </span>
                          <p className="text-xs text-[#111111] leading-normal pt-1 font-medium font-sans">
                            {rec.slice(3)}
                          </p>
                        </div>
                      ))
                    ) : (
                      [
                        "01 Do NOT click any links in this message or target page.",
                        "02 Do NOT share OTPs, passwords, or personal identity documents.",
                        "03 Report this contact to your service provider or cybersecurity cell.",
                        "04 Block this sender number/email immediately."
                      ].map((rec, idx) => (
                        <div key={idx} className="p-4 rounded-xl border border-[#E5E5E5] bg-[#F7F7F5] flex items-start gap-3">
                          <span className="text-sm font-extrabold text-red-600 bg-white px-2.5 py-1 rounded border border-[#E5E5E5] shrink-0">
                            {rec.slice(0, 2)}
                          </span>
                          <p className="text-xs text-[#111111] leading-normal pt-1 font-medium font-sans">
                            {rec.slice(3)}
                          </p>
                        </div>
                      ))
                    )
                  )}
                </div>
              </div>

            </div>
          )}

          {/* TAB 2: REVEAL SCAM */}
          {activeTab === 'reveal' && (
            <RevealScamPanel 
              originalText={analysisResult.originalText || analysisResult.transcript || textInput || multiText} 
              highlights={analysisResult.highlights} 
            />
          )}

          {/* TAB 3: SCAM DNA */}
          {activeTab === 'dna' && (
            <ScamDNA 
              dnaSignals={analysisResult.dnaSignals || analysisResult.tacticBreakdown} 
            />
          )}

          {/* TAB 4: SANDBOX BROWSER */}
          {activeTab === 'sandbox' && selectedMode === 'sandbox' && (
            <SandboxBrowser sandboxData={analysisResult.sandboxData} />
          )}

        </div>
      )}
    </div>
  );
};

export default Investigate;
