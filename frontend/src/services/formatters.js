/**
 * Formats a raw scan document returned by the backend into a clean UI investigation object.
 * Strictly uses data present in the backend document without inventing fake fields.
 */
export function formatScanDocument(scan) {
  if (!scan) return null;

  const id = scan._id ? String(scan._id) : `SC-${Date.now()}`;
  const displayId = id.length > 8 ? `SC-${id.slice(-6).toUpperCase()}` : id;
  const fusion = scan.fusion_result || {};
  const qwen = scan.qwen_result || {};
  const sandbox = scan.sandbox_report || {};
  const inputData = scan.input_data || {};

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

  const rawText = inputData.content || inputData.text || inputData.extracted_text || inputData.transcript || "";
  const rawUrl = inputData.url || inputData.url_content || inputData.detected_url || sandbox.url || "";
  const filename = inputData.filename || inputData.image_filename || inputData.audio_filename || "";

  // Target label for tables / summaries
  let targetLabel = rawUrl || filename || (rawText ? rawText.slice(0, 60) : "Threat Payload");

  const scanType = (scan.type || 'text').toUpperCase();
  const vectorLabel = scanType === 'MULTIMODAL' || scanType === 'UNIFIED'
    ? "MULTIMODAL"
    : (scanType === 'URL' ? 'WEBSITE SANDBOX' : scanType);

  const explanation = fusion.explanation || qwen.explanation || (isInconclusive ? "Not enough behavioral evidence was collected to classify this payload." : "Threat analysis complete.");
  const recommendations = fusion.recommendations || [];

  // Tactic breakdown directly from model fusion
  const tacticBreakdown = fusion.tactic_breakdown || qwen.tactic_breakdown || null;
  const dnaSignals = fusion.dna_signals || qwen.dna_signals || null;
  const highlights = fusion.tactic_highlights || qwen.tactic_highlights || [];

  const createdAt = scan.created_at ? new Date(scan.created_at) : new Date();
  const dateFormatted = createdAt.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric'
  });
  const timeFormatted = createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  return {
    id: displayId,
    rawId: id,
    type: scan.type || 'text',
    vector: vectorLabel,
    target: targetLabel,
    filename: filename,
    score: score,
    threatLevel: threatLevel,
    scamType: scamType,
    title: scamType,
    category: scamType,
    explanation: explanation,
    summary: explanation,
    recommendations: recommendations,
    tacticBreakdown: tacticBreakdown,
    dnaSignals: dnaSignals,
    highlights: highlights,
    date: dateFormatted,
    time: timeFormatted,
    timestamp: `${dateFormatted}, ${timeFormatted}`,
    createdAt: createdAt.toISOString(),
    originalContent: {
      text: rawText,
      url: rawUrl,
      filename: filename,
      transcript: inputData.transcript
    },
    sandboxData: sandbox
  };
}
