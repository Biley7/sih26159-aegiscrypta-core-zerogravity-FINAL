import React, { useState } from 'react';
import {
  UploadCloud,
  AlertTriangle,
  ShieldAlert,
  Activity,
  CheckCircle2,
  RefreshCw,
  X
} from 'lucide-react';
import { PcapAnalysisResponse } from '../types';

interface PcapForensicsViewProps {
  pcapData: PcapAnalysisResponse | null;
  onUploadPcap: (file: File) => void;
  isLoading: boolean;
}

export const PcapForensicsView: React.FC<PcapForensicsViewProps> = ({
  pcapData,
  onUploadPcap,
  isLoading
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileSizeStr, setFileSizeStr] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [selectedStreamId, setSelectedStreamId] = useState<number | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const validateAndProcessFile = (file: File) => {
    setValidationError(null);
    const validExtensions = ['.pcap', '.pcapng', '.cap'];
    const hasValidExt = validExtensions.some((ext) => file.name.toLowerCase().endsWith(ext));

    if (!hasValidExt) {
      setValidationError(`Unsupported file format "${file.name}". Requires .pcap or .pcapng network packet capture.`);
      return;
    }

    if (file.size > 50 * 1024 * 1024) {
      setValidationError(`File size ${(file.size / (1024 * 1024)).toFixed(1)} MB exceeds the 50MB forensic buffer threshold.`);
      return;
    }

    const sizeFormatted = file.size > 1024 * 1024
      ? `${(file.size / (1024 * 1024)).toFixed(2)} MB`
      : `${(file.size / 1024).toFixed(1)} KB`;

    setSelectedFile(file);
    setFileSizeStr(sizeFormatted);
    onUploadPcap(file);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndProcessFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndProcessFile(e.dataTransfer.files[0]);
    }
  };

  const selectedStream = pcapData?.streams.find((s) => s.stream_id === selectedStreamId);

  return (
    <div className="pcap-forensics-container" aria-label="Passive PCAP Network Forensics">
      {/* Upload Dropzone */}
      <div
        className={`pcap-upload-dropzone ${dragOver ? 'drag-over' : ''} ${isLoading ? 'opacity-70 pointer-events-none' : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
      >
        <input
          type="file"
          id="pcap-file-input"
          accept=".pcap,.pcapng,.cap"
          onChange={handleFileChange}
          className="hidden-file-input"
        />
        <label htmlFor="pcap-file-input" className="dropzone-label">
          <div className="dropzone-icon-wrap">
            {isLoading ? (
              <RefreshCw size={24} className="animate-spin text-soc-pqc" />
            ) : (
              <UploadCloud size={24} className="text-soc-pqc" />
            )}
          </div>
          <div>
            <h3 className="text-sm font-bold text-text-primary">
              {isLoading
                ? 'Reassembling TCP Streams & Extracting Cryptographic Records...'
                : selectedFile
                ? `Active Capture: ${selectedFile.name} (${fileSizeStr})`
                : 'Ingest .pcap or .pcapng Network Packet Capture'}
            </h3>
            <p className="text-xs text-text-secondary mt-1">
              Drag &amp; drop capture dumps or <span className="text-soc-pqc underline cursor-pointer font-semibold">browse filesystem</span>. Reassembles full TCP streams, STARTTLS stripping, and cleartext credential exposures.
            </p>
          </div>
        </label>
      </div>

      {/* Validation & Ingestion Status Bar */}
      {validationError ? (
        <div className="p-3 bg-soc-critical-bg border border-soc-critical-border rounded text-soc-critical font-mono text-xs flex items-center gap-2">
          <AlertTriangle size={14} className="shrink-0" />
          <span>{validationError}</span>
        </div>
      ) : selectedFile ? (
        <div className="p-2.5 bg-surface-secondary border border-border-primary rounded text-xs font-mono flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 text-text-primary">
            <CheckCircle2 size={13} className="text-soc-secure" />
            <span>Ingestion Validated: {selectedFile.name}</span>
            <span className="text-border-subtle">|</span>
            <span className="text-text-muted">Size: {fileSizeStr}</span>
          </div>
          <div className="text-soc-secure font-semibold">
            {pcapData ? `${pcapData.total_packets.toLocaleString()} frames parsed` : 'Analyzing frames...'}
          </div>
        </div>
      ) : null}

      {/* PCAP Telemetry Results */}
      {pcapData && (
        <div className="mt-4">
          {/* Metadata Statistics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-3 rounded bg-surface-secondary border border-border-primary mb-4 font-mono text-xs">
            <div>
              <span className="text-text-muted block text-[10px]">Capture File:</span>
              <span className="text-text-primary font-semibold truncate block">{pcapData.filename}</span>
            </div>
            <div>
              <span className="text-text-muted block text-[10px]">Total Frames:</span>
              <span className="text-text-primary font-semibold">{pcapData.total_packets.toLocaleString()}</span>
            </div>
            <div>
              <span className="text-text-muted block text-[10px]">Reconstructed Flows:</span>
              <span className="text-text-primary font-semibold">{pcapData.total_tcp_streams} streams</span>
            </div>
            <div>
              <span className="text-text-muted block text-[10px]">Protocols Detected:</span>
              <span className="text-soc-secure font-semibold">{pcapData.identified_protocols.join(', ')}</span>
            </div>
          </div>

          {/* Anomaly & Threat Warnings Strip */}
          {pcapData.summary_findings.length > 0 && (
            <div className="flex flex-col gap-2 mb-4">
              {pcapData.summary_findings.map((finding, idx) => (
                <div
                  key={idx}
                  className={`p-3 rounded border text-xs font-mono flex items-start gap-2.5 ${
                    finding.severity === 'CRITICAL'
                      ? 'bg-soc-critical-bg border-soc-critical-border'
                      : 'bg-soc-warning-bg border-soc-warning-border'
                  }`}
                >
                  <ShieldAlert size={16} className={`shrink-0 mt-0.5 ${finding.severity === 'CRITICAL' ? 'text-soc-critical' : 'text-soc-warning'}`} />
                  <div>
                    <strong className="text-text-primary block">{finding.title}</strong>
                    <p className="text-text-secondary mt-0.5">{finding.description}</p>
                    {finding.recommendation && (
                      <span className="text-soc-warning block mt-1">
                        Mitigation: {finding.recommendation}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Reconstructed TCP Stream Table */}
          <div className="dashboard-section p-0 overflow-hidden">
            <div className="p-3 border-b border-border-primary flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-text-primary flex items-center gap-2">
                <Activity size={14} className="text-soc-pqc" />
                Reconstructed TCP Streams ({pcapData.streams.length})
              </h3>
              <span className="text-[11px] font-mono text-text-muted">
                Click any row to inspect flow telemetry
              </span>
            </div>

            <div className="table-responsive-container border-none rounded-none">
              <table className="telemetry-data-table">
                <thead>
                  <tr>
                    <th>Stream ID</th>
                    <th>Client Endpoint</th>
                    <th>Server Endpoint</th>
                    <th>Protocol</th>
                    <th>Packets / Volume</th>
                    <th>TLS Version</th>
                    <th>Cipher Suite</th>
                    <th>Inspection Result</th>
                  </tr>
                </thead>
                <tbody>
                  {pcapData.streams.map((stream) => {
                    const hasThreat = stream.findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
                    const isSelected = selectedStreamId === stream.stream_id;

                    return (
                      <tr
                        key={stream.stream_id}
                        onClick={() => setSelectedStreamId(isSelected ? null : stream.stream_id)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-surface-elevated'
                            : hasThreat
                            ? 'bg-soc-critical-bg/30'
                            : ''
                        }`}
                      >
                        {/* Stream ID */}
                        <td className="font-mono font-bold text-soc-pqc">
                          #{stream.stream_id}
                        </td>

                        {/* Client */}
                        <td className="font-mono text-xs text-text-secondary">
                          {stream.client_ip}:{stream.client_port}
                        </td>

                        {/* Server */}
                        <td className="font-mono text-xs text-text-secondary">
                          {stream.server_ip}:{stream.server_port}
                        </td>

                        {/* Protocol */}
                        <td>
                          <span className="service-mode-tag">
                            {stream.protocol}
                          </span>
                        </td>

                        {/* Packets / Bytes */}
                        <td className="font-mono text-xs text-text-muted">
                          {stream.packet_count} pkts / {(stream.client_bytes + stream.server_bytes).toLocaleString()} B
                        </td>

                        {/* TLS Version */}
                        <td>
                          {stream.tls_handshake_detected ? (
                            <span className="tls-version-badge modern">
                              {stream.tls_version || 'TLS'}
                            </span>
                          ) : stream.starttls_detected === false && stream.protocol.includes('STRIPTLS') ? (
                            <span className="tls-version-badge deprecated">
                              STRIPTLS Active
                            </span>
                          ) : (
                            <span className="font-mono text-xs text-text-muted">Cleartext</span>
                          )}
                        </td>

                        {/* Cipher Suite */}
                        <td className="font-mono text-xs text-text-secondary max-w-xs truncate">
                          {stream.cipher_suite || 'N/A'}
                        </td>

                        {/* Inspection Status */}
                        <td>
                          {hasThreat ? (
                            <span className="status-badge-chip critical">
                              <AlertTriangle size={11} /> Threat Detected
                            </span>
                          ) : (
                            <span className="status-badge-chip secure">
                              <CheckCircle2 size={11} /> Clean Stream
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Selected Stream Details Drawer */}
          {selectedStream && (
            <div className="dashboard-section mt-4 p-4 border border-border-focus bg-surface-secondary">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-border-subtle">
                <h4 className="font-mono text-xs font-bold text-soc-pqc flex items-center gap-1.5">
                  <Activity size={13} />
                  Inspection Analysis: Flow #{selectedStream.stream_id} ({selectedStream.protocol})
                </h4>
                <button
                  onClick={() => setSelectedStreamId(null)}
                  className="text-xs text-text-muted hover:text-text-primary font-mono flex items-center gap-1"
                >
                  <X size={12} /> Close
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                <div className="p-3 rounded bg-surface border border-border-primary space-y-1 text-text-secondary">
                  <span className="text-text-muted block text-[10px] uppercase tracking-wider mb-1">Flow Parameters</span>
                  <div>Client: <span className="text-text-primary">{selectedStream.client_ip}:{selectedStream.client_port}</span> ({selectedStream.client_bytes} bytes sent)</div>
                  <div>Server: <span className="text-text-primary">{selectedStream.server_ip}:{selectedStream.server_port}</span> ({selectedStream.server_bytes} bytes sent)</div>
                  <div>Total Packets in Flow: {selectedStream.packet_count}</div>
                  <div>STARTTLS Explicitly Requested: {selectedStream.starttls_detected ? 'YES' : 'NO'}</div>
                  <div>TLS Handshake Negotiated: {selectedStream.tls_handshake_detected ? 'YES' : 'NO'}</div>
                </div>

                <div className="p-3 rounded bg-surface border border-border-primary space-y-1 text-text-secondary">
                  <span className="text-text-muted block text-[10px] uppercase tracking-wider mb-1">Extracted Cryptographic Artifacts</span>
                  <div>Cipher Suite: <span className="text-text-primary">{selectedStream.cipher_suite || 'None'}</span></div>
                  <div>Negotiated Protocol: <span className="text-text-primary">{selectedStream.tls_version || 'Cleartext'}</span></div>
                  <div>X.509 Certificate Extracted: {selectedStream.certificate_extracted ? 'YES' : 'NO'}</div>
                  {selectedStream.certificate_info && (
                    <div className="text-soc-pqc mt-1">
                      Cert CN: {selectedStream.certificate_info.subject_cn} (Issuer: {selectedStream.certificate_info.issuer_cn})
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
