import React, { useState } from 'react';
import {
  BookOpen,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  Terminal,
  Clock,
  Copy,
  Check,
  Shield,
  Activity,
  ArrowRight,
  ExternalLink,
  RefreshCw,
  FileText,
  Globe,
  Lock,
  Info,
  ChevronRight,
  BookMarked,
  Layers,
  Sparkles,
  X,
  Filter,
  Target,
  Compass,
  Unlock,
  Search
} from 'lucide-react';
import InfoPopover from './InfoPopover';

interface Question {
  id: number;
  question: string;
  options: string[];
  answerIndex: number;
  explanation: string;
}

const quizQuestions: Question[] = [
  {
    id: 1,
    question: "Which network indicator is most consistent with active DNS Tunneling behavior?",
    options: [
      "Frequent HTTP GET requests to common content delivery networks on standard ports",
      "High-entropy, randomized subdomains on Port 53 returning heavy TXT or CNAME record volumes",
      "Standard reverse-DNS lookups (PTR queries) for internal local subnet addresses",
      "A sudden surge in ICMP Echo Requests with default payload structures"
    ],
    answerIndex: 1,
    explanation: "DNS Tunneling exploits standard Port 53 query channels by placing encoded payloads inside randomized subdomains. This behavior bypasses traditional boundary firewalls that permit outbound recursive DNS routing."
  },
  {
    id: 2,
    question: "How does a JA3 fingerprint assist an analyst when evaluating fully encrypted TLS traffic?",
    options: [
      "It temporarily decapsulates the session's payload using public key material",
      "It fingerprints client applications based on early handshake parameter combinations",
      "It automatically intercepts and proxies the TLS connection at the core router",
      "It computes a secure cryptographic checksum of the host's operating system files"
    ],
    answerIndex: 1,
    explanation: "JA3 generates an MD5 hash from client-side parameters proposed during the Client Hello (e.g., cipher suites, extensions, versions). This allows analysts to fingerprint specific client applications or libraries even when payload encryption is fully active."
  },
  {
    id: 3,
    question: "An analyst discovers a legacy administration console exposing user sessions. Which combination of protocols transmits credentials without native encryption?",
    options: [
      "SFTP, HTTPS, SSH, TLS",
      "HTTP, FTP, Telnet, SMTP",
      "DNS, ICMP, DHCP, ARP",
      "IPsec, WireGuard, OpenVPN, WPA3"
    ],
    answerIndex: 1,
    explanation: "HTTP, FTP, Telnet, and basic SMTP transmit all commands, usernames, passwords, and data packets in cleartext. Any network-level packet capture or intermediary tap can read these payloads directly."
  },
  {
    id: 4,
    question: "During packet capture inspection of an encrypted TLS session, what specific information remains visible to passive sensors during the handshake?",
    options: [
      "The full decrypted HTTP request path, cookie strings, and request parameters",
      "The destination server's hostname via the unencrypted Server Name Indication (SNI) field",
      "The cryptographic secret session keys negotiated between the client and server",
      "The private SSL certificates stored locally on the client's internal system"
    ],
    answerIndex: 1,
    explanation: "In standard TLS handshakes (specifically TLS 1.2 and earlier, as well as the unencrypted Client Hello in TLS 1.3), the Server Name Indication (SNI) is transmitted in cleartext, allowing firewalls and monitoring tools to determine the destination hostname before encryption begins."
  },
  {
    id: 5,
    question: "When compiling a security incident narrative, what analytical boundary must an investigator respect regarding network-only evidence?",
    options: [
      "Network captures can definitively confirm local process execution names and process owner IDs",
      "Network flows can prove data transit and protocol headers, but cannot on their own prove who sat at the keyboard",
      "Network evidence is automatically invalidated if the transit router does not run an active firewall",
      "An analyst cannot determine the source IP address of packets without a host-level system log"
    ],
    answerIndex: 1,
    explanation: "Network captures provide peerless evidence of data transit, protocol exchanges, and time sequences. However, they cannot verify local physical actions, local authorized permissions, or offline file accesses. Host-level logs (EDR, authentication logs) are required for full correlation."
  }
];

const questionTopics: Record<number, { title: string; tag: string; skill: string; views: string[]; whyMatters: string }> = {
  1: {
    title: "DNS Tunneling Indicators",
    tag: "DNS ANALYSIS",
    skill: "Recursive query entropy & TXT payload inspection",
    views: ["Flow Explorer", "Protocol Intel"],
    whyMatters: "Enables detection of outbound covert channels exploiting unrestricted port 53 recursive routing."
  },
  2: {
    title: "TLS Client Fingerprinting",
    tag: "TLS FINGERPRINTING",
    skill: "Client Hello cipher negotiation fingerprint clustering",
    views: ["Protocol Intel", "Observations"],
    whyMatters: "Tracks malicious software agents and automated scripts prior to the establishment of session encryption."
  },
  3: {
    title: "Cleartext Protocol Exposure",
    tag: "CLEARTEXT EXPOSURE",
    skill: "Passive protocol decapsulation & credential audits",
    views: ["Flow Explorer", "Protocol Intel", "Timeline"],
    whyMatters: "Pinpoints high-risk administrative channels leaking unencrypted credentials across the local network."
  },
  4: {
    title: "TLS Handshake Inspection",
    tag: "TLS HANDSHAKE",
    skill: "Server Name Indication (SNI) identification & payload boundaries",
    views: ["Protocol Intel", "Flow Explorer"],
    whyMatters: "Determines requested host destinations early in the handshake before the secure tunnel is fully negotiated."
  },
  5: {
    title: "Analytical Boundaries",
    tag: "EVIDENCE LIMITS",
    skill: "Scientific defensive writing & multi-source endpoint correlation",
    views: ["Report Builder", "AI Memo", "Command Center"],
    whyMatters: "Preserves forensic credibility by separating observed transit behaviors from unverified endpoint actions."
  }
};

interface LessonModule {
  id: number;
  title: string;
  shortDesc: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Analyst';
  time: string;
  icon: React.ComponentType<any>;
  content: {
    objectives: string[];
    body: string;
    keyTerms: { term: string; definition: string }[];
    defensiveTips: string[];
    relatedViews: string[];
  };
}

const lessonModules: LessonModule[] = [
  {
    id: 1,
    title: "Reading Flow Records",
    shortDesc: "Interpret source/destination IP pairs, transport protocols, and byte/packet distributions to identify abnormal data flows.",
    difficulty: "Beginner",
    time: "5 min",
    icon: Activity,
    content: {
      objectives: [
        "Understand the core elements of a network 5-tuple",
        "Distinguish between client and server payload proportions",
        "Identify packet-to-byte ratio anomalies indicating data transfer"
      ],
      body: "NetFlow and IP flow records aggregate packet transmissions into unidirectional or bidirectional summaries. To analyze a flow, map the 5-tuple: source IP, destination IP, source port, destination port, and protocol. Look at packet-to-byte ratios: an active web session has low source-to-destination bytes but high destination-to-source bytes. Watch for reverse asymmetry—massive outbound volumes might represent data stage or exfiltration indicators.",
      keyTerms: [
        { term: "5-Tuple", definition: "The unique combination of source/destination IPs, ports, and protocol." },
        { term: "Flow Asymmetry", definition: "Unequal data flow directions indicating source uploads or heavy server downloads." }
      ],
      defensiveTips: [
        "Validate flow records against known internal subnets.",
        "Always cross-reference high-byte unilateral flows with local endpoints."
      ],
      relatedViews: ["Flow Explorer", "Incident Timeline"]
    }
  },
  {
    id: 2,
    title: "DNS Query Patterns",
    shortDesc: "Detect excessive queries to unrecognized subdomains, TXT/CNAME records, and domain generation algorithms (DGAs).",
    difficulty: "Intermediate",
    time: "8 min",
    icon: Globe,
    content: {
      objectives: [
        "Recognize structural anomalies in outbound DNS requests",
        "Identify high-entropy domain structures",
        "Audit heavy TXT and CNAME payload delivery records"
      ],
      body: "DNS is the internet's directory, and is rarely blocked. This makes it a prime vehicle for evasion. Security analysts search for anomalies such as exceptionally long, high-entropy query names (e.g., 'a7f9c2d5.c2.example.com') requesting unusual record types like TXT or CNAME. These records often carry encoded command strings or configuration files. Additionally, look for periodic query pacing (beaconing) targeting single domains.",
      keyTerms: [
        { term: "Entropy", definition: "A mathematical measure of randomness in a string of characters." },
        { term: "TXT Record", definition: "A DNS record allowing administrators to insert arbitrary human/machine text." }
      ],
      defensiveTips: [
        "Implement strict external DNS query logging.",
        "Block recursive lookups to unverified public DNS resolvers."
      ],
      relatedViews: ["Protocol Intelligence", "Signals & Observations"]
    }
  },
  {
    id: 3,
    title: "HTTP Cleartext Exposure",
    shortDesc: "Recognize the severe cryptographic weaknesses of unencrypted protocol headers and plain text content.",
    difficulty: "Beginner",
    time: "6 min",
    icon: Terminal,
    content: {
      objectives: [
        "Discover security flaws of unencrypted headers",
        "Trace plaintext credentials within POST requests",
        "Audit sensitive form actions across local web hosts"
      ],
      body: "Hypertext Transfer Protocol (HTTP) is completely unencrypted by default. Any middlebox, proxy, or packet capturer along the network path can view and parse the full transmission. This includes request paths, Cookie headers, and POST parameter request bodies. Analysts check for legacy web panels, configuration transfers, or internal management utilities still operating on port 80.",
      keyTerms: [
        { term: "Plaintext", definition: "Raw, unencrypted data readable by any protocol analyzer." },
        { term: "POST Request", definition: "An HTTP method used to send form data or payloads to a server." }
      ],
      defensiveTips: [
        "Transition all legacy systems to HTTPS.",
        "Implement HTTP Strict Transport Security (HSTS) headers."
      ],
      relatedViews: ["Protocol Intelligence", "AI Analyst Memo"]
    }
  },
  {
    id: 4,
    title: "TLS Handshake Basics",
    shortDesc: "Analyze Client Hello/Server Hello properties, cipher suite negotiation, and JA3/JA4 cryptographic fingerprints.",
    difficulty: "Analyst",
    time: "10 min",
    icon: Lock,
    content: {
      objectives: [
        "Trace the cryptographic handshake sequence",
        "Read Server Name Indication (SNI) hostnames",
        "Utilize JA3 client fingerprints to identify automated agents"
      ],
      body: "Transport Layer Security (TLS) encrypts application payloads, but the early handshake remains visible. The client transmits a Client Hello containing supported cipher suites and a Server Name Indication (SNI) indicating the destination domain. The server responds with a Server Hello and its digital certificate. Analysts use JA3 hashes to fingerprint client software based on these cipher selections—allowing identification of automated command scripts or custom utilities without breaking encryption.",
      keyTerms: [
        { term: "Client Hello", definition: "The initial packet sent by a client to propose TLS settings." },
        { term: "SNI Extension", definition: "A TLS extension showing the server's hostname before encryption begins." }
      ],
      defensiveTips: [
        "Monitor JA3 hashes against known baseline software lists.",
        "Alert on mismatched SNIs and HTTP Host headers."
      ],
      relatedViews: ["Protocol Intelligence", "Signals & Observations"]
    }
  },
  {
    id: 5,
    title: "Interpreting Severity & Confidence",
    shortDesc: "Calibrate threat signal alerts using structural metrics rather than relying on binary labels.",
    difficulty: "Intermediate",
    time: "5 min",
    icon: Shield,
    content: {
      objectives: [
        "Understand the context of security threat signals",
        "Evaluate true vs false positives based on host configurations",
        "Calibrate operational priority with high certainty metrics"
      ],
      body: "Automated detection engines generate alerts, but an analyst must calibrate them. Severity indicates the potential impact of an alert, whereas Confidence represents the statistical certainty that the alert represents true, verified behavior. For instance, a signature matching a legacy vulnerability on a system that is fully patched represents a false positive—or high severity, but near-zero operational confidence.",
      keyTerms: [
        { term: "Severity", definition: "The damage weight of a security signal if validated." },
        { term: "Confidence", definition: "The probability of the alert being true rather than noise." }
      ],
      defensiveTips: [
        "Never escalate alerts based on severity alone.",
        "Investigate the logical context, endpoint status, and protocol relevance first."
      ],
      relatedViews: ["Signals & Observations", "Command Center"]
    }
  },
  {
    id: 6,
    title: "Reconstructing Incident Timelines",
    shortDesc: "Synthesize disparate connection, intrusion, and system logs into a chronological order of events.",
    difficulty: "Analyst",
    time: "12 min",
    icon: Clock,
    content: {
      objectives: [
        "Align cross-protocol events chronologically",
        "Identify the sequence of threat-consistent activities",
        "Isolate the temporal pivot point of a network incident"
      ],
      body: "Incident reconstruction relies on establishing a reliable chronology of events. Analysts collect timestamps across network, firewall, and endpoint logs. Because time drift is common, identify a reliable pivot point (like a validated high-confidence intrusion signal) and align surrounding flows around it. Map the progression: initial DNS lookups, TCP handshakes, payload exchange, and subsequent secondary connections.",
      keyTerms: [
        { term: "Chronology", definition: "The arrangement of network logs in order of occurrence." },
        { term: "Time Drift", definition: "The slight offset between clocks of different networking hardware." }
      ],
      defensiveTips: [
        "Ensure all servers and network taps synchronize to a reliable NTP pool.",
        "Include both preceding and succeeding flows in timeline queries."
      ],
      relatedViews: ["Incident Timeline", "Flow Explorer"]
    }
  },
  {
    id: 7,
    title: "Evidence-backed Reporting",
    shortDesc: "Compose rigorous security summaries citing exact packet numbers, protocols, and timestamps without speculation.",
    difficulty: "Intermediate",
    time: "8 min",
    icon: FileText,
    content: {
      objectives: [
        "State investigative findings objectively and factually",
        "Reference specific frame numbers and exact byte counts",
        "Avoid speculative and qualitative vocabulary"
      ],
      body: "Security reports serve as formal records for legal, compliance, and engineering teams. A professional report must be factual, quantitative, and directly citation-backed. Avoid qualitative adjectives (e.g., 'massive attacks', 'suspicious requests'). Instead, state exact measurements: 'Host A initiated 1,420 connection attempts to external IP address B within 12 seconds.' Always include packet counts, port numbers, and UTC timestamps.",
      keyTerms: [
        { term: "Objective Evidence", definition: "Concrete, verifiable facts derived directly from log frames." },
        { term: "Specious Assertions", definition: "Plausible-sounding but unproven assumptions about incident root causes." }
      ],
      defensiveTips: [
        "Quote raw packet headers and packet-capture identifiers in your narrative.",
        "Avoid guessing attacker identities or motivations in official reports."
      ],
      relatedViews: ["Report Builder", "AI Analyst Memo"]
    }
  },
  {
    id: 8,
    title: "What Network Evidence Cannot Prove",
    shortDesc: "Understand the architectural blind spots of flow logs, encrypted payloads, and lateral visibility gaps.",
    difficulty: "Analyst",
    time: "7 min",
    icon: HelpCircle,
    content: {
      objectives: [
        "Recognize the inherent visibility gaps of network-only telemetry",
        "Identify signs of local credential abuse beyond network visibility",
        "Understand the end-to-end limits of encrypted flows"
      ],
      body: "Network logs provide peerless traffic visibility, but they have key architectural limits. A network capture can prove that host A connected to host B and downloaded 50MB of data on Port 443. It cannot prove: who was sitting at the physical keyboard, whether the local execution was authorized, or what specific local files were accessed. Always integrate network logs with host-based audits, endpoint detection and response (EDR) records, and identity logs.",
      keyTerms: [
        { term: "Visibility Gap", definition: "Areas of activity (like local process execution) invisible to packet sensors." },
        { term: "Correlation", definition: "Combining network evidence with host and identity records to form a complete narrative." }
      ],
      defensiveTips: [
        "Explicitly state the boundaries of your forensic evidence.",
        "Note what remains unverified due to missing host-level telemetry."
      ],
      relatedViews: ["Report Builder", "Command Center"]
    }
  }
];

interface LearningModeProps {
  hasEvidence?: boolean;
  parsedData?: any;
}

export default function LearningMode({ hasEvidence = false, parsedData = null }: LearningModeProps) {
  const [activeModule, setActiveModule] = useState<'academy' | 'quiz' | 'filters'>('academy');
  const [userAnswers, setUserAnswers] = useState<Record<number, number>>({});
  const [submitted, setSubmitted] = useState(false);
  const [selectedLessonId, setSelectedLessonId] = useState<number | null>(null);
  const [completedLessons, setCompletedLessons] = useState<number[]>([]);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [activeQuestionId, setActiveQuestionId] = useState<number>(1);

  const handleSelectOption = (qId: number, oIdx: number) => {
    if (submitted) return;
    setUserAnswers(prev => ({ ...prev, [qId]: oIdx }));
    setActiveQuestionId(qId);
  };

  const handleQuizSubmit = () => {
    setSubmitted(true);
  };

  const handleQuizReset = () => {
    setUserAnswers({});
    setSubmitted(false);
    setActiveQuestionId(1);
  };

  const handleMarkAsComplete = (lessonId: number) => {
    if (!completedLessons.includes(lessonId)) {
      setCompletedLessons(prev => [...prev, lessonId]);
    }
    setSelectedLessonId(null);
  };

  const handleCopyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => {
      setCopiedText(null);
    }, 1500);
  };

  const quizScore = submitted
    ? quizQuestions.reduce((acc, q) => (userAnswers[q.id] === q.answerIndex ? acc + 1 : acc), 0)
    : 0;

  // Active evidence heuristics to highlight corresponding lessons
  const evidenceDnsCount = parsedData?.dns?.length || 0;
  const evidenceHttpCount = parsedData?.http?.length || 0;
  const evidenceTlsCount = parsedData?.tls?.length || 0;
  const evidenceSignalsCount = parsedData?.signals?.length || 0;

  return (
    <div id="learning-mode-workspace" className="space-y-6 font-sans">
      
      {/* Academy Header */}
      <div className="p-5 bg-surface rounded-2xl border border-border-subtle flex flex-col md:flex-row gap-5 items-start md:items-center justify-between shadow-sm">
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <BookMarked size={16} className="text-accent-primary" />
            Packet Academy
          </h3>
          <p className="text-xs text-text-secondary leading-relaxed">
            Learn how to interpret packet evidence, protocol behavior, and investigation findings inside PacketSage.
          </p>
        </div>

        {/* Tab Selector - Pill Row */}
        <div className="flex bg-canvas rounded-lg p-1 border border-border-subtle text-xs gap-1 shrink-0 w-full sm:w-auto">
          {[
            { id: 'academy', label: 'Core Lessons' },
            { id: 'quiz', label: 'Analyst Quiz' },
            { id: 'filters', label: 'Wireshark Cheatsheet' }
          ].map((tab) => {
            const isSelected = activeModule === tab.id;
            return (
              <button
                key={tab.id}
                id={`tab-button-${tab.id}`}
                onClick={() => {
                  setActiveModule(tab.id as any);
                  if (tab.id !== 'academy') setSelectedLessonId(null);
                }}
                className={`flex-1 sm:flex-initial px-4 py-1.5 rounded-md cursor-pointer transition-all font-semibold ${
                  isSelected
                    ? 'bg-surface text-accent-primary border border-border-subtle shadow-sm'
                    : 'text-text-muted hover:text-text-secondary'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Compact Learning Context Strip */}
      <div className="px-4 py-2.5 bg-accent-soft border border-border-subtle/60 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs text-text-secondary">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <BookOpen size={14} className="text-text-muted shrink-0" />
            <span className="text-text-muted font-medium">Modules:</span>
            <span className="bg-surface-muted px-2 py-0.5 rounded-md font-bold text-text-primary font-mono">8</span>
          </div>
          <span className="h-3 w-[1px] bg-border-subtle" />
          <div className="flex items-center gap-2">
            <Target size={14} className="text-text-muted shrink-0" />
            <span className="text-text-muted font-medium">Skill Focus:</span>
            <span className="text-text-primary font-semibold">Network Forensics</span>
          </div>
          <span className="h-3 w-[1px] bg-border-subtle" />
          <div className="flex items-center gap-2">
            <Compass size={14} className="text-text-muted shrink-0" />
            <span className="text-text-muted font-medium">Path:</span>
            <span className="text-status-info font-semibold">Analyst Foundations</span>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          {hasEvidence ? (
            <Unlock size={14} className="text-status-success shrink-0" />
          ) : (
            <Lock size={14} className="text-text-muted shrink-0" />
          )}
          <div className="flex items-center gap-1.5">
            <span className="text-text-muted font-medium">Evidence Integration:</span>
            <InfoPopover content="Sandbox learning profiles integrate standard PCAP, NetFlow, or event stream structures to help analysts practice identification skills." align="left" />
          </div>
          {hasEvidence ? (
            <span className="flex items-center gap-1 bg-status-success-bg border border-status-success/20 text-status-success px-2 py-0.5 rounded-md font-semibold text-[10px]">
              <Check size={10} /> Enabled
            </span>
          ) : (
            <span className="flex items-center gap-1 bg-status-warning-bg border border-status-warning/20 text-status-warning px-2 py-0.5 rounded-md font-semibold text-[10px]">
              <Lock size={10} /> Locked until evidence loads
            </span>
          )}
        </div>
      </div>

      {/* TAB 1: CORE LESSONS */}
      {activeModule === 'academy' && (() => {
        // Encapsulated helper to get custom difficulty indicator (dual-segment framed badge)
        const getDifficultyMeter = (difficulty: string) => {
          let levelCode = 'L1';
          let levelClass = 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/5';
          let label = 'BEGINNER';
          if (difficulty === 'Intermediate') {
            levelCode = 'L2';
            levelClass = 'text-amber-600 dark:text-amber-400 bg-amber-500/5';
            label = 'INTERMEDIATE';
          } else if (difficulty === 'Analyst') {
            levelCode = 'L3';
            levelClass = 'text-purple-600 dark:text-purple-400 bg-purple-500/5';
            label = 'ANALYST';
          }

          return (
            <div className="inline-flex items-center border border-border-subtle rounded-md overflow-hidden font-mono text-[9px] shadow-2xs">
              <span className="px-1.5 py-0.5 bg-surface-muted text-text-muted border-r border-border-subtle font-bold tracking-tight">
                {levelCode}
              </span>
              <span className={`px-2 py-0.5 font-bold tracking-wider ${levelClass}`}>
                {label}
              </span>
            </div>
          );
        };

        // Encapsulated helper to get custom micro-status indicator (with stronger contrast and visual weight)
        const getStatusIndicator = (isCompleted: boolean, isRecommended: boolean) => {
          if (isCompleted) {
            return (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md bg-emerald-600 dark:bg-emerald-700 text-white text-[9px] font-bold uppercase tracking-wider shadow-2xs border border-emerald-500/25">
                <Check size={10} className="stroke-[3]" /> Complete
              </span>
            );
          } else if (isRecommended) {
            return (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md bg-blue-600 dark:bg-blue-700 text-white text-[9px] font-bold uppercase tracking-wider shadow-2xs border border-blue-500/25">
                <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" /> Recommended
              </span>
            );
          } else {
            return (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-[9px] font-bold uppercase tracking-wider">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400" /> Staged
              </span>
            );
          }
        };

        return (
          <div id="academy-view" className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* Modules Grid - Left Span */}
            <div className="lg:col-span-2 space-y-6">
              
              {/* FEATURED MODULE: RECOMMENDED START */}
              {(() => {
                const m = lessonModules[0]; // Module 1: Reading Flow Records
                const Icon = m.icon;
                const isSelected = selectedLessonId === m.id;
                const isCompleted = completedLessons.includes(m.id);

                return (
                  <div className="space-y-2.5">
                    <div className="flex justify-between items-center select-none">
                      <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-text-muted">
                        RECOMMENDED START
                      </span>
                      <span className="text-[9px] text-accent-primary font-mono font-bold uppercase tracking-wider bg-accent-soft px-2 py-0.5 rounded border border-accent-primary/20">
                        Primary Entry Point
                      </span>
                    </div>

                    <div
                      id={`module-card-${m.id}`}
                      onClick={() => setSelectedLessonId(m.id)}
                      className={`p-4 bg-surface rounded-2xl border transition-all duration-300 cursor-pointer flex flex-col justify-between space-y-3 relative group ${
                        isSelected
                          ? 'border-accent-primary bg-accent-primary/5 ring-1 ring-accent-primary/25'
                          : 'border-accent-primary/50 hover:border-accent-primary hover:shadow-lg shadow-sm'
                      }`}
                    >
                      <div className="space-y-2.5">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-bold text-accent-primary font-mono tracking-wider">MOD 01</span>
                            <span className="w-1 h-1 rounded-full bg-accent-primary" />
                            <span className="text-[11px] font-bold text-text-primary uppercase tracking-wider">{m.title}</span>
                          </div>
                          {getStatusIndicator(isCompleted, true)}
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
                          <div className="md:col-span-7 flex gap-3">
                            <div className="p-2 rounded-lg bg-accent-soft text-accent-primary border border-accent-primary/10 transition-colors shrink-0">
                              <Icon size={16} className="stroke-[2.5]" />
                            </div>
                            <div className="space-y-0.5">
                              <p className="text-[11px] text-text-secondary leading-relaxed">
                                {m.shortDesc}
                              </p>
                            </div>
                          </div>

                          {/* Seamless inline Objectives list - no "card-inside-card" feel */}
                          <div className="md:col-span-5 border-t md:border-t-0 md:border-l border-border-subtle/60 pt-2.5 md:pt-0 md:pl-4 space-y-1">
                            <span className="text-[9px] font-bold text-text-muted uppercase tracking-wider block">Key Objectives:</span>
                            <ul className="space-y-1 text-[10.5px] text-text-secondary">
                              {m.content.objectives.slice(0, 2).map((obj, oIdx) => (
                                <li key={oIdx} className="flex items-start gap-1.5">
                                  <CheckCircle2 size={11} className="text-emerald-500 shrink-0 mt-0.5" />
                                  <span className="line-clamp-1">{obj}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </div>

                      <div className="pt-2.5 border-t border-border-subtle/40 flex items-center justify-between text-[10px]">
                        <div className="flex items-center gap-3">
                          {getDifficultyMeter(m.difficulty)}
                          <span className="h-2.5 w-[1px] bg-border-subtle/60" />
                          <span className="text-text-muted flex items-center gap-0.5 font-mono">
                            <Clock size={10} /> {m.time}
                          </span>
                        </div>
                        <span className="text-accent-primary font-bold uppercase tracking-wider text-[10px] flex items-center gap-0.5 group-hover:translate-x-0.5 transition-transform">
                          {isCompleted ? 'Review Lesson' : 'Begin First Lesson'} <ChevronRight size={11} />
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* GROUP 1: Network Protocol Foundations */}
              <div className="space-y-3">
                <div className="flex items-center gap-2 select-none">
                  <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-accent-primary bg-accent-soft px-1.5 py-0.5 rounded border border-accent-primary/10">01</span>
                  <span className="text-[11px] font-bold uppercase tracking-[0.16em] text-text-muted">
                    Network Protocol Foundations
                  </span>
                  <div className="h-[1px] bg-border-subtle/40 flex-1 ml-2" />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {lessonModules.slice(1, 4).map((m) => {
                    const Icon = m.icon;
                    const isSelected = selectedLessonId === m.id;
                    const isCompleted = completedLessons.includes(m.id);
                    const isRecommended = hasEvidence && (
                      (m.id === 2 && evidenceDnsCount > 0) ||
                      (m.id === 3 && evidenceHttpCount > 0) ||
                      (m.id === 4 && evidenceTlsCount > 0)
                    );

                    return (
                      <div
                        key={m.id}
                        id={`module-card-${m.id}`}
                        onClick={() => setSelectedLessonId(m.id)}
                        className={`p-3.5 bg-surface rounded-xl border transition-all duration-200 cursor-pointer flex flex-col justify-between space-y-3 relative group ${
                          isSelected
                            ? 'border-accent-primary bg-accent-primary/5 ring-1 ring-accent-primary/20'
                            : 'border-border-subtle hover:border-border-strong hover:shadow-md shadow-sm'
                        }`}
                      >
                        <div className="space-y-2.5">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-bold text-accent-primary font-mono tracking-wider">
                              MOD {String(m.id).padStart(2, '0')}
                            </span>
                            {getStatusIndicator(isCompleted, !!isRecommended)}
                          </div>

                          <div className="flex items-start gap-2.5">
                            <div className="p-1.5 rounded-lg bg-surface-muted text-text-primary group-hover:bg-accent-primary/15 group-hover:text-accent-primary transition-colors shrink-0 mt-0.5 border border-border-subtle/40">
                              <Icon size={13} />
                            </div>
                            <div className="space-y-0.5">
                              <h4 className="text-[11.5px] font-bold text-text-primary group-hover:text-accent-primary transition-colors leading-snug line-clamp-1">
                                {m.title}
                              </h4>
                              <p className="text-[10.5px] text-text-secondary leading-relaxed line-clamp-2">
                                {m.shortDesc}
                              </p>
                            </div>
                          </div>
                        </div>

                        <div className="pt-2.5 border-t border-border-subtle/40 flex items-center justify-between text-[10px]">
                          <div className="flex items-center gap-2">
                            {getDifficultyMeter(m.difficulty)}
                            <span className="h-2.5 w-[1px] bg-border-subtle/60" />
                            <span className="text-text-muted flex items-center gap-0.5 font-mono">
                              <Clock size={10} /> {m.time}
                            </span>
                          </div>
                          <span className="inline-flex items-center gap-0.5 px-2 py-0.5 bg-accent-soft/45 border border-accent-primary/20 rounded font-bold text-[9.5px] text-accent-primary uppercase tracking-wider group-hover:bg-accent-primary group-hover:text-white group-hover:border-accent-primary transition-all duration-250">
                            {isCompleted ? 'Review' : 'Start'} <ChevronRight size={10} />
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* GROUP 2: Traffic Interpretation */}
              <div className="space-y-3">
                <div className="flex items-center gap-2 select-none">
                  <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-accent-primary bg-accent-soft px-1.5 py-0.5 rounded border border-accent-primary/10">02</span>
                  <span className="text-[11px] font-bold uppercase tracking-[0.16em] text-text-muted">
                    Traffic Interpretation
                  </span>
                  <div className="h-[1px] bg-border-subtle/40 flex-1 ml-2" />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {lessonModules.slice(4, 6).map((m) => {
                    const Icon = m.icon;
                    const isSelected = selectedLessonId === m.id;
                    const isCompleted = completedLessons.includes(m.id);
                    const isRecommended = hasEvidence && (
                      m.id === 5 && evidenceSignalsCount > 0
                    );

                    return (
                      <div
                        key={m.id}
                        id={`module-card-${m.id}`}
                        onClick={() => setSelectedLessonId(m.id)}
                        className={`p-3.5 bg-surface rounded-xl border transition-all duration-200 cursor-pointer flex flex-col justify-between space-y-3 relative group ${
                          isSelected
                            ? 'border-accent-primary bg-accent-primary/5 ring-1 ring-accent-primary/20'
                            : 'border-border-subtle hover:border-border-strong hover:shadow-md shadow-sm'
                        }`}
                      >
                        <div className="space-y-2.5">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-bold text-accent-primary font-mono tracking-wider">
                              MOD {String(m.id).padStart(2, '0')}
                            </span>
                            {getStatusIndicator(isCompleted, !!isRecommended)}
                          </div>

                          <div className="flex items-start gap-2.5">
                            <div className="p-1.5 rounded-lg bg-surface-muted text-text-primary group-hover:bg-accent-primary/15 group-hover:text-accent-primary transition-colors shrink-0 mt-0.5 border border-border-subtle/40">
                              <Icon size={13} />
                            </div>
                            <div className="space-y-0.5">
                              <h4 className="text-[11.5px] font-bold text-text-primary group-hover:text-accent-primary transition-colors leading-snug line-clamp-1">
                                {m.title}
                              </h4>
                              <p className="text-[10.5px] text-text-secondary leading-relaxed line-clamp-2">
                                {m.shortDesc}
                              </p>
                            </div>
                          </div>
                        </div>

                        <div className="pt-2.5 border-t border-border-subtle/40 flex items-center justify-between text-[10px]">
                          <div className="flex items-center gap-2">
                            {getDifficultyMeter(m.difficulty)}
                            <span className="h-2.5 w-[1px] bg-border-subtle/60" />
                            <span className="text-text-muted flex items-center gap-0.5 font-mono">
                              <Clock size={10} /> {m.time}
                            </span>
                          </div>
                          <span className="inline-flex items-center gap-0.5 px-2 py-0.5 bg-accent-soft/45 border border-accent-primary/20 rounded font-bold text-[9.5px] text-accent-primary uppercase tracking-wider group-hover:bg-accent-primary group-hover:text-white group-hover:border-accent-primary transition-all duration-250">
                            {isCompleted ? 'Review' : 'Start'} <ChevronRight size={10} />
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* GROUP 3: Evidence-Backed Reporting */}
              <div className="space-y-3">
                <div className="flex items-center gap-2 select-none">
                  <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-accent-primary bg-accent-soft px-1.5 py-0.5 rounded border border-accent-primary/10">03</span>
                  <span className="text-[11px] font-bold uppercase tracking-[0.16em] text-text-muted">
                    Evidence-Backed Reporting
                  </span>
                  <div className="h-[1px] bg-border-subtle/40 flex-1 ml-2" />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {lessonModules.slice(6).map((m) => {
                    const Icon = m.icon;
                    const isSelected = selectedLessonId === m.id;
                    const isCompleted = completedLessons.includes(m.id);
                    const isRecommended = hasEvidence && (
                      m.id === 6 && hasEvidence
                    );

                    return (
                      <div
                        key={m.id}
                        id={`module-card-${m.id}`}
                        onClick={() => setSelectedLessonId(m.id)}
                        className={`p-3.5 bg-surface rounded-xl border transition-all duration-200 cursor-pointer flex flex-col justify-between space-y-3 relative group ${
                          isSelected
                            ? 'border-accent-primary bg-accent-primary/5 ring-1 ring-accent-primary/20'
                            : 'border-border-subtle hover:border-border-strong hover:shadow-md shadow-sm'
                        }`}
                      >
                        <div className="space-y-2.5">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-bold text-accent-primary font-mono tracking-wider">
                              MOD {String(m.id).padStart(2, '0')}
                            </span>
                            {getStatusIndicator(isCompleted, !!isRecommended)}
                          </div>

                          <div className="flex items-start gap-2.5">
                            <div className="p-1.5 rounded-lg bg-surface-muted text-text-primary group-hover:bg-accent-primary/15 group-hover:text-accent-primary transition-colors shrink-0 mt-0.5 border border-border-subtle/40">
                              <Icon size={13} />
                            </div>
                            <div className="space-y-0.5">
                              <h4 className="text-[11.5px] font-bold text-text-primary group-hover:text-accent-primary transition-colors leading-snug line-clamp-1">
                                {m.title}
                              </h4>
                              <p className="text-[10.5px] text-text-secondary leading-relaxed line-clamp-2">
                                {m.shortDesc}
                              </p>
                            </div>
                          </div>
                        </div>

                        <div className="pt-2.5 border-t border-border-subtle/40 flex items-center justify-between text-[10px]">
                          <div className="flex items-center gap-2">
                            {getDifficultyMeter(m.difficulty)}
                            <span className="h-2.5 w-[1px] bg-border-subtle/60" />
                            <span className="text-text-muted flex items-center gap-0.5 font-mono">
                              <Clock size={10} /> {m.time}
                            </span>
                          </div>
                          <span className="inline-flex items-center gap-0.5 px-2 py-0.5 bg-accent-soft/45 border border-accent-primary/20 rounded font-bold text-[9.5px] text-accent-primary uppercase tracking-wider group-hover:bg-accent-primary group-hover:text-white group-hover:border-accent-primary transition-all duration-250">
                            {isCompleted ? 'Review' : 'Start'} <ChevronRight size={10} />
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

            </div>

            {/* Side Panel: Recommended Path or Active Lesson Reader */}
            <div className="space-y-4">
              {selectedLessonId === null ? (
                // Default Path Overview Panel
                <div className="p-5 bg-surface rounded-2xl border border-border-subtle space-y-5 shadow-sm">
                  <div className="space-y-1">
                    <h4 className="text-xs font-bold uppercase tracking-[0.12em] text-text-muted">
                      Syllabus Path
                    </h4>
                    <p className="text-[11px] text-text-secondary leading-relaxed">
                      Follow the verified instructional hierarchy to advance your forensic analysis capabilities.
                    </p>
                  </div>

                  {/* Structured Path Map */}
                  <div className="space-y-3 relative before:absolute before:left-3 before:top-2 before:bottom-2 before:w-[1px] before:bg-border-subtle">
                    {[
                      { step: '01', title: 'Reading Flow Records', id: 1, desc: 'Foundation pillar' },
                      { step: '02', title: 'DNS Query Patterns', id: 2, desc: 'Core correlation' },
                      { step: '07', title: 'Evidence-backed Reporting', id: 7, desc: 'Synthesis phase' }
                    ].map((pathStep, idx) => {
                      const isStepCompleted = completedLessons.includes(pathStep.id);
                      let styleClass = 'bg-surface-muted text-text-muted border-border-subtle';
                      if (isStepCompleted) {
                        styleClass = 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/35';
                      } else if (idx === 0 || selectedLessonId === pathStep.id) {
                        styleClass = 'bg-accent-primary/15 text-accent-primary border-accent-primary/35';
                      }
                      return (
                        <div key={idx} className="flex items-start gap-3 relative">
                          <div className={`w-6 h-6 rounded-full text-[10px] font-bold flex items-center justify-center shrink-0 border z-10 ${styleClass}`}>
                            {isStepCompleted ? <Check size={11} className="stroke-[3]" /> : pathStep.step}
                          </div>
                          <div className="pt-0.5 min-w-0">
                            <span className="text-xs font-bold text-text-primary block truncate">{pathStep.title}</span>
                            <span className="text-[10px] text-text-muted">
                              {pathStep.desc}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Live Evidence Correlation Board */}
                  <div className="pt-4 border-t border-border-subtle/60 space-y-3">
                    <span className="text-[10px] font-bold uppercase tracking-[0.12em] text-status-info flex items-center gap-1">
                      <Sparkles size={11} className="text-status-info" />
                      Evidence-Linked Guidance
                    </span>

                    {!hasEvidence ? (
                      <div className="rounded-xl border border-accent-primary/20 bg-accent-soft p-3.5 text-[11px] leading-relaxed text-text-muted flex gap-2">
                        <Info size={14} className="text-status-info shrink-0 mt-0.5" />
                        <div>
                          <strong>Load forensic logs</strong> in the Import tab to unlock context-aware lessons mapping to active protocols.
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-2.5">
                        <p className="text-[11px] text-text-secondary">
                          We matched your active dataset against standard forensic signatures. Prioritize the following modules:
                        </p>
                        
                        <div className="space-y-2">
                          {evidenceDnsCount > 0 && (
                            <div onClick={() => setSelectedLessonId(2)} className="p-2 bg-surface-muted rounded-lg border border-border-subtle hover:border-accent-primary/50 cursor-pointer text-[11px] flex justify-between items-center">
                              <span className="text-text-primary font-semibold">★ DNS Query Patterns</span>
                              <span className="text-status-info font-mono text-[10px]">{evidenceDnsCount} Queries</span>
                            </div>
                          )}
                          {evidenceHttpCount > 0 && (
                            <div onClick={() => setSelectedLessonId(3)} className="p-2 bg-surface-muted rounded-lg border border-border-subtle hover:border-accent-primary/50 cursor-pointer text-[11px] flex justify-between items-center">
                              <span className="text-text-primary font-semibold">★ HTTP Cleartext Exposure</span>
                              <span className="text-status-info font-mono text-[10px]">{evidenceHttpCount} Clear</span>
                            </div>
                          )}
                          {evidenceTlsCount > 0 && (
                            <div onClick={() => setSelectedLessonId(4)} className="p-2 bg-surface-muted rounded-lg border border-border-subtle hover:border-accent-primary/50 cursor-pointer text-[11px] flex justify-between items-center">
                              <span className="text-text-primary font-semibold">★ TLS Handshake Basics</span>
                              <span className="text-status-info font-mono text-[10px]">{evidenceTlsCount} Handshakes</span>
                            </div>
                          )}
                          {evidenceSignalsCount > 0 && (
                            <div onClick={() => setSelectedLessonId(5)} className="p-2 bg-surface-muted rounded-lg border border-border-subtle hover:border-accent-primary/50 cursor-pointer text-[11px] flex justify-between items-center">
                              <span className="text-text-primary font-semibold">★ Severity & Confidence</span>
                              <span className="text-status-warning font-mono text-[10px]">{evidenceSignalsCount} Alerts</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                // Active Lesson Reader Panel
                (() => {
                  const activeLesson = lessonModules.find(m => m.id === selectedLessonId)!;
                  const isCompleted = completedLessons.includes(activeLesson.id);
                  return (
                    <div className="relative overflow-hidden p-5 bg-surface rounded-2xl border border-border-strong/80 space-y-4 shadow-md animate-in fade-in duration-200">
                      {/* Top border bar accent */}
                      <div className="absolute top-0 left-0 right-0 h-[3px] bg-accent-primary" />
                      
                      <div className="flex justify-between items-center pt-1">
                        <span className="text-[10px] font-bold text-accent-primary bg-accent-soft border border-accent-primary/20 px-2.5 py-0.5 rounded font-mono uppercase tracking-wider">
                          Module {String(activeLesson.id).padStart(2, '0')}
                        </span>
                        <button
                          onClick={() => setSelectedLessonId(null)}
                          className="p-1 rounded-md text-text-muted hover:text-text-primary hover:bg-surface-muted transition-colors cursor-pointer"
                          title="Close Lesson Details"
                        >
                          <X size={14} className="stroke-[2.5]" />
                        </button>
                      </div>

                      <div className="space-y-1.5">
                        <h4 className="text-sm font-bold text-text-primary leading-snug">{activeLesson.title}</h4>
                        <div className="flex items-center gap-2 text-[10px] text-text-muted font-mono">
                          <span className="font-bold text-accent-primary">{activeLesson.difficulty.toUpperCase()}</span>
                          <span className="text-border-strong/40">•</span>
                          <span className="flex items-center gap-0.5"><Clock size={10} /> {activeLesson.time} reading</span>
                        </div>
                      </div>

                      <div className="space-y-4 text-xs text-text-secondary leading-relaxed">
                        {/* Objectives */}
                        <div className="space-y-2 p-3.5 bg-surface-muted/65 rounded-xl border border-border-subtle/80">
                          <span className="text-[10px] font-bold text-text-muted uppercase tracking-[0.08em] block">Training Objectives</span>
                          <ul className="space-y-1.5 text-[11px]">
                            {activeLesson.content.objectives.map((obj, oIdx) => (
                              <li key={oIdx} className="flex items-start gap-2 text-text-secondary leading-relaxed">
                                <CheckCircle2 size={12} className="text-status-success shrink-0 mt-0.5" />
                                <span>{obj}</span>
                              </li>
                            ))}
                          </ul>
                        </div>

                        {/* Briefing Narrative (Body) */}
                        <div className="border-l-2 border-accent-primary pl-3 py-1 bg-accent-soft/20 rounded-r-lg">
                          <p className="text-[11.5px] text-text-secondary leading-relaxed font-serif italic">
                            "{activeLesson.content.body}"
                          </p>
                        </div>

                        {/* Key Terms */}
                        <div className="space-y-2">
                          <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-text-muted block">Core Concepts</span>
                          <div className="space-y-1.5">
                            {activeLesson.content.keyTerms.map((term, tIdx) => (
                              <div key={tIdx} className="p-2.5 bg-surface-muted/45 rounded-xl border border-border-subtle/40 hover:border-border-subtle transition-colors duration-150">
                                <strong className="text-accent-primary text-[11.5px] font-mono block tracking-tight">{term.term}</strong>
                                <p className="text-[10.5px] text-text-secondary mt-0.5 leading-relaxed">{term.definition}</p>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Analyst Tips */}
                        <div className="space-y-2 p-3 bg-indigo-500/5 dark:bg-indigo-500/10 border border-indigo-500/20 rounded-xl">
                          <span className="text-[10px] font-bold text-indigo-600 dark:text-indigo-400 uppercase tracking-[0.08em] flex items-center gap-1">
                            <Shield size={11} className="stroke-[2.5]" /> Defensive Advisory
                          </span>
                          <ul className="space-y-1 text-[11px] list-disc pl-3 text-text-secondary leading-relaxed">
                            {activeLesson.content.defensiveTips.map((tip, tIdx) => (
                              <li key={tIdx}>{tip}</li>
                            ))}
                          </ul>
                        </div>

                        {/* Related Modules */}
                        <div className="flex items-center gap-1.5 flex-wrap pt-1 text-[10px]">
                          <span className="text-[9px] font-bold text-text-muted uppercase tracking-[0.08em]">Explore Views:</span>
                          {activeLesson.content.relatedViews.map((view, vIdx) => (
                            <span key={vIdx} className="bg-surface-muted border border-border-subtle/50 px-2 py-0.5 rounded text-[10px] font-mono font-bold text-text-secondary">
                              {view}
                            </span>
                          ))}
                        </div>
                      </div>

                      {isCompleted ? (
                        <div className="space-y-2">
                          <div className="w-full py-2.5 bg-emerald-600 dark:bg-emerald-700 text-white font-bold rounded-lg text-xs flex items-center justify-center gap-1.5 shadow-sm border border-emerald-500/25">
                            <Check size={13} className="stroke-[3]" />
                            Module Completed
                          </div>
                          <button
                            onClick={() => {
                              setCompletedLessons(prev => prev.filter(id => id !== activeLesson.id));
                            }}
                            className="w-full text-center text-[10px] text-text-muted hover:text-text-primary underline cursor-pointer transition-colors duration-150"
                          >
                            Reset progress for this module
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => handleMarkAsComplete(activeLesson.id)}
                          className="w-full py-2.5 bg-accent-primary hover:bg-accent-primary/95 text-white font-bold rounded-lg text-xs transition-all flex items-center justify-center gap-1.5 cursor-pointer shadow-sm active:scale-[0.98]"
                        >
                          <CheckCircle2 size={13} />
                          Verify & Complete Lesson
                        </button>
                      )}
                    </div>
                  );
                })()
              )}
            </div>

          </div>
        );
      })()}

      {/* TAB 2: ANALYST QUIZ */}
      {activeModule === 'quiz' && (
        <div id="quiz-view" className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in duration-200">
          
          {/* Main Quiz Area */}
          <div className="lg:col-span-2 space-y-4">
            
            {/* Top Compact Summary Row */}
            <div className="p-4 bg-surface rounded-2xl border border-border-subtle flex flex-col gap-3.5 select-none relative overflow-hidden shadow-xs">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
                  <div className="whitespace-nowrap flex items-center gap-1">
                    <span className="text-text-muted">Questions:</span>
                    <span className="font-bold text-text-primary font-mono bg-surface-muted px-2 py-0.5 rounded text-[11px]">5</span>
                  </div>
                  <span className="h-3 w-[1px] bg-border-subtle hidden sm:inline" />
                  <div className="whitespace-nowrap flex items-center gap-1">
                    <span className="text-text-muted">Focus:</span>
                    <span className="font-bold text-text-primary">Defensive Practice</span>
                  </div>
                  <span className="h-3 w-[1px] bg-border-subtle hidden sm:inline" />
                  <div className="whitespace-nowrap flex items-center gap-1.5">
                    <span className="text-text-muted">Level:</span>
                    <span className="font-mono text-[9px] font-bold text-purple-600 dark:text-purple-400 bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 rounded-md whitespace-nowrap">ANALYST FOUNDATIONS</span>
                  </div>
                </div>

                {/* Progress & Navigation Chips */}
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-text-muted font-bold uppercase tracking-wider font-mono">
                    {submitted ? 'Review Case Files:' : `${Object.keys(userAnswers).length} of 5 Answered:`}
                  </span>
                  <div className="flex gap-1.5">
                    {quizQuestions.map((q) => {
                      const isSelected = activeQuestionId === q.id;
                      const isAnswered = userAnswers[q.id] !== undefined;
                      const isCorrect = submitted && userAnswers[q.id] === q.answerIndex;

                      let chipStyle = "bg-surface border-border-subtle text-text-muted hover:border-border-strong hover:text-text-secondary";
                      
                      if (isSelected) {
                        chipStyle = "bg-accent-primary text-white border-accent-primary shadow-xs font-bold ring-2 ring-accent-primary/20";
                      } else if (submitted) {
                        if (isCorrect) {
                          chipStyle = "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 font-bold";
                        } else {
                          chipStyle = "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30 font-bold";
                        }
                      } else if (isAnswered) {
                        chipStyle = "bg-accent-soft/30 text-accent-primary border-accent-primary/20";
                      }

                      return (
                        <button
                          key={q.id}
                          onClick={() => setActiveQuestionId(q.id)}
                          className={`w-7 h-7 flex items-center justify-center text-xs rounded-lg border font-mono transition-all duration-150 cursor-pointer ${chipStyle}`}
                        >
                          {q.id}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Slim Progress Bar */}
              <div className="w-full h-1 bg-canvas rounded-full overflow-hidden border border-border-subtle/30">
                <div 
                  className="h-full bg-accent-primary transition-all duration-500 ease-out rounded-full" 
                  style={{ width: `${(Object.keys(userAnswers).length / 5) * 100}%` }}
                />
              </div>
            </div>

            {/* Questions list */}
            <div className="space-y-4">
              {quizQuestions.map((q, qIdx) => {
                const selectedOpt = userAnswers[q.id];
                const isCorrect = selectedOpt === q.answerIndex;
                const isAnswered = selectedOpt !== undefined;
                const isActive = activeQuestionId === q.id;
                const topicInfo = questionTopics[q.id];

                return (
                  <div
                    key={q.id}
                    id={`quiz-question-${q.id}`}
                    onClick={() => setActiveQuestionId(q.id)}
                    className={`p-5 rounded-2xl border transition-all duration-300 space-y-4 shadow-sm relative overflow-hidden cursor-pointer ${
                      isActive 
                        ? 'border-accent-primary/50 bg-accent-soft/5 dark:bg-accent-soft/10' 
                        : 'border-border-subtle bg-surface/80 hover:border-border-strong hover:bg-surface'
                    }`}
                  >
                    {/* Left vertical indicator for active case */}
                    {isActive && (
                      <div className="absolute left-0 top-0 bottom-0 w-[3px] bg-accent-primary" />
                    )}

                    {/* Case Header */}
                    <div className="flex justify-between items-center select-none pb-2 border-b border-border-subtle/40">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] font-bold text-accent-primary bg-accent-soft px-2 py-0.5 rounded border border-accent-primary/10">
                          CASE 0{q.id}
                        </span>
                        <span className="font-mono text-[10px] font-bold text-text-muted tracking-wider uppercase">
                          {topicInfo.tag}
                        </span>
                      </div>

                      {/* Status indicator */}
                      <div>
                        {submitted ? (
                          isCorrect ? (
                            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider border bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20">
                              Correct
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider border bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20">
                              Needs Review
                            </span>
                          )
                        ) : isAnswered ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/15 text-[9px] font-bold uppercase tracking-wider font-mono">
                            Answered
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-slate-500/5 dark:bg-slate-500/10 border border-slate-300/40 dark:border-slate-700/40 text-text-muted text-[9px] font-bold uppercase tracking-wider font-mono">
                            Unanswered
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Case Prompt */}
                    <div className="space-y-1">
                      <span className="text-[9px] font-bold text-text-muted uppercase tracking-[0.1em] block">Analyst Prompt</span>
                      <p className="text-[12.5px] font-medium text-text-primary leading-relaxed">
                        {q.question}
                      </p>
                    </div>

                    {/* Options */}
                    <div className="space-y-2.5">
                      {q.options.map((opt, oIdx) => {
                        const isOptSelected = selectedOpt === oIdx;
                        const isOptCorrect = oIdx === q.answerIndex;
                        const optionLetter = ["A", "B", "C", "D"][oIdx];

                        let optionClass = "bg-canvas/50 border-border-subtle hover:bg-surface-muted hover:border-border-strong text-text-secondary";
                        let markerClass = "bg-surface-muted text-text-muted border-border-subtle";

                        if (isOptSelected) {
                          optionClass = "bg-accent-soft/20 border-accent-primary/50 text-text-primary font-semibold";
                          markerClass = "bg-accent-primary text-white border-accent-primary";
                        }

                        if (submitted) {
                          if (isOptCorrect) {
                            optionClass = "bg-emerald-500/5 dark:bg-emerald-500/10 border-emerald-500/50 text-emerald-800 dark:text-emerald-300 font-semibold";
                            markerClass = "bg-emerald-500 text-white border-emerald-500";
                          } else if (isOptSelected) {
                            optionClass = "bg-rose-500/5 dark:bg-rose-500/10 border-rose-500/50 text-rose-800 dark:text-rose-300 font-semibold";
                            markerClass = "bg-rose-500 text-white border-rose-500";
                          } else {
                            optionClass = "bg-canvas/20 border-border-subtle/40 text-text-muted opacity-60 cursor-not-allowed";
                            markerClass = "bg-canvas/40 text-text-muted border-border-subtle/20";
                          }
                        }

                        return (
                          <button
                            key={oIdx}
                            disabled={submitted}
                            onClick={(e) => {
                              e.stopPropagation(); // Avoid triggering double active question sets
                              handleSelectOption(q.id, oIdx);
                              setActiveQuestionId(q.id);
                            }}
                            className={`w-full text-left p-3.5 rounded-xl border text-xs transition-all duration-150 flex items-center justify-between cursor-pointer focus:outline-none focus:ring-1 focus:ring-accent-primary/20 ${optionClass}`}
                          >
                            <div className="flex items-center gap-3 pr-2">
                              {/* Option Letter Marker */}
                              <span className={`w-6 h-6 shrink-0 flex items-center justify-center font-mono text-[10.5px] font-bold rounded-md border transition-all ${markerClass}`}>
                                {optionLetter}
                              </span>
                              <span className="leading-relaxed">{opt}</span>
                            </div>
                            
                            {/* Right side check/selected indicator */}
                            <div className="shrink-0 ml-3">
                              {submitted ? (
                                isOptCorrect ? (
                                  <span className="flex items-center justify-center w-5 h-5 rounded-full bg-emerald-500 text-white shadow-2xs">
                                    <Check size={11} className="stroke-[3]" />
                                  </span>
                                ) : isOptSelected ? (
                                  <span className="flex items-center justify-center w-5 h-5 rounded-full bg-rose-500 text-white shadow-2xs">
                                    <X size={11} className="stroke-[3]" />
                                  </span>
                                ) : null
                              ) : isOptSelected ? (
                                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-accent-primary text-white shadow-2xs">
                                  <Check size={11} className="stroke-[3]" />
                                </span>
                              ) : (
                                <span className="w-5 h-5 rounded-full border border-border-subtle/80 block" />
                              )}
                            </div>
                          </button>
                        );
                      })}
                    </div>

                    {/* Explanation / Feedback (why this matters) */}
                    {submitted && (
                      <div className="p-4 bg-surface-muted rounded-xl border border-border-subtle text-xs leading-relaxed text-text-secondary animate-in fade-in duration-200 space-y-2 select-text">
                        <div className="flex items-center gap-1.5 font-bold">
                          {isCorrect ? (
                            <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1 text-[11px] uppercase tracking-wider font-mono">
                              Rigorous Interpretation
                            </span>
                          ) : (
                            <span className="text-rose-600 dark:text-rose-400 flex items-center gap-1 text-[11px] uppercase tracking-wider font-mono">
                              Analytical Oversight
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-text-secondary leading-relaxed">{q.explanation}</p>
                        
                        <div className="pt-2 border-t border-border-subtle/50 text-[10px] text-text-muted flex items-center gap-1.5">
                          <span className="font-bold uppercase tracking-wider text-[9px] text-text-muted shrink-0">Tested Competency:</span>
                          <span className="font-mono">{topicInfo.skill}</span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Anchored Quiz Action Footer */}
            <div className="p-4 bg-surface rounded-2xl border border-border-strong/70 flex flex-col sm:flex-row items-center justify-between gap-4 select-none shadow-sm mt-6">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-accent-soft text-accent-primary border border-accent-primary/10 rounded-lg">
                  <Shield size={16} />
                </div>
                <div>
                  <h5 className="text-xs font-bold text-text-primary">Defensive Self-Assessment</h5>
                  <p className="text-[10.5px] text-text-muted leading-tight">
                    {submitted 
                      ? `Assessment complete. Score: ${quizScore}/5 (${Math.round((quizScore / 5) * 100)}%).` 
                      : `${Object.keys(userAnswers).length} of 5 cases evaluated.`
                    }
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2.5 w-full sm:w-auto justify-end">
                {!submitted ? (
                  <button
                    onClick={handleQuizSubmit}
                    disabled={Object.keys(userAnswers).length < quizQuestions.length}
                    className="w-full sm:w-auto px-5 py-2.5 bg-accent-primary hover:bg-accent-primary/95 disabled:bg-surface-muted disabled:text-text-muted disabled:border-border-subtle disabled:cursor-not-allowed text-white font-bold rounded-lg text-xs cursor-pointer shadow-sm transition-all border border-transparent flex items-center justify-center gap-1.5 active:scale-[0.98]"
                  >
                    <CheckCircle2 size={13} />
                    {Object.keys(userAnswers).length < quizQuestions.length 
                      ? `Complete All Cases (${Object.keys(userAnswers).length}/5)` 
                      : "Submit Investigation Answers"
                    }
                  </button>
                ) : (
                  <button
                    onClick={handleQuizReset}
                    className="w-full sm:w-auto px-4 py-2 bg-canvas hover:bg-surface-muted text-text-primary font-bold rounded-lg text-xs border border-border-subtle cursor-pointer transition-all flex items-center justify-center gap-1.5"
                  >
                    <RefreshCw size={13} />
                    Reset Evaluation & Retry
                  </button>
                )}
              </div>
            </div>

            {/* Reassuring assist note */}
            <div className="rounded-xl border border-accent-primary/10 bg-accent-soft/10 px-4 py-3 text-[10.5px] leading-relaxed text-text-muted">
              <strong>Analyst Note:</strong> These assessment modules simulate technical forensics and defensive reasoning. Answers are for instructional training and do not modify current active evidence captures or database entries.
            </div>
          </div>

          {/* Quiz Takeaway Sidebar */}
          <div className="space-y-4">
            {/* Dynamic Active Case Guidance */}
            {(() => {
              const activeTopic = questionTopics[activeQuestionId];
              return (
                <div className="p-5 bg-surface rounded-2xl border border-border-subtle space-y-4 shadow-sm animate-in fade-in duration-200">
                  <div className="flex items-center gap-2">
                    <Layers size={14} className="text-accent-primary" />
                    <h4 className="text-xs font-bold uppercase tracking-[0.12em] text-text-primary">
                      Active Case Focus
                    </h4>
                  </div>
                  
                  <div className="space-y-3.5">
                    <div className="space-y-1 bg-surface-muted/50 p-3 rounded-xl border border-border-subtle/40">
                      <span className="text-[9px] font-bold text-text-muted uppercase tracking-[0.08em] block">Target Concept</span>
                      <span className="text-[11.5px] font-bold text-text-primary block leading-snug">{activeTopic.title}</span>
                      <span className="text-[10px] text-text-secondary block font-mono bg-canvas px-2 py-1 rounded border border-border-subtle/30 mt-1.5 w-fit">
                        {activeTopic.tag}
                      </span>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[9px] font-bold text-text-muted uppercase tracking-[0.08em] block">Core Forensic Competency</span>
                      <p className="text-[11px] text-text-secondary leading-relaxed">
                        {activeTopic.skill}
                      </p>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[9px] font-bold text-text-muted uppercase tracking-[0.08em] block">Why This Matters</span>
                      <p className="text-[11px] text-text-secondary leading-relaxed">
                        {activeTopic.whyMatters}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-border-subtle/40 space-y-2">
                      <span className="text-[9px] font-bold uppercase tracking-[0.08em] text-text-muted block">
                        Correlative Workspace Views
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {activeTopic.views.map((v, idx) => (
                          <span
                            key={idx}
                            className="inline-flex items-center gap-1 bg-surface-muted border border-border-subtle/70 px-2 py-1 rounded text-[10px] font-mono font-bold text-text-secondary"
                          >
                            {v}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* Analyst Reasoning Guide */}
            <div className="p-5 bg-surface rounded-2xl border border-border-subtle space-y-4 shadow-sm">
              <div className="flex items-center gap-2">
                <Shield size={14} className="text-accent-primary" />
                <div className="flex items-center gap-1.5">
                  <h4 className="text-xs font-bold uppercase tracking-[0.12em] text-text-primary">
                    Analyst Reasoning Guide
                  </h4>
                  <InfoPopover content="Quiz answers are evaluated against defensive packet-analysis reasoning, evidence boundaries, and analyst validation principles." align="left" />
                </div>
              </div>
              
              <div className="space-y-3.5 text-[11px] text-text-secondary leading-relaxed">
                <p>
                  As defensive network analysts, we adhere to absolute evidentiary standards. We document observable indicators, patterns, and packet sequences, avoiding speculation regarding host states.
                </p>

                <div className="space-y-2 border-l-2 border-accent-primary/30 pl-3">
                  <div className="text-[10.5px] font-medium text-text-primary">
                    Core Guidance:
                  </div>
                  <ul className="list-disc pl-4 space-y-1.5 text-text-muted">
                    <li>Document what the network evidence shows.</li>
                    <li>Avoid claiming host compromise without endpoint logs.</li>
                    <li>Use correlation language when evidence is incomplete.</li>
                  </ul>
                </div>
              </div>

              {/* Evidence Language Guide */}
              <div className="rounded-xl border border-border-subtle/80 bg-accent-soft/30 p-3.5 space-y-3">
                <span className="text-[10px] font-bold text-accent-primary uppercase tracking-[0.08em] block">
                  Evidence Language Guide
                </span>
                
                <div className="space-y-2.5 text-[10.5px]">
                  <div className="space-y-1 pb-2 border-b border-border-subtle/30">
                    <span className="text-status-error font-semibold uppercase tracking-wider text-[9px] block">Incomplete / Overclaiming</span>
                    <p className="text-text-muted font-mono bg-canvas p-1.5 rounded border border-border-subtle/30 text-[10px]">
                      "Malware confirmed on host, C2 server verified."
                    </p>
                  </div>
                  
                  <div className="space-y-1">
                    <span className="text-status-success font-semibold uppercase tracking-wider text-[9px] block">Rigorous Statement</span>
                    <p className="text-accent-primary font-mono bg-canvas p-1.5 rounded border border-border-subtle/30 text-[10px]">
                      "Outbound packet metrics are consistent with C2-related beacon patterns. Requires host endpoint correlation."
                    </p>
                  </div>
                </div>
              </div>

              {/* General Shortcuts to Interactive Views */}
              <div className="pt-3 border-t border-border-subtle/40 space-y-2.5">
                <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-text-muted block">
                  Applicable Forensic Tools
                </span>
                <div className="grid grid-cols-2 gap-1.5 text-[10px] font-mono">
                  <div className="bg-surface-muted p-1.5 rounded text-center text-text-secondary font-bold border border-border-subtle">Flow Explorer</div>
                  <div className="bg-surface-muted p-1.5 rounded text-center text-text-secondary font-bold border border-border-subtle">Protocol Intel</div>
                  <div className="bg-surface-muted p-1.5 rounded text-center text-text-secondary font-bold border border-border-subtle">Observations</div>
                  <div className="bg-surface-muted p-1.5 rounded text-center text-text-secondary font-bold border border-border-subtle">Timeline</div>
                </div>
              </div>
            </div>
          </div>

        </div>
      )}

      {/* TAB 3: WIRESHARK CHEATSHEET */}
      {activeModule === 'filters' && (() => {
        const firstFlowIp = parsedData?.flows?.[0]?.sourceIp || parsedData?.flows?.[0]?.destinationIp || "10.0.0.15";
        const firstDnsQuery = parsedData?.dns?.[0]?.query || "suspicious-lab.test";

        const categories = [
          {
            id: 'common',
            title: "A) Common display filters",
            icon: <Filter size={15} className="text-accent-primary shrink-0" />,
            items: [
              {
                title: "Filter TCP retransmissions",
                command: "tcp.analysis.retransmission",
                desc: "tracking reliability issues or network loss."
              },
              {
                title: "Filter large frame volumes",
                command: "frame.len > 1400",
                desc: "identifying potential fragmentation or MTU issues."
              },
              {
                title: "Filter specific IP conversation",
                command: `ip.addr == ${firstFlowIp}`,
                desc: "isolating traffic to/from a specific host."
              }
            ]
          },
          {
            id: 'dns_http',
            title: "B) DNS & HTTP investigation",
            icon: <Globe size={15} className="text-accent-primary shrink-0" />,
            items: [
              {
                title: "Filter targeted DNS queries",
                command: `dns.qry.name contains "${firstDnsQuery === 'suspicious-lab.test' ? 'example' : firstDnsQuery.split('.')[0]}"`,
                desc: "tracking lookups for suspicious or known domains."
              },
              {
                title: "Review HTTP POST requests",
                command: "http.request.method == \"POST\"",
                desc: "reviewing form submissions or data posts."
              },
              {
                title: "Review cleartext credential indicators",
                command: "http contains \"password\"",
                desc: "identifying potential credential exposure in cleartext."
              }
            ]
          },
          {
            id: 'tls',
            title: "C) TLS & handshake inspection",
            icon: <Lock size={15} className="text-accent-primary shrink-0" />,
            items: [
              {
                title: "Inspect SNI exposure",
                command: "tls.handshake.extensions_server_name",
                desc: "checking requested domains in TLS handshakes."
              },
              {
                title: "Filter TLS client hello",
                command: "tls.handshake.type == 1",
                desc: "analyzing client hello details and cipher suites."
              },
              {
                title: "Review encrypted web traffic",
                command: "tcp.port == 443",
                desc: "isolating HTTPS traffic for deeper inspection."
              }
            ]
          },
          {
            id: 'tcpdump',
            title: "D) tcpdump command templates",
            icon: <Terminal size={15} className="text-accent-primary shrink-0" />,
            items: [
              {
                title: "Read PCAP without resolving names",
                command: "tcpdump -nn -r traffic.pcap",
                desc: "avoiding DNS lookups during offline analysis."
              },
              {
                title: "Capture host traffic",
                command: `tcpdump host ${firstFlowIp}`,
                desc: "capturing traffic to/from a specific host."
              },
              {
                title: "Filter out DNS and NTP",
                command: "tcpdump -r traffic.pcap \"not port 53 and not port 123\"",
                desc: "reducing noise from common background services."
              }
            ]
          }
        ];

        return (
          <div id="filters-view" className="space-y-6">
            
            {/* Investigation Filter Reference Banner */}
            <div className="p-4 bg-surface rounded-2xl border border-border-subtle flex flex-col lg:flex-row lg:items-center justify-between gap-4 select-none shadow-sm">
              <div className="flex items-center gap-3.5">
                <div className="p-3 bg-accent-soft rounded-xl border border-accent-primary/10 text-accent-primary shrink-0">
                  <Search size={18} />
                </div>
                <div className="space-y-1">
                  <h4 className="text-xs font-bold text-text-primary uppercase tracking-wider">Investigation filter reference</h4>
                  <p className="text-xs text-text-secondary">
                    Copy-ready filters and capture commands for validating PacketSage findings in Wireshark or tcpdump.
                  </p>
                </div>
              </div>
              
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md bg-accent-soft text-accent-primary border border-accent-primary/10">
                  Wireshark filters
                </span>
                <span className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md bg-accent-soft text-accent-primary border border-accent-primary/10">
                  tcpdump commands
                </span>
                <span className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md bg-accent-soft text-accent-primary border border-accent-primary/10">
                  DNS / HTTP / TLS
                </span>
                <span className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                  <Shield size={11} />
                  Defensive inspection only
                </span>
              </div>
            </div>

            {/* Grid of Categories */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {categories.map((category) => (
                <div key={category.id} className="p-5 bg-surface rounded-2xl border border-border-subtle space-y-4 shadow-sm flex flex-col justify-between">
                  <div className="space-y-4">
                    <div className="flex items-center gap-2 select-none border-b border-border-subtle/40 pb-3">
                      {category.icon}
                      <h4 className="text-xs font-bold text-text-primary uppercase tracking-wider">{category.title}</h4>
                    </div>
                    
                    <div className="divide-y divide-border-subtle/40">
                      {category.items.map((item, idx) => (
                        <div key={idx} className="flex flex-col sm:flex-row sm:items-center justify-between py-3.5 first:pt-0 last:pb-0 gap-3">
                          <div className="space-y-0.5">
                            <div className="text-xs font-semibold text-text-primary">{item.title}</div>
                            <div className="text-[10.5px] text-text-muted">Use when: {item.desc}</div>
                          </div>
                          
                          <div className="flex items-center font-mono text-[11px] shrink-0 self-start sm:self-center">
                            <span className="bg-canvas/50 border border-border-subtle/60 border-r-0 px-2.5 py-1.5 rounded-l-lg text-status-info select-all max-w-[150px] sm:max-w-[200px] md:max-w-[250px] truncate" title={item.command}>
                              {item.command}
                            </span>
                            <button
                              onClick={() => handleCopyToClipboard(item.command)}
                              className="border border-border-subtle/60 px-2.5 py-1.5 rounded-r-lg bg-surface hover:bg-surface-muted text-[10px] font-medium text-text-secondary hover:text-text-primary cursor-pointer transition-colors flex items-center gap-1 font-sans active:scale-[0.98]"
                            >
                              {copiedText === item.command ? "Copied" : "Copy"}
                              {copiedText === item.command ? <Check size={11} className="text-emerald-500 stroke-[3]" /> : <Copy size={11} />}
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Bottom Workflow Helper Section */}
            <div className="p-5 bg-surface rounded-2xl border border-border-subtle space-y-4 shadow-sm select-none">
              <div className="flex items-center gap-3 border-b border-border-subtle/40 pb-3">
                <div className="p-2 bg-accent-soft rounded-lg text-accent-primary">
                  <Layers size={16} />
                </div>
                <h4 className="text-xs font-bold text-text-primary uppercase tracking-wider">From PacketSage to Wireshark</h4>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-7 gap-2 md:gap-4 items-center py-2">
                {/* Step 1 */}
                <div className="md:col-span-1 flex items-center gap-3 bg-canvas/30 p-3 rounded-xl border border-border-subtle/50 h-full">
                  <div className="w-6 h-6 rounded-full bg-accent-primary text-white text-xs font-bold flex items-center justify-center shrink-0">1</div>
                  <p className="text-[11px] text-text-secondary leading-tight font-semibold">Start from a signal, flow, or protocol event</p>
                </div>
                
                <div className="flex justify-center md:col-span-1">
                  <ArrowRight size={14} className="text-text-muted shrink-0 rotate-90 md:rotate-0" />
                </div>
                
                {/* Step 2 */}
                <div className="md:col-span-1 flex items-center gap-3 bg-canvas/30 p-3 rounded-xl border border-border-subtle/50 h-full">
                  <div className="w-6 h-6 rounded-full bg-accent-primary text-white text-xs font-bold flex items-center justify-center shrink-0">2</div>
                  <p className="text-[11px] text-text-secondary leading-tight font-semibold">Copy the relevant filter</p>
                </div>
                
                <div className="flex justify-center md:col-span-1">
                  <ArrowRight size={14} className="text-text-muted shrink-0 rotate-90 md:rotate-0" />
                </div>
                
                {/* Step 3 */}
                <div className="md:col-span-1 flex items-center gap-3 bg-canvas/30 p-3 rounded-xl border border-border-subtle/50 h-full">
                  <div className="w-6 h-6 rounded-full bg-accent-primary text-white text-xs font-bold flex items-center justify-center shrink-0">3</div>
                  <p className="text-[11px] text-text-secondary leading-tight font-semibold">Validate packet-level context</p>
                </div>
                
                <div className="flex justify-center md:col-span-1">
                  <ArrowRight size={14} className="text-text-muted shrink-0 rotate-90 md:rotate-0" />
                </div>
                
                {/* Step 4 */}
                <div className="md:col-span-1 flex items-center gap-3 bg-canvas/30 p-3 rounded-xl border border-border-subtle/50 h-full">
                  <div className="w-6 h-6 rounded-full bg-accent-primary text-white text-xs font-bold flex items-center justify-center shrink-0">4</div>
                  <p className="text-[11px] text-text-secondary leading-tight font-semibold">Add confirmed observations to report</p>
                </div>
              </div>
              
              {/* Context-aware information block */}
              <div className="mt-2 p-3 bg-accent-soft/30 border border-accent-primary/10 rounded-xl flex items-center gap-2.5 text-xs text-text-secondary">
                <Info size={14} className="text-accent-primary shrink-0" />
                {hasEvidence ? (
                  <p className="leading-normal">
                    <strong>Context-Aware Mode:</strong> Live evidence is active. Filters and IP queries have been updated with parameters from the active trace (<span className="font-mono text-[11px] bg-canvas/80 text-accent-primary px-1.5 py-0.5 rounded border border-border-subtle/30">{firstFlowIp}</span>, <span className="font-mono text-[11px] bg-canvas/80 text-accent-primary px-1.5 py-0.5 rounded border border-border-subtle/30">{firstDnsQuery}</span>).
                  </p>
                ) : (
                  <p className="text-text-muted leading-normal">
                    Load evidence to generate context-aware filters from active flows and signals. Currently displaying baseline templates.
                  </p>
                )}
              </div>
            </div>

          </div>
        );
      })()}
    </div>
  );
}
