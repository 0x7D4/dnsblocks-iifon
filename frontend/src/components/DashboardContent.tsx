import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import axios from 'axios';
const API_BASE = "http://127.0.0.1:8001";

const COLORS = ['#0d7ff2', '#a855f7', '#f97316', '#22c55e', '#ef4444', '#eab308'];

export function DashboardContent() {
    const [summary, setSummary] = useState<any>(null);
    const [isps, setIsps] = useState<any[]>([]);
    const [notable, setNotable] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [errorMsg, setErrorMsg] = useState("");

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [sumRes, ispRes, notRes] = await Promise.all([
                    axios.get(`${API_BASE}/api/summary`),
                    axios.get(`${API_BASE}/api/isps`),
                    axios.get(`${API_BASE}/api/notable-domains`)
                ]);
                setSummary(sumRes.data);
                setIsps(ispRes.data);
                setNotable(notRes.data);
            } catch (e: any) {
                console.error(e);
                setErrorMsg(e.message || "Failed to fetch telemetry data");
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, []);

    if (errorMsg) return <div className="p-8 text-red-500 data-font">Error loading telemetry: {errorMsg}</div>;
    if (loading || !summary) return <div className="p-8 text-[#aaa] data-font">Loading telemetry...</div>;

    return (
        <div className="flex-1 overflow-y-auto p-8 bg-[#121212] relative">
            {/* Background ambient glows */}
            <div className="absolute top-0 left-1/4 w-96 h-96 bg-[#0d7ff2] rounded-full mix-blend-screen filter blur-[150px] opacity-10 pointer-events-none" />
            <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-[#a855f7] rounded-full mix-blend-screen filter blur-[150px] opacity-10 pointer-events-none" />

            <header className="mb-8 flex justify-between items-center z-10 relative">
                <div>
                    <h1 className="text-3xl font-bold text-white tracking-tight mb-2">Analysis Dashboard</h1>
                    <p className="text-[#888] text-sm">Real-time DNS Censorship Statistics & Comparisons</p>
                </div>
                <div className="flex items-center gap-4">
                    <div className="px-4 py-2 rounded-full glass text-sm font-medium text-[#4daaf5] border-[#0d7ff2]/30 flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-[#0d7ff2] animate-pulse" />
                        Live DB Connection
                    </div>
                </div>
            </header>

            {/* Bento Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8 z-10 relative">
                <MetricCard title="Total Domains Tested" value={summary.total_domains_tested?.toLocaleString()} color="#0d7ff2" delay={0.1} />
                <MetricCard title="Total Blocked" value={summary.total_blocked?.toLocaleString()} color="#ef4444" delay={0.2} />
                <MetricCard title="Unblocked" value={summary.unblocked?.toLocaleString()} color="#22c55e" delay={0.3} />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 z-10 relative">
                {/* Chart Section */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
                    className="lg:col-span-2 glass rounded-xl p-6 border border-[#2a2a2a]"
                >
                    <h3 className="text-lg font-semibold text-white mb-6">ISP Block Comparison</h3>
                    <div className="h-72">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={isps} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                                <XAxis dataKey="isp" stroke="#666" tick={{ fill: '#888', fontSize: 12 }} axisLine={false} tickLine={false} />
                                <YAxis stroke="#666" tick={{ fill: '#888', fontSize: 12 }} axisLine={false} tickLine={false} />
                                <Tooltip
                                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                                    contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333', borderRadius: '8px', color: '#fff' }}
                                />
                                <Bar dataKey="blocked" radius={[4, 4, 0, 0]}>
                                    {isps.map((_, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </motion.div>

                {/* Notable Domains Sidebar Table */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}
                    className="glass rounded-xl p-6 border border-[#2a2a2a] flex flex-col"
                >
                    <h3 className="text-lg font-semibold text-white mb-4">Notable Domains</h3>
                    <div className="flex-1 overflow-y-auto pr-2 space-y-3">
                        {notable.slice(0, 15).map((d: any, i: number) => (
                            <div key={i} className="p-3 rounded-lg bg-[#1a1a1a]/50 border border-[#333] hover:border-[#4daaf5]/50 transition-colors group">
                                <div className="flex justify-between items-start mb-2">
                                    <span className="text-[#eee] font-medium text-sm truncate">{d.domain}</span>
                                    <span className="text-xs text-[#888] bg-[#222] px-2 py-0.5 rounded">Rank: {d.tranco_rank || 'N/A'}</span>
                                </div>
                                <div className="flex flex-wrap gap-1">
                                    {d.blocked_by.map((isp: string, idx: number) => (
                                        <span key={idx} className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                                            {isp}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </motion.div>
            </div>
        </div>
    );
}

function MetricCard({ title, value, color, delay }: { title: string, value: string, color: string, delay: number }) {
    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay }}
            whileHover={{ y: -4, transition: { duration: 0.2 } }}
            className="glass p-6 rounded-xl border relative overflow-hidden group"
            style={{ borderColor: 'rgba(255,255,255,0.05)' }}
        >
            <div
                className="absolute top-0 left-0 w-full h-1 opacity-50 group-hover:opacity-100 transition-opacity"
                style={{ backgroundColor: color, boxShadow: `0 0 10px ${color}` }}
            />
            <h3 className="text-[#888] text-sm font-medium mb-2">{title}</h3>
            <p className="text-4xl font-bold tracking-tight text-white data-font">{value}</p>
        </motion.div>
    );
}
