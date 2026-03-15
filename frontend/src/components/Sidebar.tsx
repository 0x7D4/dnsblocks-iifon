import { LayoutGrid, Globe, ShieldAlert, BarChart3, Download } from 'lucide-react';
import { motion } from 'framer-motion';
const API_BASE = "http://127.0.0.1:8001";

export function Sidebar() {
    return (
        <div className="w-64 h-screen border-r border-[#333] bg-[#1a1a1a] flex flex-col p-6 flex-shrink-0">
            <div className="flex items-center gap-3 mb-10">
                <img src="/aiori-logo.png" alt="AIORI" className="w-8 h-8 rounded-md" />
                <span className="font-semibold text-xl tracking-tight text-white data-font">DNSBlocks</span>
            </div>

            <nav className="flex-1 space-y-2">
                <NavItem icon={<LayoutGrid size={20} />} label="Overview" active />
                <NavItem icon={<Globe size={20} />} label="ISPs" />
                <NavItem icon={<ShieldAlert size={20} />} label="Domains" />
                <NavItem icon={<BarChart3 size={20} />} label="Categories" />
            </nav>

            <div className="mt-auto">
                <a
                    href={`${API_BASE}/api/export`}
                    download
                    className="flex items-center justify-center gap-2 w-full py-3 px-4 rounded-lg bg-[#2a2a2a] hover:bg-[#333] transition-colors border border-[#444] text-[#ddd] text-sm font-medium hover:text-[#4daaf5] hover:border-[#4daaf5] group"
                >
                    <Download size={16} className="group-hover:translate-y-0.5 transition-transform" />
                    Export Report
                </a>
            </div>
        </div>
    );
}

function NavItem({ icon, label, active = false }: { icon: React.ReactNode, label: string, active?: boolean }) {
    return (
        <motion.button
            whileHover={{ x: 4 }}
            whileTap={{ scale: 0.98 }}
            className={`flex items-center gap-3 w-full p-3 rounded-lg text-sm font-medium transition-all ${active
                ? 'bg-[rgba(77,170,245,0.15)] text-[#4daaf5] border border-[rgba(77,170,245,0.3)]'
                : 'text-[#aaa] hover:text-white hover:bg-[#2a2a2a]'
                }`}>
            {icon}
            {label}
        </motion.button>
    );
}
