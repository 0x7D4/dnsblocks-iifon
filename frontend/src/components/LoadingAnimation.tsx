import { motion } from "framer-motion";

export function LoadingAnimation({ onComplete }: { onComplete: () => void }) {
    return (
        <motion.div
            initial={{ opacity: 1 }}
            animate={{ opacity: 0 }}
            transition={{ duration: 0.8, delay: 2.5 }}
            onAnimationComplete={onComplete}
            className="fixed inset-0 z-50 flex items-center justify-center bg-[#101010]"
        >
            <motion.div
                initial={{ scale: 0.8, opacity: 0, filter: 'blur(10px)' }}
                animate={{ scale: 1, opacity: 1, filter: 'blur(0px)' }}
                transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
                className="flex flex-col items-center justify-center relative"
            >
                <motion.div
                    animate={{
                        boxShadow: [
                            "0px 0px 0px 0px rgba(77,170,245,0)",
                            "0px 0px 100px 30px rgba(77,170,245,0.4)",
                            "0px 0px 0px 0px rgba(77,170,245,0)"
                        ]
                    }}
                    transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                    className="rounded-2xl"
                >
                    <img src="/aiori-logo.png" alt="AIORI Logo" className="w-32 h-32 md:w-48 md:h-48 object-contain rounded-2xl relative z-10" />
                </motion.div>

                <motion.div
                    initial={{ width: 0, opacity: 0 }}
                    animate={{ width: 200, opacity: 1 }}
                    transition={{ duration: 1.5, delay: 0.5, ease: "circOut" }}
                    className="h-[2px] bg-gradient-to-r from-transparent via-[#4daaf5] to-transparent mt-8"
                />
                <motion.p
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 1 }}
                    className="mt-4 text-[#888] font-mono text-sm tracking-widest uppercase"
                >
                    INITIALIZING_DATAGRIP_MATRIX
                </motion.p>
            </motion.div>
        </motion.div>
    );
}
