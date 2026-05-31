import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Lock, Mail, ArrowRight, Cpu } from 'lucide-react';
import logo from '../assets/logo.png';

// Extremely subtle binary stream data for cybersecurity texture
const BINARY_STREAMS = [
  { id: 1, left: '6%', delay: 0, speed: 25, text: '01101001 01101111 01100011' },
  { id: 2, left: '15%', delay: 4, speed: 30, text: 'VEhSRUFUX0RFVEVDVEVE' },
  { id: 3, left: '25%', delay: 2, speed: 22, text: '192.168.1.105 // ACCESS' },
  { id: 4, right: '6%', delay: 1, speed: 26, text: 'STATUS_CONNECTED // 200' },
  { id: 5, right: '15%', delay: 5, speed: 32, text: '0x7ffd50b2e810 // MEM' },
  { id: 6, right: '25%', delay: 3, speed: 20, text: 'AES_256_GCM_ENCRYPT' },
];

export default function Login({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [focusedField, setFocusedField] = useState(null);
  const [error, setError] = useState(null);

  const [requirePasswordChange, setRequirePasswordChange] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [credentials, setCredentials] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      const { login } = await import('../auth.js');
      const userInfo = await login(email, password);
      onLogin(userInfo);
    } catch (err) {
      if (err.requirePasswordChange) {
        setCredentials({ username: err.username, oldPassword: err.oldPassword });
        setRequirePasswordChange(true);
      } else {
        setError(err.message);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleChangePasswordSubmit = async (e) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError("Les mots de passe ne correspondent pas");
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch('http://localhost:8000/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: credentials.username,
          old_password: credentials.oldPassword,
          new_password: newPassword
        })
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || "Erreur lors du changement de mot de passe");
      }
      const { login } = await import('../auth.js');
      const userInfo = await login(credentials.username, newPassword);
      onLogin(userInfo);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#05060b] flex items-center justify-center relative overflow-hidden font-sans select-none py-10">
      
      {/* ── BACKGROUND VISUALS (CTI Dashboard Navy Theme) ─────────────── */}
      
      {/* Perfect match for Dashboard radial gradient */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,#0c1222_0%,#05060b_100%)]" />
      
      {/* Soft Glowing Mesh Orbs (Brighter/Lighter cyber feel) */}
      <motion.div 
        animate={{ 
          scale: [1, 1.15, 1],
          opacity: [0.25, 0.4, 0.25],
          x: [-15, 15, -15],
          y: [-10, 10, -10]
        }}
        transition={{ duration: 12, repeat: Infinity, ease: "easeInOut" }}
        className="absolute top-[-5%] left-[5%] w-[45%] h-[45%] rounded-full bg-sky-500/15 blur-[120px] pointer-events-none" 
      />
      <motion.div 
        animate={{ 
          scale: [1, 1.2, 1],
          opacity: [0.2, 0.35, 0.2],
          x: [15, -15, 15],
          y: [10, -10, 10]
        }}
        transition={{ duration: 15, repeat: Infinity, ease: "easeInOut", delay: 1 }}
        className="absolute bottom-[-5%] right-[5%] w-[45%] h-[45%] rounded-full bg-indigo-500/15 blur-[120px] pointer-events-none" 
      />

      {/* Cyberpunk Grid Background */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(14,165,233,0.015)_1px,transparent_1px),linear-gradient(90deg,rgba(14,165,233,0.015)_1px,transparent_1px)] bg-[size:30px_30px] [mask-image:radial-gradient(ellipse_at_center,black_70%,transparent_100%)] opacity-80 pointer-events-none" />

      {/* Tech Dots Mesh Decor */}
      <div className="absolute inset-0 bg-[radial-gradient(rgba(14,165,233,0.02)_1px,transparent_1px)] bg-[size:16px_16px] pointer-events-none" />

      {/* SVG Network Topology / Node Map (Left and Right Decor) - Color-harmonized with Cyan/Blue */}
      <svg className="absolute top-0 left-0 w-[30%] h-full opacity-15 pointer-events-none hidden md:block" viewBox="0 0 400 800">
        <defs>
          <radialGradient id="glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#0ea5e9" stopOpacity="1" />
            <stop offset="100%" stopColor="#0ea5e9" stopOpacity="0" />
          </radialGradient>
        </defs>
        <path d="M50,150 L180,250 L120,450 L280,550 L100,700" fill="none" stroke="rgba(14,165,233,0.15)" strokeWidth="1.5" />
        <path d="M180,250 L280,320 L280,550" fill="none" stroke="rgba(99,102,241,0.15)" strokeWidth="1" />
        
        {/* Nodes */}
        <circle cx="50" cy="150" r="4" fill="#0ea5e9" />
        <circle cx="50" cy="150" r="12" fill="url(#glow)" className="animate-pulse" />
        <circle cx="180" cy="250" r="5" fill="#6366f1" />
        <circle cx="120" cy="450" r="4" fill="#0ea5e9" />
        <circle cx="280" cy="320" r="4" fill="#6366f1" />
        <circle cx="280" cy="550" r="6" fill="#0ea5e9" />
        <circle cx="280" cy="550" r="16" fill="url(#glow)" className="animate-pulse" />
        <circle cx="100" cy="700" r="5" fill="#6366f1" />
      </svg>

      <svg className="absolute top-0 right-0 w-[30%] h-full opacity-15 pointer-events-none hidden md:block" viewBox="0 0 400 800">
        <path d="M350,120 L220,280 L290,480 L120,580 L300,720" fill="none" stroke="rgba(99,102,241,0.15)" strokeWidth="1.5" />
        <path d="M220,280 L120,380 L120,580" fill="none" stroke="rgba(14,165,233,0.15)" strokeWidth="1" />
        
        {/* Nodes */}
        <circle cx="350" cy="120" r="4" fill="#6366f1" />
        <circle cx="220" cy="280" r="6" fill="#0ea5e9" />
        <circle cx="220" cy="280" r="16" fill="url(#glow)" className="animate-pulse" />
        <circle cx="120" cy="380" r="4" fill="#0ea5e9" />
        <circle cx="290" cy="480" r="5" fill="#6366f1" />
        <circle cx="120" cy="580" r="4" fill="#0ea5e9" />
        <circle cx="300" cy="720" r="5" fill="#6366f1" />
      </svg>

      {/* Cyber Threat / Binary Rain streams on borders */}
      <div className="absolute inset-y-0 inset-x-0 overflow-hidden pointer-events-none">
        {BINARY_STREAMS.map((stream) => (
          <motion.div
            key={stream.id}
            initial={{ y: '-100%', opacity: 0 }}
            animate={{ y: '100%', opacity: [0, 0.4, 0.4, 0] }}
            transition={{
              duration: stream.speed,
              repeat: Infinity,
              ease: "linear",
              delay: stream.delay
            }}
            style={{
              position: 'absolute',
              left: stream.left,
              right: stream.right,
              fontFamily: 'monospace',
              fontSize: '10px',
              color: '#0ea5e9',
              writingMode: 'vertical-rl',
              textOrientation: 'upright',
              letterSpacing: '2px',
              textShadow: '0 0 5px rgba(14,165,233,0.3)',
              opacity: 0.1
            }}
          >
            {stream.text}
          </motion.div>
        ))}
      </div>

      {/* ── LOGIN FORM CARD (Color-harmonized with Dashboard panels) ──── */}
      <motion.div 
        initial={{ opacity: 0, scale: 0.96, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-[410px] mx-4 h-fit my-auto relative z-10 glowing-border-card"
      >
        {/* Harmonized lighter glass base: Slate-900/60 backdrop-blur */}
        <div className="bg-[#0b1224]/65 backdrop-blur-[20px] rounded-[24px] p-6 sm:p-8 shadow-[0_20px_50px_rgba(0,0,0,0.6),inset_0_1px_1px_rgba(255,255,255,0.08)] border border-slate-800/40 flex flex-col items-center">
          
          {/* Subtle Top Glowing Line Accent */}
          <div className="absolute inset-x-12 top-0 h-[1.5px] bg-gradient-to-r from-transparent via-sky-400 to-transparent opacity-60" />

          {/* Logo Section */}
          <motion.div 
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.1, duration: 0.5 }}
            className="mb-6"
          >
            <img src={logo} alt="BlueSec" className="h-10 w-auto drop-shadow-[0_0_10px_rgba(14,165,233,0.2)]" />
          </motion.div>

          {/* Header Title */}
          <div className="w-full mb-6 text-center">
            <h2 className="text-xl font-bold text-white tracking-tight mb-1">
              {requirePasswordChange ? 'Update Password' : 'Welcome Back'}
            </h2>
            <p className="text-slate-400 text-[10px] tracking-widest uppercase font-semibold">
              {requirePasswordChange ? 'Password change required' : 'Secure access to BlueSec CTI'}
            </p>
          </div>

          {/* Form */}
          {!requirePasswordChange ? (
          <form onSubmit={handleSubmit} className="w-full space-y-4">

            {error && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-2.5 text-red-400 text-xs text-center">
                {error}
              </div>
            )}

            {/* Email / Username Field */}
            <div className="space-y-1">
              <label className="text-[9px] font-bold text-slate-400 uppercase tracking-widest ml-1">
                Username
              </label>
              <div className="relative group">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                  <Mail className={`w-4 h-4 transition-colors duration-300 ${focusedField === 'email' ? 'text-sky-450' : 'text-slate-500'}`} />
                </div>
                <input
                  type="text"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onFocus={() => setFocusedField('email')}
                  onBlur={() => setFocusedField(null)}
                  className="w-full bg-[#060a16]/60 border border-slate-800/80 rounded-xl py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-655 focus:outline-none focus:ring-2 focus:ring-sky-500/30 focus:border-sky-500/40 transition-all duration-300 shadow-inner hover:border-slate-700/80 hover:bg-[#0c1224]/80"
                  placeholder="admin_cti"
                  required
                />
              </div>
            </div>

            {/* Password Field */}
            <div className="space-y-1">
              <label className="text-[9px] font-bold text-slate-400 uppercase tracking-widest ml-1">
                Password
              </label>
              <div className="relative group">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                  <Lock className={`w-4 h-4 transition-colors duration-300 ${focusedField === 'password' ? 'text-indigo-400' : 'text-slate-500'}`} />
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onFocus={() => setFocusedField('password')}
                  onBlur={() => setFocusedField(null)}
                  className="w-full bg-[#060a16]/60 border border-slate-800/80 rounded-xl py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-655 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500/40 transition-all duration-300 shadow-inner hover:border-slate-700/80 hover:bg-[#0c1224]/80"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>

            {/* Checkbox and Forgot Password */}
            <div className="flex items-center justify-between pt-1">
              <label className="flex items-center gap-2 cursor-pointer group">
                <div className="relative flex items-center justify-center">
                  <input type="checkbox" className="peer sr-only" />
                  <div className="w-3.5 h-3.5 rounded border border-slate-700 bg-slate-950/60 peer-checked:bg-sky-500 peer-checked:border-sky-500 transition-all duration-300" />
                  <div className="absolute opacity-0 peer-checked:opacity-100 transition-opacity duration-300 scale-50 peer-checked:scale-100">
                    <svg className="w-2.5 h-2.5 text-slate-950 drop-shadow" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                </div>
                <span className="text-[11px] text-slate-400 group-hover:text-slate-200 transition-colors duration-300 select-none">Remember me</span>
              </label>
              <a href="#" className="text-[11px] text-sky-400 hover:text-sky-300 hover:underline underline-offset-4 transition-all duration-300 font-medium">Forgot password?</a>
            </div>

            {/* Submit Button (Gradient from Sky Blue to Indigo matching the Dashboard accent theme) */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full relative group overflow-hidden rounded-xl p-[1px] mt-5"
            >
              {/* Perfect match for Dashboard active gradients (Sky to Indigo) */}
              <span className="absolute inset-0 bg-gradient-to-r from-sky-500 via-indigo-500 to-purple-600 opacity-80 group-hover:opacity-100 transition-opacity duration-500 bg-[length:200%_auto] animate-[gradient_3s_linear_infinite]" />
              
              <div className="relative bg-[#080d1a] px-4 py-3 rounded-xl flex items-center justify-center gap-2 transition-all duration-300 group-hover:bg-opacity-80">
                {/* Glow on hover */}
                <div className="absolute inset-0 opacity-0 group-hover:opacity-20 bg-gradient-to-r from-sky-400 to-indigo-400 rounded-xl blur-md transition-opacity duration-500" />
                
                {isLoading ? (
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                ) : (
                  <>
                    <span className="font-bold text-white tracking-widest text-[10px] uppercase relative z-10">Authenticate</span>
                    <motion.div
                      className="relative z-10"
                      initial={false}
                      animate={{ x: 0 }}
                      whileHover={{ x: 3 }}
                      transition={{ type: "spring", stiffness: 400, damping: 10 }}
                    >
                      <ArrowRight className="w-3.5 h-3.5 text-white" />
                    </motion.div>
                  </>
                )}
              </div>
            </button>
          </form>
          ) : (
          <form onSubmit={handleChangePasswordSubmit} className="w-full space-y-4">
            {error && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-2.5 text-red-400 text-xs text-center">
                {error}
              </div>
            )}
            <div className="space-y-1">
              <label className="text-[9px] font-bold text-slate-400 uppercase tracking-widest ml-1">
                New Password
              </label>
              <div className="relative group">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                  <Lock className={`w-4 h-4 transition-colors duration-300 ${focusedField === 'newPassword' ? 'text-indigo-400' : 'text-slate-500'}`} />
                </div>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  onFocus={() => setFocusedField('newPassword')}
                  onBlur={() => setFocusedField(null)}
                  className="w-full bg-[#060a16]/60 border border-slate-800/80 rounded-xl py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-655 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500/40 transition-all duration-300 shadow-inner hover:border-slate-700/80 hover:bg-[#0c1224]/80"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>
            <div className="space-y-1">
              <label className="text-[9px] font-bold text-slate-400 uppercase tracking-widest ml-1">
                Confirm Password
              </label>
              <div className="relative group">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                  <Lock className={`w-4 h-4 transition-colors duration-300 ${focusedField === 'confirmPassword' ? 'text-indigo-400' : 'text-slate-500'}`} />
                </div>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  onFocus={() => setFocusedField('confirmPassword')}
                  onBlur={() => setFocusedField(null)}
                  className="w-full bg-[#060a16]/60 border border-slate-800/80 rounded-xl py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-655 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500/40 transition-all duration-300 shadow-inner hover:border-slate-700/80 hover:bg-[#0c1224]/80"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full relative group overflow-hidden rounded-xl p-[1px] mt-5"
            >
              <span className="absolute inset-0 bg-gradient-to-r from-sky-500 via-indigo-500 to-purple-600 opacity-80 group-hover:opacity-100 transition-opacity duration-500 bg-[length:200%_auto] animate-[gradient_3s_linear_infinite]" />
              <div className="relative bg-[#080d1a] px-4 py-3 rounded-xl flex items-center justify-center gap-2 transition-all duration-300 group-hover:bg-opacity-80">
                <div className="absolute inset-0 opacity-0 group-hover:opacity-20 bg-gradient-to-r from-sky-400 to-indigo-400 rounded-xl blur-md transition-opacity duration-500" />
                {isLoading ? (
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                ) : (
                  <>
                    <span className="font-bold text-white tracking-widest text-[10px] uppercase relative z-10">Update & Login</span>
                    <motion.div
                      className="relative z-10"
                      initial={false}
                      animate={{ x: 0 }}
                      whileHover={{ x: 3 }}
                      transition={{ type: "spring", stiffness: 400, damping: 10 }}
                    >
                      <ArrowRight className="w-3.5 h-3.5 text-white" />
                    </motion.div>
                  </>
                )}
              </div>
            </button>
          </form>
          )}

          {/* Minimal cybersecurity footer logo */}
          <div className="mt-6 flex items-center justify-center gap-1 opacity-20 hover:opacity-50 transition-opacity duration-300 cursor-pointer">
             <Cpu className="w-3 h-3 text-sky-400" />
             <span className="font-mono text-[8px] text-slate-400 tracking-widest uppercase">BlueSec Shield v4.1</span>
          </div>
        </div>
      </motion.div>

      {/* Scoped CSS for the glowing, sweeping border card & animations */}
      <style dangerouslySetInnerHTML={{__html: `
        @property --border-angle {
          syntax: "<angle>";
          inherits: false;
          initial-value: 0deg;
        }

        @keyframes border-rotate {
          to {
            --border-angle: 360deg;
          }
        }

        @keyframes gradient {
          0% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
          100% { background-position: 0% 50%; }
        }

        .glowing-border-card {
          position: relative;
        }

        .glowing-border-card::before {
          content: '';
          position: absolute;
          inset: -1.5px;
          border-radius: 24px;
          padding: 1.5px;
          background: conic-gradient(from var(--border-angle), transparent 20%, #0ea5e9 40%, #6366f1 60%, transparent 80%);
          -webkit-mask: 
             linear-gradient(#fff 0 0) content-box, 
             linear-gradient(#fff 0 0);
          -webkit-mask-composite: xor;
                  mask-composite: exclude;
          animation: border-rotate 6s linear infinite;
          pointer-events: none;
        }
      `}} />
    </div>
  );
}
