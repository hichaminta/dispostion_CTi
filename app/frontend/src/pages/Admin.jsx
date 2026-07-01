import React, { useState, useEffect } from 'react';
import { Shield, Users, UserPlus, Trash2, ShieldAlert, RefreshCw } from 'lucide-react';
import { motion } from 'framer-motion';
import { getValidToken, logout } from '../auth.js';

const API = `/api/admin`;

async function authHeaders() {
  const token = await getValidToken();
  return { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };
}

export default function Admin() {
  const [users, setUsers]   = useState([]);
  const [roles, setRoles]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'analyst', forcePasswordChange: false });
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const headers = await authHeaders();
      const [uRes, rRes] = await Promise.all([
        fetch(`${API}/users`, { headers }),
        fetch(`${API}/roles`, { headers }),
      ]);
      if (!uRes.ok) {
        const errBody = await uRes.json().catch(() => ({}));
        throw new Error(errBody.detail || `Erreur ${uRes.status}`);
      }
      setUsers(await uRes.json());
      if (rRes.ok) setRoles((await rRes.json()).filter(r => !r.name.startsWith('default-roles')));
    } catch (err) {
      if (err.message.includes('expir')) {
        logout();
        window.location.reload();
        return;
      }
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleDelete = async (userId) => {
    if (!confirm('Supprimer cet utilisateur ?')) return;
    const headers = await authHeaders();
    await fetch(`${API}/users/${userId}`, { method: 'DELETE', headers });
    fetchData();
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    setSaving(true);
    setFormError(null);
    try {
      const headers = await authHeaders();
      const res = await fetch(`${API}/users`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          username: newUser.username,
          email: newUser.email,
          enabled: true,
          emailVerified: true,
          credentials: [{ type: 'password', value: newUser.password, temporary: newUser.forcePasswordChange }],
          // Both fields are needed for Keycloak to properly enforce the password change flow
          requiredActions: newUser.forcePasswordChange ? ['UPDATE_PASSWORD'] : [],
        }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || `Erreur ${res.status}`);
      }
      const { user_id } = await res.json();
      // Assign role
      const headers2 = await authHeaders();
      const roleRes = await fetch(`${API}/users/${user_id}/roles?role_name=${newUser.role}`, {
        method: 'POST', headers: headers2,
      });
      if (!roleRes.ok) {
        const errBody = await roleRes.json().catch(() => ({}));
        throw new Error(`Utilisateur créé mais erreur rôle: ${errBody.detail || roleRes.status}`);
      }
      setShowForm(false);
      setFormError(null);
      setNewUser({ username: '', email: '', password: '', role: 'analyst', forcePasswordChange: false });
      fetchData();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="p-8 text-center text-slate-400 animate-pulse">Chargement...</div>;

  if (error) return (
    <div className="p-8 flex flex-col items-center justify-center text-red-400">
      <ShieldAlert className="w-12 h-12 mb-4" />
      <h2 className="text-xl font-bold">Erreur d'accès</h2>
      <p>{error}</p>
    </div>
  );

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            Administration
          </h1>
          <p className="text-slate-400 mt-1 text-sm">Gérez les utilisateurs et leurs rôles.</p>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchData} className="p-2 text-slate-400 hover:text-white hover:bg-white/5 rounded-xl transition-all">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-2 bg-sky-500 hover:bg-sky-400 text-white px-4 py-2 rounded-xl text-sm transition-all"
          >
            Nouvel utilisateur
          </button>
        </div>
      </div>

      {/* Création utilisateur */}
      {showForm && (
        <motion.form
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          onSubmit={handleCreate}
          className="bg-slate-900/60 border border-white/10 rounded-2xl p-6 space-y-4"
        >
          <h2 className="text-white font-semibold flex items-center gap-2"><UserPlus className="w-4 h-4 text-sky-400" /> Créer un utilisateur</h2>
          {formError && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3 text-red-400 text-sm">
              ⚠️ {formError}
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <input required placeholder="Username" value={newUser.username}
              onChange={e => setNewUser(p => ({ ...p, username: e.target.value }))}
              className="bg-slate-800/50 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500/40" />
            <input type="email" placeholder="Email" value={newUser.email}
              onChange={e => setNewUser(p => ({ ...p, email: e.target.value }))}
              className="bg-slate-800/50 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500/40" />
            <input required type="password" placeholder="Mot de passe" value={newUser.password}
              onChange={e => setNewUser(p => ({ ...p, password: e.target.value }))}
              className="bg-slate-800/50 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500/40" />
            <select value={newUser.role} onChange={e => setNewUser(p => ({ ...p, role: e.target.value }))}
              className="bg-slate-800/50 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500/40">
              {roles.map(r => <option key={r.name} value={r.name}>{r.name}</option>)}
            </select>
          </div>
          <div className="flex items-center gap-2 mt-2">
            <input type="checkbox" id="forcePasswordChange" checked={newUser.forcePasswordChange}
              onChange={e => setNewUser(p => ({ ...p, forcePasswordChange: e.target.checked }))}
              className="rounded border-white/10 bg-slate-800/50 text-sky-500 focus:ring-sky-500/40 w-4 h-4" />
            <label htmlFor="forcePasswordChange" className="text-sm text-slate-300">Forcer le changement de mot de passe à la première connexion</label>
          </div>
          <div className="flex gap-3 justify-end">
            <button type="button" onClick={() => setShowForm(false)} className="px-4 py-2 text-slate-400 hover:text-white text-sm transition-all">Annuler</button>
            <button type="submit" disabled={saving}
              className="px-4 py-2 bg-sky-500 hover:bg-sky-400 text-white text-sm rounded-xl transition-all disabled:opacity-50">
              {saving ? 'Création...' : 'Créer'}
            </button>
          </div>
        </motion.form>
      )}

      {/* Table utilisateurs */}
      <div className="bg-slate-900/50 border border-white/10 rounded-2xl overflow-hidden backdrop-blur-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-white/5 border-b border-white/10 text-slate-300 text-sm">
                <th className="p-4 font-medium">Username</th>
                <th className="p-4 font-medium">Email</th>
                <th className="p-4 font-medium">Statut</th>
                <th className="p-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-sm">
              {users.map((user) => (
                <motion.tr key={user.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                  className="hover:bg-white/5 transition-colors">
                  <td className="p-4 font-medium text-slate-200">{user.username}</td>
                  <td className="p-4 text-slate-400">{user.email || '—'}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded-md text-xs font-medium ${user.enabled
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                      {user.enabled ? 'Actif' : 'Inactif'}
                    </span>
                  </td>
                  <td className="p-4 text-right">
                    <button onClick={() => handleDelete(user.id)}
                      className="p-2 hover:bg-red-500/20 hover:text-red-400 text-slate-500 rounded-lg transition-colors">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </motion.tr>
              ))}
              {users.length === 0 && (
                <tr><td colSpan="4" className="p-8 text-center text-slate-500">Aucun utilisateur.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
