/** Gestion de usuarios (solo admin). */
import { useEffect, useState, type FormEvent } from 'react';
import { AxiosError } from 'axios';
import { UserPlus, Trash2, KeyRound, Shield, X } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { usersApi, ROLE_LABELS, type User, type RoleName } from '@/lib/users';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';

const ROLES: RoleName[] = ['admin', 'analista', 'lector'];

export function UsersTab({ onFlash }: { onFlash: (k: 'ok' | 'err', t: string) => void }) {
  const { user: me } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [creating, setCreating] = useState(false);

  async function reload() {
    setUsers(await usersApi.list());
  }
  useEffect(() => {
    reload().catch(() => onFlash('err', 'No se pudieron cargar los usuarios'));
  }, []);

  const err = (e: unknown) =>
    onFlash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'Error');

  async function changeRole(u: User, role: RoleName) {
    try {
      await usersApi.update(u.id, { role });
      await reload();
      onFlash('ok', 'Rol actualizado');
    } catch (e) {
      err(e);
    }
  }
  async function toggleActive(u: User) {
    try {
      await usersApi.update(u.id, { isActive: !u.isActive });
      await reload();
    } catch (e) {
      err(e);
    }
  }
  async function reset(u: User) {
    const pwd = prompt(`Nueva contraseña para ${u.email} (mín. 8 caracteres):`);
    if (!pwd) return;
    try {
      await usersApi.resetPassword(u.id, pwd);
      onFlash('ok', 'Contraseña restablecida');
    } catch (e) {
      err(e);
    }
  }
  async function remove(u: User) {
    if (!confirm(`¿Eliminar al usuario ${u.email}?`)) return;
    try {
      await usersApi.remove(u.id);
      await reload();
      onFlash('ok', 'Usuario eliminado');
    } catch (e) {
      err(e);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button size="sm" onClick={() => setCreating((v) => !v)}>
          {creating ? <X className="h-4 w-4" /> : <UserPlus className="h-4 w-4" />}
          {creating ? 'Cerrar' : 'Nuevo usuario'}
        </Button>
      </div>

      {creating && (
        <CreateUserForm
          onCreated={async () => {
            setCreating(false);
            await reload();
            onFlash('ok', 'Usuario creado');
          }}
          onError={err}
        />
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Usuarios ({users.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                  <th className="pb-2 pr-4 font-medium">Usuario</th>
                  <th className="pb-2 pr-4 font-medium">Rol</th>
                  <th className="pb-2 pr-4 font-medium">Último acceso</th>
                  <th className="pb-2 pr-4 font-medium">Activo</th>
                  <th className="pb-2 font-medium text-right">Acciones</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-b border-border/30 last:border-0">
                    <td className="py-2.5 pr-4">
                      <div className="font-medium">{u.fullName}</div>
                      <div className="text-xs text-muted-foreground">{u.email}</div>
                    </td>
                    <td className="py-2.5 pr-4">
                      <select
                        value={u.role}
                        onChange={(e) => changeRole(u, e.target.value as RoleName)}
                        disabled={u.id === me?.id}
                        className="h-8 rounded-md border border-input bg-background/60 px-2 text-xs"
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>
                            {ROLE_LABELS[r]}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="py-2.5 pr-4 text-muted-foreground">
                      {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString('es-CO') : 'Nunca'}
                    </td>
                    <td className="py-2.5 pr-4">
                      <Switch
                        checked={u.isActive}
                        onChange={() => toggleActive(u)}
                        disabled={u.id === me?.id}
                      />
                    </td>
                    <td className="py-2.5">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon" onClick={() => reset(u)} title="Restablecer contraseña">
                          <KeyRound className="h-4 w-4" />
                        </Button>
                        {u.id !== me?.id && (
                          <Button variant="ghost" size="icon" onClick={() => remove(u)} title="Eliminar">
                            <Trash2 className="h-4 w-4 text-red-400" />
                          </Button>
                        )}
                        {u.id === me?.id && (
                          <span title="Tu usuario">
                            <Shield className="h-4 w-4 text-neon" />
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function CreateUserForm({
  onCreated,
  onError,
}: {
  onCreated: () => void;
  onError: (e: unknown) => void;
}) {
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<RoleName>('lector');
  const [saving, setSaving] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await usersApi.create({ email, fullName, password, role });
      onCreated();
    } catch (err) {
      onError(err);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Nuevo usuario</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label>Nombre completo</Label>
            <Input value={fullName} onChange={(e) => setFullName(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label>Correo</Label>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label>Contraseña (mín. 8)</Label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
          </div>
          <div className="space-y-2">
            <Label>Rol</Label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as RoleName)}
              className="h-10 w-full rounded-md border border-input bg-background/60 px-3 text-sm"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </select>
          </div>
          <div className="sm:col-span-2 flex justify-end">
            <Button type="submit" disabled={saving}>
              {saving ? 'Creando…' : 'Crear usuario'}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
