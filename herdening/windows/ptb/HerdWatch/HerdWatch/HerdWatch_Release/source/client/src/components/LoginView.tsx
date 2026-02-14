import { useState } from 'react';
import { Shield } from 'lucide-react';

interface Props {
    onLogin: () => void;
}

const TARGET_HASH = 'c7d90ff64cd2fd444717555128d9256e454bbcbe6545de104de92b31624f9cb2';
const USERNAME = 'herd';

export function LoginView({ onLogin }: Props) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            // Basic delay to simulate work/prevent brute-force speed
            await new Promise(r => setTimeout(r, 500));

            if (username.toLowerCase() !== USERNAME) {
                setError('Invalid credentials');
                setLoading(false);
                return;
            }

            // Client-side SHA-256 hashing
            const msgBuffer = new TextEncoder().encode(password);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            if (hashHex === TARGET_HASH) {
                onLogin();
            } else {
                setError('Invalid credentials');
            }
        } catch (err) {
            setError('An error occurred');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background text-foreground">
            <div className="w-full max-w-md p-8 bg-card border border-border rounded-xl shadow-lg">
                <div className="flex flex-col items-center mb-8">
                    <div className="bg-primary/10 p-4 rounded-full mb-4">
                        <Shield className="w-12 h-12 text-primary" />
                    </div>
                    <h1 className="text-2xl font-bold">HerdWatch Access</h1>
                    <p className="text-muted-foreground text-sm mt-2">Restricted Area</p>
                </div>

                <form onSubmit={handleLogin} className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium mb-1">Username</label>
                        <input
                            type="text"
                            value={username}
                            onChange={e => setUsername(e.target.value)}
                            className="w-full p-2 rounded-md bg-secondary border border-border focus:ring-1 focus:ring-primary outline-none"
                            placeholder="username"
                            autoFocus
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1">Password</label>
                        <input
                            type="password"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            className="w-full p-2 rounded-md bg-secondary border border-border focus:ring-1 focus:ring-primary outline-none"
                            placeholder="password"
                        />
                    </div>

                    {error && (
                        <div className="text-red-500 text-sm text-center bg-red-500/10 p-2 rounded">
                            {error}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-primary text-primary-foreground py-2 rounded-md font-bold hover:opacity-90 transition-opacity disabled:opacity-50"
                    >
                        {loading ? 'Verifying...' : 'Login'}
                    </button>
                </form>
            </div>
        </div>
    );
}
