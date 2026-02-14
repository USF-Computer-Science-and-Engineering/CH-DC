import { Copyable } from './Copyable';
import { Shield, Terminal, FileText, AlertTriangle, Activity } from 'lucide-react';

export function CheatsheetView() {
    return (
        <div className="p-6 max-w-4xl mx-auto space-y-8">
            <div className="space-y-2">
                <h2 className="text-2xl font-bold flex items-center gap-2">
                    <Shield className="w-6 h-6 text-primary" />
                    Defense Cheatsheet
                </h2>
                <p className="text-muted-foreground">
                    Quick reference commands for blocking malicious traffic on Windows.
                </p>
            </div>

            <div className="grid gap-6">
                {/* Hosts File Section */}
                <section className="space-y-4 border border-border p-4 rounded-lg bg-card">
                    <div className="flex items-center gap-2 mb-2">
                        <FileText className="w-5 h-5 text-blue-400" />
                        <h3 className="text-lg font-semibold">1. Sinkhole Domain (Hosts File)</h3>
                    </div>
                    <p className="text-sm text-muted-foreground">
                        Redirect a malicious domain to 0.0.0.0 to prevent connection. Requires Admin.
                    </p>
                    <div className="bg-muted p-3 rounded-md font-mono text-sm relative group">
                        <div className="text-xs text-muted-foreground mb-1 select-none"># Add this line to C:\Windows\System32\drivers\etc\hosts</div>
                        <div className="flex items-center justify-between">
                            <span>0.0.0.0 example-malicious-domain.com</span>
                            <Copyable text="0.0.0.0 example-malicious-domain.com" />
                        </div>
                    </div>
                    <div className="bg-muted p-3 rounded-md font-mono text-sm relative group">
                        <div className="text-xs text-muted-foreground mb-1 select-none"># Powershell command to append to hosts file</div>
                        <div className="flex items-center justify-between gap-4">
                            <span className="truncate">"0.0.0.0 example.com" | Out-File -Append C:\Windows\System32\drivers\etc\hosts -Encoding ascii</span>
                            <Copyable text='"0.0.0.0 example.com" | Out-File -Append C:\Windows\System32\drivers\etc\hosts -Encoding ascii' />
                        </div>
                    </div>
                </section>

                {/* Firewall IP Block */}
                <section className="space-y-4 border border-border p-4 rounded-lg bg-card">
                    <div className="flex items-center gap-2 mb-2">
                        <Terminal className="w-5 h-5 text-red-400" />
                        <h3 className="text-lg font-semibold">2. Block IP Address (Firewall)</h3>
                    </div>
                    <p className="text-sm text-muted-foreground">
                        Block all traffic to/from a specific IP address using Windows Firewall.
                    </p>
                    <div className="bg-muted p-3 rounded-md font-mono text-sm">
                        <div className="text-xs text-muted-foreground mb-1 select-none"># Block Outbound Connection to IP</div>
                        <div className="flex items-center justify-between gap-4">
                            <span className="truncate">New-NetFirewallRule -DisplayName "Block IP Out" -Direction Outbound -RemoteAddress 192.168.1.100 -Action Block</span>
                            <Copyable text='New-NetFirewallRule -DisplayName "Block IP Out" -Direction Outbound -RemoteAddress 192.168.1.100 -Action Block' />
                        </div>
                    </div>
                    <div className="bg-muted p-3 rounded-md font-mono text-sm">
                        <div className="text-xs text-muted-foreground mb-1 select-none"># Block Inbound Connection from IP</div>
                        <div className="flex items-center justify-between gap-4">
                            <span className="truncate">New-NetFirewallRule -DisplayName "Block IP In" -Direction Inbound -RemoteAddress 192.168.1.100 -Action Block</span>
                            <Copyable text='New-NetFirewallRule -DisplayName "Block IP In" -Direction Inbound -RemoteAddress 192.168.1.100 -Action Block' />
                        </div>
                    </div>
                </section>

                {/* Process Block */}
                <section className="space-y-4 border border-border p-4 rounded-lg bg-card">
                    <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className="w-5 h-5 text-orange-400" />
                        <h3 className="text-lg font-semibold">3. Block Process (Firewall)</h3>
                    </div>
                    <p className="text-sm text-muted-foreground">
                        Prevent a specific application from accessing the network.
                    </p>
                    <div className="bg-muted p-3 rounded-md font-mono text-sm">
                        <div className="text-xs text-muted-foreground mb-1 select-none"># Block Executable from Network</div>
                        <div className="flex items-center justify-between gap-4">
                            <span className="truncate">New-NetFirewallRule -DisplayName "Block Malware" -Direction Outbound -Program "C:\Path\To\Malware.exe" -Action Block</span>
                            <Copyable text='New-NetFirewallRule -DisplayName "Block Malware" -Direction Outbound -Program "C:\Path\To\Malware.exe" -Action Block' />
                        </div>
                    </div>
                </section>

                {/* DNS Flushing */}
                <section className="space-y-4 border border-border p-4 rounded-lg bg-card">
                    <div className="flex items-center gap-2 mb-2">
                        <Terminal className="w-5 h-5 text-green-400" />
                        <h3 className="text-lg font-semibold">4. Reset DNS Cache</h3>
                    </div>
                    <p className="text-sm text-muted-foreground">
                        Clear the local DNS resolver cache to remove old records.
                    </p>
                    <div className="bg-muted p-3 rounded-md font-mono text-sm">
                        <div className="flex items-center justify-between gap-4">
                            <span>ipconfig /flushdns</span>
                            <Copyable text='ipconfig /flushdns' />
                        </div>
                    </div>
                </section>

                {/* ETW Troubleshooting */}
                <section className="space-y-4 border border-border p-4 rounded-lg bg-card">
                    <div className="flex items-center gap-2 mb-2">
                        <Activity className="w-5 h-5 text-purple-400" />
                        <h3 className="text-lg font-semibold">5. ETW Troubleshooting (0x800705AA)</h3>
                    </div>
                    <p className="text-sm text-muted-foreground">
                        Fix "Insufficient system resources" by cleaning up zombie ETW sessions.
                    </p>

                    <div className="bg-muted p-3 rounded-md font-mono text-sm space-y-3">
                        <div>
                            <div className="text-xs text-muted-foreground mb-1 select-none"># 1. List all active trace sessions</div>
                            <div className="flex items-center justify-between gap-4">
                                <span>logman query -ets</span>
                                <Copyable text='logman query -ets' />
                            </div>
                        </div>

                        <div>
                            <div className="text-xs text-muted-foreground mb-1 select-none"># 2. Stop a specific session (replace "Name")</div>
                            <div className="flex items-center justify-between gap-4">
                                <span>logman stop "Name" -ets</span>
                                <Copyable text='logman stop "Name" -ets' />
                            </div>
                        </div>

                        <div>
                            <div className="text-xs text-muted-foreground mb-1 select-none"># 3. Stop ALL HerdWatch sessions (PowerShell)</div>
                            <div className="flex items-center justify-between gap-4">
                                <span className="truncate">{"logman query -ets | Select-String \"HerdWatch\" | ForEach-Object { $name = $_.ToString().Split(' ')[0]; logman stop $name -ets }"}</span>
                                <Copyable text="logman query -ets | Select-String 'HerdWatch' | ForEach-Object { $name = $_.ToString().Split(' ')[0]; logman stop $name -ets }" />
                            </div>
                        </div>
                    </div>
                </section>
            </div>
        </div>
    );
}
