# HerdWatch

HerdWatch is a DNS activity monitoring tool for Windows, featuring real-time ETW capture and a modern Web UI.

## Getting Started

### Prerequisites
- Windows 10/11 or Server 2016+
- .NET 8.0 SDK
- Node.js (for frontend build)

### Build Instructions

1.  **Build Frontend**:
    ```powershell
    cd client
    npm install
    npm run build
    cd ..
    ```

2.  **Build Backend**:
    ```powershell
    dotnet build -c Release
    ```

3.  **Run**:
    Open a terminal as **Administrator** (required for ETW):
    ```powershell
    dotnet run -- --web --port 5000
    ```
    Access the UI at `http://localhost:5000`.

## features

- **Live DNS Monitoring**: Captures all DNS queries system-wide.
- **Process Analytics**: Group queries by process.
- **Web UI**: React-based dashboard for easy visualization.
