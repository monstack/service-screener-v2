import { useState, useEffect, useRef } from 'react'

// AWS Logo SVG Component
const AWSLogo = () => (
    <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="40" height="40" rx="8" fill="url(#aws-gradient)" />
        <path d="M12 22.5C12 21.12 13.12 20 14.5 20H25.5C26.88 20 28 21.12 28 22.5V25.5C28 26.88 26.88 28 25.5 28H14.5C13.12 28 12 26.88 12 25.5V22.5Z" fill="white" />
        <path d="M14 15C14 14.45 14.45 14 15 14H25C25.55 14 26 14.45 26 15V17C26 17.55 25.55 18 25 18H15C14.45 18 14 17.55 14 17V15Z" fill="white" opacity="0.8" />
        <defs>
            <linearGradient id="aws-gradient" x1="0" y1="0" x2="40" y2="40">
                <stop stopColor="#FF9900" />
                <stop offset="1" stopColor="#FFB84D" />
            </linearGradient>
        </defs>
    </svg>
)

// Loading Spinner
const Spinner = () => <div className="spinner"></div>

// Status Badge Component
const StatusBadge = ({ status }) => (
    <span className={`status-badge status-${status}`}>
        {status === 'running' && <span className="animate-pulse">●</span>}
        {status}
    </span>
)

function App() {
    const [activeTab, setActiveTab] = useState('login')
    const [services, setServices] = useState([])
    const [regions, setRegions] = useState([])
    const [frameworks, setFrameworks] = useState([])
    const [profiles, setProfiles] = useState([])

    const [selectedServices, setSelectedServices] = useState([])
    const [selectedRegions, setSelectedRegions] = useState([])
    const [selectedFrameworks, setSelectedFrameworks] = useState([])
    const [selectedProfile, setSelectedProfile] = useState('default')

    const [scanJob, setScanJob] = useState(null)
    const [reports, setReports] = useState([])
    const [loading, setLoading] = useState(true)
    const [scanning, setScanning] = useState(false)

    // SSO State
    const [ssoStatus, setSsoStatus] = useState({ authenticated: false })
    const [ssoStartUrl, setSsoStartUrl] = useState('')
    const [ssoRegion, setSsoRegion] = useState('ap-southeast-1')
    const [ssoAuthInfo, setSsoAuthInfo] = useState(null)
    const [ssoPolling, setSsoPolling] = useState(false)
    const [ssoAccounts, setSsoAccounts] = useState([])
    const [ssoRoles, setSsoRoles] = useState([])
    const [selectedAccount, setSelectedAccount] = useState(null)
    const [selectedRole, setSelectedRole] = useState(null)
    const pollIntervalRef = useRef(null)

    // Fetch initial data
    useEffect(() => {
        Promise.all([
            fetch('/api/services').then(r => r.json()),
            fetch('/api/regions').then(r => r.json()),
            fetch('/api/frameworks').then(r => r.json()),
            fetch('/api/aws-profiles').then(r => r.json()),
            fetch('/api/reports').then(r => r.json()),
            fetch('/api/sso/status').then(r => r.json())
        ]).then(([servicesData, regionsData, frameworksData, profilesData, reportsData, ssoStatusData]) => {
            setServices(servicesData.services || [])
            setRegions(regionsData.regions || [])
            setFrameworks(frameworksData.frameworks || [])
            setProfiles(profilesData.profiles || ['default'])
            setReports(reportsData.reports || [])
            setSsoStatus(ssoStatusData)
            if (ssoStatusData.authenticated) {
                setActiveTab('scan')
            }
            setLoading(false)
        }).catch(err => {
            console.error('Failed to fetch data:', err)
            setLoading(false)
        })
    }, [])

    // Poll scan status
    useEffect(() => {
        if (!scanJob || scanJob.status === 'completed' || scanJob.status === 'failed') return

        const interval = setInterval(() => {
            fetch(`/api/scan/${scanJob.job_id}`)
                .then(r => r.json())
                .then(data => {
                    setScanJob(data)
                    if (data.status === 'completed' || data.status === 'failed') {
                        setScanning(false)
                        fetch('/api/reports').then(r => r.json()).then(d => setReports(d.reports || []))
                    }
                })
        }, 2000)

        return () => clearInterval(interval)
    }, [scanJob])

    // SSO Functions
    const startSsoLogin = async () => {
        if (!ssoStartUrl) {
            alert('Please enter your AWS SSO Start URL')
            return
        }

        try {
            const response = await fetch('/api/sso/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ start_url: ssoStartUrl, region: ssoRegion })
            })
            const data = await response.json()

            if (data.status === 'started') {
                setSsoAuthInfo(data)
                // Open verification URL in new tab
                window.open(data.verification_uri_complete, '_blank')
                // Start polling
                startSsoPolling()
            } else {
                alert(`SSO Error: ${data.message}`)
            }
        } catch (err) {
            console.error('SSO start failed:', err)
            alert('Failed to start SSO login')
        }
    }

    const startSsoPolling = () => {
        setSsoPolling(true)
        pollIntervalRef.current = setInterval(async () => {
            try {
                const response = await fetch('/api/sso/poll', { method: 'POST' })
                const data = await response.json()

                if (data.status === 'success') {
                    clearInterval(pollIntervalRef.current)
                    setSsoPolling(false)
                    setSsoStatus({ authenticated: true, expires_at: data.expires_in })
                    setSsoAuthInfo(null)
                    loadSsoAccounts()
                } else if (data.status === 'expired' || data.status === 'denied' || data.status === 'error') {
                    clearInterval(pollIntervalRef.current)
                    setSsoPolling(false)
                    alert(`SSO ${data.status}: ${data.message}`)
                }
            } catch (err) {
                console.error('SSO poll failed:', err)
            }
        }, 3000)
    }

    const loadSsoAccounts = async () => {
        const response = await fetch('/api/sso/accounts')
        const data = await response.json()
        setSsoAccounts(data.accounts || [])
    }

    const loadSsoRoles = async (accountId) => {
        setSelectedAccount(accountId)
        const response = await fetch(`/api/sso/accounts/${accountId}/roles`)
        const data = await response.json()
        setSsoRoles(data.roles || [])
    }

    const selectSsoRole = (roleName) => {
        setSelectedRole(roleName)
        setActiveTab('scan')
    }

    const toggleService = (serviceId) => {
        setSelectedServices(prev =>
            prev.includes(serviceId)
                ? prev.filter(s => s !== serviceId)
                : [...prev, serviceId]
        )
    }

    const toggleRegion = (regionId) => {
        setSelectedRegions(prev =>
            prev.includes(regionId)
                ? prev.filter(r => r !== regionId)
                : [...prev, regionId]
        )
    }

    const toggleFramework = (frameworkId) => {
        setSelectedFrameworks(prev =>
            prev.includes(frameworkId)
                ? prev.filter(f => f !== frameworkId)
                : [...prev, frameworkId]
        )
    }

    const selectAllServices = () => {
        setSelectedServices(services.map(s => s.id))
    }

    const clearServices = () => {
        setSelectedServices([])
    }

    const startScan = async () => {
        if (selectedServices.length === 0 || selectedRegions.length === 0) {
            alert('Please select at least one service and one region')
            return
        }

        // Check if SSO authenticated but no account/role selected
        if (ssoStatus.authenticated && (!selectedAccount || !selectedRole)) {
            alert('Please select an AWS account and role in the Login tab first')
            setActiveTab('login')
            return
        }

        setScanning(true)
        try {
            const scanPayload = {
                services: selectedServices,
                regions: selectedRegions,
                frameworks: selectedFrameworks,
                aws_profile: selectedProfile,
                // Include SSO info if authenticated
                use_sso: ssoStatus.authenticated,
                sso_account_id: selectedAccount,
                sso_role_name: selectedRole
            }

            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(scanPayload)
            })
            const data = await response.json()
            setScanJob(data)
            setActiveTab('progress')
        } catch (err) {
            console.error('Failed to start scan:', err)
            setScanning(false)
            alert('Failed to start scan. Check console for details.')
        }
    }

    if (loading) {
        return (
            <div className="app">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', flexDirection: 'column', gap: '1rem' }}>
                    <Spinner />
                    <p style={{ color: 'var(--text-secondary)' }}>Loading AWS Service Screener...</p>
                </div>
            </div>
        )
    }

    return (
        <div className="app">
            {/* Header */}
            <header className="header">
                <div className="header-logo">
                    <AWSLogo />
                    <div>
                        <div className="header-title">AWS Service Screener</div>
                        <div className="header-subtitle">Well-Architected Best Practices Scanner</div>
                    </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    {ssoStatus.authenticated ? (
                        <span className="status-badge status-completed">🔐 SSO Connected</span>
                    ) : (
                        <select
                            className="form-select"
                            style={{ width: '180px' }}
                            value={selectedProfile}
                            onChange={(e) => setSelectedProfile(e.target.value)}
                        >
                            {profiles.map(p => (
                                <option key={p} value={p}>{p}</option>
                            ))}
                        </select>
                    )}
                </div>
            </header>

            {/* Navigation Tabs */}
            <div className="main-content">
                <div className="tabs">
                    <button
                        className={`tab ${activeTab === 'login' ? 'active' : ''}`}
                        onClick={() => setActiveTab('login')}
                    >
                        🔐 {ssoStatus.authenticated ? 'Account' : 'Login'}
                    </button>
                    <button
                        className={`tab ${activeTab === 'scan' ? 'active' : ''}`}
                        onClick={() => setActiveTab('scan')}
                    >
                        🔍 New Scan
                    </button>
                    <button
                        className={`tab ${activeTab === 'progress' ? 'active' : ''}`}
                        onClick={() => setActiveTab('progress')}
                    >
                        ⏳ Scan Progress
                    </button>
                    <button
                        className={`tab ${activeTab === 'reports' ? 'active' : ''}`}
                        onClick={() => setActiveTab('reports')}
                    >
                        📊 Reports ({reports.length})
                    </button>
                </div>

                {/* Login Tab */}
                {activeTab === 'login' && (
                    <div className="animate-fadeIn">
                        {!ssoStatus.authenticated ? (
                            <div className="card" style={{ maxWidth: '600px', margin: '0 auto' }}>
                                <div className="card-header">
                                    <h2 className="card-title">
                                        <span className="card-title-icon">🔐</span>
                                        AWS SSO Login
                                    </h2>
                                </div>

                                {!ssoAuthInfo ? (
                                    <>
                                        <div className="form-group">
                                            <label className="form-label">AWS SSO Start URL</label>
                                            <input
                                                type="text"
                                                className="form-input"
                                                placeholder="https://your-company.awsapps.com/start"
                                                value={ssoStartUrl}
                                                onChange={(e) => setSsoStartUrl(e.target.value)}
                                            />
                                            <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.5rem' }}>
                                                Find this URL in your AWS SSO portal or ask your administrator
                                            </p>
                                        </div>

                                        <div className="form-group">
                                            <label className="form-label">SSO Region</label>
                                            <select
                                                className="form-select"
                                                value={ssoRegion}
                                                onChange={(e) => setSsoRegion(e.target.value)}
                                            >
                                                <option value="us-east-1">US East (N. Virginia)</option>
                                                <option value="us-east-2">US East (Ohio)</option>
                                                <option value="us-west-2">US West (Oregon)</option>
                                                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                                                <option value="ap-southeast-2">Asia Pacific (Sydney)</option>
                                                <option value="ap-northeast-1">Asia Pacific (Tokyo)</option>
                                                <option value="eu-west-1">Europe (Ireland)</option>
                                                <option value="eu-central-1">Europe (Frankfurt)</option>
                                            </select>
                                            <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.5rem' }}>
                                                Select the region where your AWS SSO (Identity Center) is configured
                                            </p>
                                        </div>

                                        <button
                                            className="btn btn-aws btn-lg"
                                            style={{ width: '100%' }}
                                            onClick={startSsoLogin}
                                        >
                                            🚀 Start SSO Login
                                        </button>

                                        <div style={{ marginTop: '2rem', padding: '1rem', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-md)' }}>
                                            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '0.5rem' }}>
                                                <strong>Or use AWS Profile</strong>
                                            </p>
                                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                                                If you already have AWS credentials configured, use the profile dropdown in the header and go to "New Scan".
                                            </p>
                                        </div>
                                    </>
                                ) : (
                                    <div style={{ textAlign: 'center' }}>
                                        <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔗</div>
                                        <h3 style={{ marginBottom: '1rem' }}>Complete Login in Browser</h3>
                                        <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                                            A new tab should have opened. Enter this code if prompted:
                                        </p>
                                        <div style={{
                                            fontSize: '2rem',
                                            fontWeight: 'bold',
                                            fontFamily: 'monospace',
                                            padding: '1rem',
                                            background: 'var(--bg-tertiary)',
                                            borderRadius: 'var(--radius-md)',
                                            marginBottom: '1.5rem'
                                        }}>
                                            {ssoAuthInfo.user_code}
                                        </div>

                                        {ssoPolling && (
                                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                                                <Spinner />
                                                <span style={{ color: 'var(--text-secondary)' }}>Waiting for login...</span>
                                            </div>
                                        )}

                                        <a
                                            href={ssoAuthInfo.verification_uri_complete}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="btn btn-secondary"
                                            style={{ marginTop: '1rem' }}
                                        >
                                            Open Login Page Again →
                                        </a>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <div className="card" style={{ maxWidth: '800px', margin: '0 auto' }}>
                                <div className="card-header">
                                    <h2 className="card-title">
                                        <span className="card-title-icon">✅</span>
                                        SSO Connected - Select Account
                                    </h2>
                                    <StatusBadge status="completed" />
                                </div>

                                {ssoAccounts.length > 0 ? (
                                    <div className="checkbox-grid">
                                        {ssoAccounts.map(account => (
                                            <div
                                                key={account.accountId}
                                                className={`checkbox-item ${selectedAccount === account.accountId ? 'selected' : ''}`}
                                                onClick={() => loadSsoRoles(account.accountId)}
                                                style={{ cursor: 'pointer' }}
                                            >
                                                <div>
                                                    <div className="checkbox-item-label">{account.accountName}</div>
                                                    <div className="checkbox-item-category">{account.accountId}</div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                ) : (
                                    <div style={{ textAlign: 'center', padding: '2rem' }}>
                                        <Spinner />
                                        <p style={{ color: 'var(--text-secondary)', marginTop: '1rem' }}>Loading accounts...</p>
                                    </div>
                                )}

                                {ssoRoles.length > 0 && (
                                    <div style={{ marginTop: '1.5rem' }}>
                                        <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Select Role:</h3>
                                        <div className="checkbox-grid">
                                            {ssoRoles.map(role => (
                                                <button
                                                    key={role.roleName}
                                                    className="btn btn-primary"
                                                    onClick={() => selectSsoRole(role.roleName)}
                                                >
                                                    {role.roleName}
                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}

                {/* New Scan Tab */}
                {activeTab === 'scan' && (
                    <div className="animate-fadeIn">
                        {/* Regions Selection */}
                        <div className="card" style={{ marginBottom: '1.5rem' }}>
                            <div className="card-header">
                                <h2 className="card-title">
                                    <span className="card-title-icon">🌍</span>
                                    Select AWS Regions
                                </h2>
                                <span style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
                                    {selectedRegions.length} selected
                                </span>
                            </div>
                            <div className="checkbox-grid">
                                {regions.map(region => (
                                    <label
                                        key={region.id}
                                        className={`checkbox-item ${selectedRegions.includes(region.id) ? 'selected' : ''}`}
                                    >
                                        <input
                                            type="checkbox"
                                            checked={selectedRegions.includes(region.id)}
                                            onChange={() => toggleRegion(region.id)}
                                        />
                                        <div>
                                            <div className="checkbox-item-label">{region.id}</div>
                                            <div className="checkbox-item-category">{region.name}</div>
                                        </div>
                                    </label>
                                ))}
                            </div>
                        </div>

                        {/* Services Selection */}
                        <div className="card" style={{ marginBottom: '1.5rem' }}>
                            <div className="card-header">
                                <h2 className="card-title">
                                    <span className="card-title-icon">⚙️</span>
                                    Select AWS Services
                                </h2>
                                <div style={{ display: 'flex', gap: '0.5rem' }}>
                                    <button className="btn btn-secondary" onClick={selectAllServices}>Select All</button>
                                    <button className="btn btn-secondary" onClick={clearServices}>Clear</button>
                                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', alignSelf: 'center', marginLeft: '0.5rem' }}>
                                        {selectedServices.length} selected
                                    </span>
                                </div>
                            </div>
                            <div className="checkbox-grid">
                                {services.map(service => (
                                    <label
                                        key={service.id}
                                        className={`checkbox-item ${selectedServices.includes(service.id) ? 'selected' : ''}`}
                                    >
                                        <input
                                            type="checkbox"
                                            checked={selectedServices.includes(service.id)}
                                            onChange={() => toggleService(service.id)}
                                        />
                                        <div>
                                            <div className="checkbox-item-label">{service.name}</div>
                                            <div className="checkbox-item-category">{service.category}</div>
                                        </div>
                                    </label>
                                ))}
                            </div>
                        </div>

                        {/* Frameworks Selection */}
                        <div className="card" style={{ marginBottom: '1.5rem' }}>
                            <div className="card-header">
                                <h2 className="card-title">
                                    <span className="card-title-icon">📋</span>
                                    Compliance Frameworks (Optional)
                                </h2>
                            </div>
                            <div className="checkbox-grid">
                                {frameworks.map(framework => (
                                    <label
                                        key={framework.id}
                                        className={`checkbox-item ${selectedFrameworks.includes(framework.id) ? 'selected' : ''}`}
                                    >
                                        <input
                                            type="checkbox"
                                            checked={selectedFrameworks.includes(framework.id)}
                                            onChange={() => toggleFramework(framework.id)}
                                        />
                                        <div>
                                            <div className="checkbox-item-label">{framework.id}</div>
                                            <div className="checkbox-item-category">{framework.name}</div>
                                        </div>
                                    </label>
                                ))}
                            </div>
                        </div>

                        {/* Start Scan Button */}
                        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
                            <button
                                className="btn btn-aws btn-lg"
                                onClick={startScan}
                                disabled={scanning || selectedServices.length === 0 || selectedRegions.length === 0}
                            >
                                {scanning ? <Spinner /> : '🚀'}
                                {scanning ? 'Starting Scan...' : 'Start Scan'}
                            </button>
                            <p style={{ color: 'var(--text-muted)', marginTop: '0.75rem', fontSize: '0.875rem' }}>
                                Scanning {selectedServices.length} services in {selectedRegions.length} regions
                            </p>
                        </div>
                    </div>
                )}

                {/* Progress Tab */}
                {activeTab === 'progress' && (
                    <div className="animate-fadeIn">
                        {scanJob ? (
                            <div className="card">
                                <div className="card-header">
                                    <h2 className="card-title">
                                        <span className="card-title-icon">📡</span>
                                        Scan Progress
                                    </h2>
                                    <StatusBadge status={scanJob.status} />
                                </div>

                                <div className="progress-container">
                                    <div className="progress-bar">
                                        <div
                                            className="progress-fill"
                                            style={{ width: `${scanJob.progress}%` }}
                                        ></div>
                                    </div>
                                    <div className="progress-text">
                                        <span>{scanJob.current_task}</span>
                                        <span>{scanJob.progress}%</span>
                                    </div>
                                </div>

                                <div style={{ marginTop: '1.5rem', padding: '1rem', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-md)' }}>
                                    <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                                        <strong>Job ID:</strong> {scanJob.job_id}
                                    </p>
                                    <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                                        <strong>Started:</strong> {new Date(scanJob.created_at).toLocaleString()}
                                    </p>
                                    {scanJob.completed_at && (
                                        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                                            <strong>Completed:</strong> {new Date(scanJob.completed_at).toLocaleString()}
                                        </p>
                                    )}
                                </div>

                                {scanJob.status === 'completed' && scanJob.report_path && (
                                    <div style={{ marginTop: '1.5rem', textAlign: 'center' }}>
                                        <a
                                            href={scanJob.report_path}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="btn btn-success btn-lg"
                                        >
                                            📊 View Report
                                        </a>
                                    </div>
                                )}

                                {scanJob.status === 'failed' && scanJob.error && (
                                    <div style={{ marginTop: '1.5rem', padding: '1rem', background: 'rgba(248, 81, 73, 0.1)', borderRadius: 'var(--radius-md)', border: '1px solid var(--accent-danger)' }}>
                                        <p style={{ color: 'var(--accent-danger)', fontSize: '0.875rem' }}>
                                            <strong>Error:</strong> {scanJob.error}
                                        </p>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <div className="card">
                                <div className="empty-state">
                                    <div className="empty-state-icon">📡</div>
                                    <p>No active scan. Start a new scan from the "New Scan" tab.</p>
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* Reports Tab */}
                {activeTab === 'reports' && (
                    <div className="animate-fadeIn">
                        {reports.length > 0 ? (
                            <div className="grid-2">
                                {reports.map((report, idx) => (
                                    <div key={idx} className="card">
                                        <div className="card-header">
                                            <h3 className="card-title">
                                                <span className="card-title-icon">📊</span>
                                                Account: {report.account_id}
                                            </h3>
                                        </div>
                                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '1rem' }}>
                                            Generated: {new Date(report.created_at).toLocaleString()}
                                        </p>
                                        <a
                                            href={report.path}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="btn btn-primary"
                                        >
                                            Open Report →
                                        </a>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="card">
                                <div className="empty-state">
                                    <div className="empty-state-icon">📊</div>
                                    <p>No reports yet. Run a scan to generate your first report.</p>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    )
}

export default App
