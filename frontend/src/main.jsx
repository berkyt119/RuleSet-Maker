import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { API_BASE, api, setToken, token } from './api/client'
import './styles/app.css'

const policyLabels = {
  require_uppercase: 'Требовать прописную букву',
  require_lowercase: 'Требовать строчную букву',
  require_digit: 'Требовать цифру',
  require_special_char: 'Требовать специальный символ',
}

function Login({ onLogin }) {
  const [form, setForm] = useState({ username: '', password: '' })
  const [error, setError] = useState('')
  async function submit(event) {
    event.preventDefault()
    setError('')
    try {
      const data = await api('/auth/login', { method: 'POST', body: JSON.stringify(form) })
      setToken(data.access_token)
      onLogin(data.must_change_password ? 'change-required' : 'dashboard')
    } catch (err) {
      setError(err.message)
    }
  }
  return <AuthShell title="Вход">
    <form onSubmit={submit} className="form">
      <label>Логин<input value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} autoFocus /></label>
      <label>Пароль<input type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></label>
      {error && <div className="error">{error}</div>}
      <button>Войти</button>
    </form>
  </AuthShell>
}

function AuthShell({ title, children }) {
  return <main className="auth"><section className="auth-card"><div className="auth-brand"><img src="/dogma.png" alt="DOGMA" /><div><strong>DOGMA-VPN</strong><span>Private network</span></div></div><h1>{title}</h1><p>Сервис выбора доменов и ruleset для sing-box.</p>{children}</section></main>
}

function ChangePassword({ forced, onDone }) {
  const [form, setForm] = useState({ current_password: '', new_password: '', confirm_password: '' })
  const [error, setError] = useState('')
  async function submit(event) {
    event.preventDefault()
    setError('')
    try {
      await api('/auth/change-password', { method: 'POST', body: JSON.stringify(form) })
      onDone()
    } catch (err) {
      setError(err.message)
    }
  }
  return <Panel title={forced ? 'Необходимо сменить пароль' : 'Смена пароля'}>
    <form onSubmit={submit} className="form narrow">
      <label>Текущий пароль<input type="password" value={form.current_password} onChange={e => setForm({ ...form, current_password: e.target.value })} /></label>
      <label>Новый пароль<input type="password" value={form.new_password} onChange={e => setForm({ ...form, new_password: e.target.value })} /></label>
      <label>Подтверждение<input type="password" value={form.confirm_password} onChange={e => setForm({ ...form, confirm_password: e.target.value })} /></label>
      {error && <div className="error">{error}</div>}
      <button>Сохранить пароль</button>
    </form>
  </Panel>
}

function Dashboard() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api('/dashboard').then(setData).catch(err => setError(err.message)) }, [])
  if (error) return <Panel title="Дашборд"><div className="error">{error}</div></Panel>
  if (!data) return <Panel title="Дашборд"><p>Загрузка...</p></Panel>
  return <Panel title="Дашборд">
    {data.catalog_error && <div className="error">{data.catalog_error}</div>}
    <div className="metric-grid">
      <Metric label="Всего сервисов" value={data.services_total} />
      <Metric label="Из JSON каталога" value={data.imported_services_count} />
      <Metric label="Добавлены клиентом" value={data.custom_services_count} />
      <Metric label="Групп" value={data.groups_count} />
      <Metric label="Включено сервисов" value={data.enabled_services_count} />
      <Metric label="Доменов в JSON" value={data.ruleset_domains_count} />
      <Metric label="CIDR в JSON" value={data.ruleset_cidrs_count} />
    </div>
    <div className="dashboard-meta">
      <Metric label="Каталог обновлен" value={formatDate(data.source_json_updated_at)} compact />
      <Metric label="Ruleset обновлен" value={formatDate(data.ruleset_updated_at)} compact />
    </div>
  </Panel>
}

function Metric({ label, value, compact = false }) {
  return <div className={`metric ${compact ? 'metric-compact' : ''}`}><span>{label}</span><b>{value ?? 'нет данных'}</b></div>
}

function DomainsPage() {
  const [catalog, setCatalog] = useState(null)
  const [enabled, setEnabled] = useState(new Set())
  const [expandedCustomServices, setExpandedCustomServices] = useState(new Set())
  const [dirty, setDirty] = useState(false)
  const [ruleset, setRuleset] = useState(null)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [customForm, setCustomForm] = useState({ name: '', root_domain: '' })
  const [domainForms, setDomainForms] = useState({})
  const [valueTypes, setValueTypes] = useState({})

  async function load() {
    const [catalogData, rulesetData] = await Promise.all([api('/domains/catalog'), api('/domains/ruleset')])
    setCatalog(catalogData)
    setEnabled(new Set(catalogData.groups.flatMap(group => group.services.filter(service => service.enabled).map(service => service.key))))
    setRuleset(rulesetData)
    setDirty(false)
  }

  useEffect(() => { load().catch(err => setError(err.message)) }, [])

  const allServices = useMemo(() => catalog?.groups.flatMap(group => group.services) || [], [catalog])
  const selectedDomainsCount = useMemo(() => {
    const domains = new Set()
    for (const service of allServices) {
      if (!enabled.has(service.key)) continue
      if (service.root_domain) domains.add(service.root_domain)
      for (const domain of service.related_domains || []) domains.add(domain)
    }
    return domains.size
  }, [allServices, enabled])
  const selectedCidrsCount = useMemo(() => {
    const cidrs = new Set()
    for (const service of allServices) {
      if (!enabled.has(service.key)) continue
      for (const item of service.custom_cidrs || []) cidrs.add(item.cidr)
    }
    return cidrs.size
  }, [allServices, enabled])

  function toggleService(key, value) {
    const next = new Set(enabled)
    value ? next.add(key) : next.delete(key)
    setEnabled(next)
    setDirty(true)
  }

  function toggleGroup(group, value) {
    const next = new Set(enabled)
    for (const service of group.services) value ? next.add(service.key) : next.delete(service.key)
    setEnabled(next)
    setDirty(true)
  }

  function toggleCustomList(key) {
    const next = new Set(expandedCustomServices)
    next.has(key) ? next.delete(key) : next.add(key)
    setExpandedCustomServices(next)
  }

  async function save() {
    setError('')
    setMessage('')
    try {
      const result = await api('/domains/selection', { method: 'PUT', body: JSON.stringify({ enabled_service_keys: [...enabled] }) })
      setRuleset({ ...(ruleset || {}), ...result })
      setDirty(false)
      setMessage('Изменения сохранены, JSON для sing-box сформирован.')
      await load()
    } catch (err) {
      setError(err.message)
    }
  }

  async function createCustomService(event) {
    event.preventDefault()
    setError('')
    try {
      await api('/domains/custom-services', { method: 'POST', body: JSON.stringify({ name: customForm.name, root_domain: customForm.root_domain || null }) })
      setCustomForm({ name: '', root_domain: '' })
      await load()
      setDirty(true)
    } catch (err) {
      setError(err.message)
    }
  }

  async function addDomain(event, serviceId) {
    event.preventDefault()
    setError('')
    try {
      await api(`/domains/custom-services/${serviceId}/domains`, { method: 'POST', body: JSON.stringify({ domain: domainForms[serviceId] || '', value_type: valueTypes[serviceId] || 'domain' }) })
      setDomainForms({ ...domainForms, [serviceId]: '' })
      await load()
      setDirty(true)
    } catch (err) {
      setError(err.message)
    }
  }

  async function deleteService(serviceId) {
    await api(`/domains/custom-services/${serviceId}`, { method: 'DELETE' })
    await load()
    setDirty(true)
  }

  async function deleteDomain(serviceId, domainId) {
    await api(`/domains/custom-services/${serviceId}/domains/${domainId}`, { method: 'DELETE' })
    await load()
    setDirty(true)
  }

  async function deleteCidr(serviceId, cidrId) {
    await api(`/domains/custom-services/${serviceId}/cidrs/${cidrId}`, { method: 'DELETE' })
    await load()
    setDirty(true)
  }

  if (error && !catalog) return <Panel title="Домены"><div className="error">{error}</div></Panel>
  if (!catalog) return <Panel title="Домены"><p>Загрузка...</p></Panel>

  return <Panel title="Домены">
    <div className="toolbar">
      <div><b>Каталог:</b> {formatDate(catalog.generated_at)}</div>
      <div><b>Сервисов:</b> {enabled.size}</div>
      <div><b>Доменов:</b> {selectedDomainsCount}</div>
      <div><b>CIDR:</b> {selectedCidrsCount}</div>
      <button onClick={save} disabled={!dirty}>Сохранить изменения</button>
      <a className="button secondary" href={`${API_BASE}/domains/ruleset/download`} onClick={downloadWithAuth}>Скачать JSON</a>
    </div>
    {catalog.error && <div className="error">{catalog.error}</div>}
    {error && <div className="error">{error}</div>}
    {message && <div className="success">{message}</div>}
    <form onSubmit={createCustomService} className="inline-form custom-create">
      <label>Название сервиса<input placeholder="Например, video services" value={customForm.name} onChange={e => setCustomForm({ ...customForm, name: e.target.value })} /></label>
      <label>Основной домен<input placeholder="Необязательно" value={customForm.root_domain} onChange={e => setCustomForm({ ...customForm, root_domain: e.target.value })} /></label>
      <button>Создать сервис</button>
    </form>
    <div className="groups-list">{catalog.groups.map(group => {
      const serviceKeys = group.services.map(service => service.key)
      const groupEnabled = serviceKeys.length > 0 && serviceKeys.every(key => enabled.has(key))
      const groupPartial = serviceKeys.some(key => enabled.has(key)) && !groupEnabled
      return <section className="domain-group" key={group.key}>
        <div className="group-head"><div className="group-icon">{initials(group.name)}</div><div><h3>{group.name}</h3><p>{group.services.length} сервисов</p></div><Toggle checked={groupEnabled} partial={groupPartial} onChange={value => toggleGroup(group, value)} /></div>
        <div className="service-grid">{group.services.map(service => {
          const customDomains = service.custom_domains || []
          const customCidrs = service.custom_cidrs || []
          const isCustomExpanded = expandedCustomServices.has(service.key)
          return <article className={`service-card ${service.is_custom ? 'custom-service-card' : ''}`} key={service.key}>
            <div className="service-top"><div className="service-icon">{initials(service.display_name)}</div><div className="service-text"><b title={service.display_name}>{service.display_name}</b><span title={service.root_domain || 'Пользовательские значения'}>{service.root_domain || 'Пользовательские значения'}</span></div><Toggle checked={enabled.has(service.key)} onChange={value => toggleService(service.key, value)} /></div>
            {service.is_custom ? <div className="service-summary"><span>Домены: {customDomains.length + (service.root_domain ? 1 : 0)}</span><span>CIDR: {customCidrs.length}</span></div> : <p>{service.domains_count} доменов</p>}
            {service.is_custom && <div className="custom-tools"><form onSubmit={event => addDomain(event, service.custom_service_id)}><label>Тип значения<select value={valueTypes[service.custom_service_id] || 'domain'} onChange={e => setValueTypes({ ...valueTypes, [service.custom_service_id]: e.target.value })}><option value="domain">Домен</option><option value="ip_cidr">IP CIDR</option></select></label><label>Домен или IP CIDR<input placeholder={(valueTypes[service.custom_service_id] || 'domain') === 'ip_cidr' ? '8.8.8.8/32' : 'example.com'} value={domainForms[service.custom_service_id] || ''} onChange={e => setDomainForms({ ...domainForms, [service.custom_service_id]: e.target.value })} /></label><button>Добавить</button></form><div className="custom-actions"><button className="secondary list-toggle" type="button" onClick={() => toggleCustomList(service.key)}>{isCustomExpanded ? 'Скрыть список' : 'Показать список'}</button><button className="danger" type="button" onClick={() => deleteService(service.custom_service_id)}>Удалить сервис</button></div>{isCustomExpanded && <div className="custom-list"><div className="custom-list-section"><h4>Домены</h4>{service.root_domain && <div className="domain-row"><span>{service.root_domain}</span><em>Основной</em></div>}{customDomains.map(item => <div className="domain-row" key={`domain-${item.id}`}><span>{item.domain}</span><button className="link-button" onClick={() => deleteDomain(service.custom_service_id, item.id)}>Удалить</button></div>)}{!service.root_domain && customDomains.length === 0 && <div className="empty-list">Доменов нет</div>}</div><div className="custom-list-section"><h4>CIDR</h4>{customCidrs.map(item => <div className="domain-row" key={`cidr-${item.id}`}><span>{item.cidr}</span><button className="link-button" onClick={() => deleteCidr(service.custom_service_id, item.id)}>Удалить</button></div>)}{customCidrs.length === 0 && <div className="empty-list">CIDR нет</div>}</div></div>}</div>}
          </article>
        })}</div>
      </section>
    })}</div>
  </Panel>
}

function Toggle({ checked, partial, onChange }) {
  return <button type="button" className={`toggle ${checked ? 'on' : ''} ${partial ? 'partial' : ''}`} onClick={() => onChange(!checked)}><span /></button>
}

function AdminUsers() {
  const [users, setUsers] = useState([])
  const [form, setForm] = useState({ username: '', password: '', role: 'user', must_change_password: true })
  const [policy, setPolicy] = useState(null)
  const [error, setError] = useState('')
  const [policyMessage, setPolicyMessage] = useState('')
  async function load() {
    const [usersData, policyData] = await Promise.all([api('/admin/users'), api('/admin/password-policy')])
    setUsers(usersData)
    setPolicy(policyData)
  }
  useEffect(() => { load().catch(err => setError(err.message)) }, [])
  async function create(event) {
    event.preventDefault()
    setError('')
    try {
      await api('/admin/users', { method: 'POST', body: JSON.stringify(form) })
      setForm({ username: '', password: '', role: 'user', must_change_password: true })
      await load()
    } catch (err) {
      setError(err.message)
    }
  }
  async function toggleActive(user) {
    setError('')
    try {
      await api(`/admin/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ is_active: !user.is_active }) })
      await load()
    } catch (err) {
      setError(err.message)
    }
  }
  async function deleteUser(user) {
    if (!confirm(`Удалить учетную запись ${user.username}?`)) return
    setError('')
    try {
      await api(`/admin/users/${user.id}`, { method: 'DELETE' })
      await load()
    } catch (err) {
      setError(err.message)
    }
  }
  return <Panel title="Пользователи">
    <form onSubmit={create} className="inline-form">
      <label>Логин<input placeholder="login" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} /></label>
      <label>Пароль<input placeholder="password" type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></label>
      <label>Роль<select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}><option value="user">user</option><option value="admin">admin</option></select></label>
      <button>Создать</button>
    </form>
    {error && <div className="error">{error}</div>}
    <div className="table-wrap"><table><thead><tr><th>ID</th><th>Логин</th><th>Роль</th><th>Активен</th><th>Смена пароля</th><th>Действия</th></tr></thead><tbody>{users.map(user => <tr key={user.id}><td>{user.id}</td><td>{user.username}</td><td>{user.role}</td><td>{user.is_active ? 'да' : 'нет'}</td><td>{user.must_change_password ? 'да' : 'нет'}</td><td><div className="table-actions"><button className="secondary" type="button" onClick={() => toggleActive(user)}>{user.is_active ? 'Отключить' : 'Включить'}</button><button className="danger" type="button" onClick={() => deleteUser(user)}>Удалить</button></div></td></tr>)}</tbody></table></div>
    {policy && <section className="policy-block"><h3>Парольная политика</h3><PasswordPolicyForm policy={policy} setPolicy={setPolicy} message={policyMessage} setMessage={setPolicyMessage} /></section>}
  </Panel>
}

function PasswordPolicyForm({ policy, setPolicy, message, setMessage }) {
  const [error, setError] = useState('')
  async function save(event) {
    event.preventDefault()
    setError('')
    setMessage('')
    try {
      const savedPolicy = await api('/admin/password-policy', {
        method: 'PUT',
        body: JSON.stringify({
          min_length: policy.min_length,
          require_uppercase: policy.require_uppercase,
          require_lowercase: policy.require_lowercase,
          require_digit: policy.require_digit,
          require_special_char: policy.require_special_char,
        }),
      })
      setPolicy(savedPolicy)
      setMessage('Сохранено')
    } catch (err) {
      setError(err.message)
    }
  }
  return <form onSubmit={save} className="form narrow">
    <label>Минимальная длина<input type="number" value={policy.min_length} onChange={e => setPolicy({ ...policy, min_length: Number(e.target.value) })} /></label>
    {Object.entries(policyLabels).map(([key, label]) => <label className="check" key={key}><input type="checkbox" checked={policy[key]} onChange={e => setPolicy({ ...policy, [key]: e.target.checked })} />{label}</label>)}
    {error && <div className="error">{error}</div>}
    <button>Сохранить</button>{message && <span>{message}</span>}
  </form>
}

function LogsPage() {
  const [logs, setLogs] = useState([])
  const [error, setError] = useState('')
  useEffect(() => { api('/logs').then(setLogs).catch(err => setError(err.message)) }, [])
  return <Panel title="Логи">
    {error && <div className="error">{error}</div>}
    <div className="table-wrap"><table><thead><tr><th>Дата</th><th>User ID</th><th>Действие</th><th>Объект</th><th>Детали</th></tr></thead><tbody>{logs.map(row => <tr key={row.id}><td>{formatDate(row.created_at)}</td><td>{row.user_id || ''}</td><td>{row.action}</td><td>{row.entity}</td><td>{row.details || ''}</td></tr>)}</tbody></table></div>
  </Panel>
}

function Panel({ title, children }) {
  return <section className="panel"><h2>{title}</h2>{children}</section>
}

function initials(value) {
  return String(value || '?').split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase()
}

function formatDate(value) {
  if (!value) return 'нет данных'
  return new Date(value).toLocaleString('ru-RU')
}

async function downloadWithAuth(event) {
  event.preventDefault()
  const response = await fetch(event.currentTarget.href, { headers: { Authorization: `Bearer ${token()}` } })
  const blob = await response.blob()
  const disposition = response.headers.get('Content-Disposition') || ''
  const filename = disposition.match(/filename="(.+)"/)?.[1] || 'ruleset.json'
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function App() {
  const [route, setRoute] = useState(token() ? 'dashboard' : 'login')
  const [me, setMe] = useState(null)
  useEffect(() => { if (token()) api('/auth/me').then(setMe).catch(() => { setToken(null); setRoute('login') }) }, [route])
  if (route === 'login') return <Login onLogin={setRoute} />
  return <div className="app"><aside><div><div className="brand"><img src="/dogma.png" alt="Dogma VPN" /><div><h1>DOGMA-VPN</h1><span>PRIVATE NETWORK</span></div></div><button onClick={() => setRoute('dashboard')}>Дашборд</button><button onClick={() => setRoute('domains')}>Домены</button><button onClick={() => setRoute('logs')}>Логи</button>{me?.role === 'admin' && <button onClick={() => setRoute('users')}>Пользователи</button>}</div><div className="sidebar-bottom"><button className="settings-button" title="Сменить пароль" aria-label="Сменить пароль" onClick={() => setRoute('password')}>⚙</button><button onClick={() => { setToken(null); setRoute('login') }}>Выход</button></div></aside><main>{route === 'change-required' && <ChangePassword forced onDone={() => setRoute('dashboard')} />}{route === 'password' && <ChangePassword onDone={() => setRoute('dashboard')} />}{route === 'dashboard' && <Dashboard />}{route === 'domains' && <DomainsPage />}{route === 'logs' && <LogsPage />}{route === 'users' && <AdminUsers />}</main></div>
}

createRoot(document.getElementById('root')).render(<App />)
