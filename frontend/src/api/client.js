const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000/api'

export function token() {
  return localStorage.getItem('token')
}

export function setToken(value) {
  if (value) localStorage.setItem('token', value)
  else localStorage.removeItem('token')
}

export async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) }
  if (token()) headers.Authorization = `Bearer ${token()}`
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers })
  if (!response.ok) {
    let message = 'Ошибка запроса'
    let code = 'REQUEST_ERROR'
    try {
      const data = await response.json()
      message = data.error?.message || message
      code = data.error?.code || code
    } catch (_) {}
    const error = new Error(message)
    error.code = code
    throw error
  }
  if (response.status === 204) return null
  return response.json()
}

export { API_BASE }
