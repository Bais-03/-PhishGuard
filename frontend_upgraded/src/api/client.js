import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 30000,
})

export async function analyzeUrl(url) {
  const { data } = await api.post('/analyze/url', { url })
  return data
}

export async function analyzeEmail(rawEmail) {
  const { data } = await api.post('/analyze/email', { raw_email: rawEmail })
  return data
}

export async function analyzeEmailFile(file) {
  const formData = new FormData()
  formData.append('file', file)
  
  const { data } = await api.post('/upload/eml', formData, {
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  })
  return data
}

export async function getHealth() {
  const { data } = await api.get('/health')
  return data
}

export async function getCacheStats() {
  const { data } = await api.get('/cache/stats')
  return data
}

export default api