import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import './index.css'
import App from './App.jsx'

//views
import Login from './components/Login.jsx'
import Register from './components/Register.jsx'
import Protected from './components/Protected.jsx'
import PageNotFound from './components/PageNotFound.jsx'

const router = createBrowserRouter([
  {
    path: '/'
  }
])

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
